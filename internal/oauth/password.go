package oauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Argon2id parameters for new hashes: RFC 9106's second recommended option
// with one lane (Cloud Run instances have one vCPU).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16

	// Upper bounds accepted when parsing, so a hash cannot exhaust the
	// 256 MiB instance.
	maxArgonMemory = 128 * 1024
	maxArgonTime   = 10
)

type passwordHash struct {
	bcrypt []byte // set for bcrypt hashes

	salt, key            []byte
	time, memory, thread uint32
}

// HashPassword returns an argon2id PHC string for password.
func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// parseHash accepts "$argon2id$v=19$m=..,t=..,p=..$salt$key" or a bcrypt
// hash ($2a$, $2b$, $2y$, cost >= 10).
func parseHash(s string) (*passwordHash, error) {
	switch {
	case strings.HasPrefix(s, "$2a$"), strings.HasPrefix(s, "$2b$"), strings.HasPrefix(s, "$2y$"):
		cost, err := bcrypt.Cost([]byte(s))
		if err != nil {
			return nil, errors.New("malformed bcrypt hash")
		}
		if cost < 10 {
			return nil, errors.New("bcrypt cost must be at least 10")
		}
		return &passwordHash{bcrypt: []byte(s)}, nil
	case strings.HasPrefix(s, "$argon2id$"):
		parts := strings.Split(s, "$")
		if len(parts) != 6 || parts[2] != "v="+strconv.Itoa(argon2.Version) {
			return nil, errors.New("malformed argon2id hash")
		}
		h := &passwordHash{}
		var m, t, p int
		if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
			return nil, errors.New("malformed argon2id parameters")
		}
		if m < 19*1024 || m > maxArgonMemory || t < 1 || t > maxArgonTime || p < 1 || p > 16 {
			return nil, errors.New("argon2id parameters out of range (m 19456..131072 KiB, t 1..10, p 1..16)")
		}
		h.memory, h.time, h.thread = uint32(m), uint32(t), uint32(p)
		var err error
		if h.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(h.salt) < 16 {
			return nil, errors.New("argon2id salt must be at least 16 bytes")
		}
		if h.key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(h.key) < 16 || len(h.key) > 64 {
			return nil, errors.New("argon2id key must be 16-64 bytes")
		}
		return h, nil
	}
	return nil, errors.New("must be an argon2id PHC string or a bcrypt hash")
}

func (h *passwordHash) verify(password string) bool {
	if h.bcrypt != nil {
		return bcrypt.CompareHashAndPassword(h.bcrypt, []byte(password)) == nil
	}
	key := argon2.IDKey([]byte(password), h.salt, h.time, h.memory, uint8(h.thread), uint32(len(h.key)))
	return subtle.ConstantTimeCompare(key, h.key) == 1
}
