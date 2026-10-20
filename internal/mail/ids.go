package mail

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/emersion/go-imap/v2"
)

// Message IDs are opaque to callers but self-describing:
//
//	m1.<base64url(folder)>.<uidvalidity>.<uid>
//	d1.<base64url(folder)>.<uidvalidity>.<uid>.<base64url(hmac)>
//
// UIDVALIDITY is checked on every use, so an ID can never silently address a
// different message after the server renumbers a folder. Draft IDs carry an
// HMAC over the location and the exact draft bytes: SendDraft only accepts
// drafts this server created and that are unmodified since.
const (
	msgIDPrefix   = "m1"
	draftIDPrefix = "d1"
	maxIDLen      = 2048
	maxFolderLen  = 1024
	draftMACLabel = "generic-email-mcp/draft/v1"
)

var b64 = base64.RawURLEncoding

type msgRef struct {
	Folder      string
	UIDValidity uint32
	UID         imap.UID
}

func (r msgRef) String() string {
	return msgIDPrefix + "." + r.body()
}

func (r msgRef) body() string {
	return b64.EncodeToString([]byte(r.Folder)) + "." +
		strconv.FormatUint(uint64(r.UIDValidity), 10) + "." +
		strconv.FormatUint(uint64(r.UID), 10)
}

// parseRef parses a message or draft ID. The draft MAC is not checked here.
func parseRef(id string) (msgRef, error) {
	ref, _, err := parseID(id)
	return ref, err
}

// parseDraftRef parses a draft ID and returns its MAC for verification.
func parseDraftRef(id string) (msgRef, []byte, error) {
	ref, mac, err := parseID(id)
	if err != nil {
		return msgRef{}, nil, err
	}
	if mac == nil {
		return msgRef{}, nil, fmt.Errorf("%w: not a draft id", ErrDraftInvalid)
	}
	return ref, mac, nil
}

func parseID(id string) (msgRef, []byte, error) {
	bad := func(why string) (msgRef, []byte, error) {
		return msgRef{}, nil, fmt.Errorf("%w: %s", ErrInvalidID, why)
	}
	if id == "" || len(id) > maxIDLen {
		return bad("empty or too long")
	}
	parts := strings.Split(id, ".")
	var wantParts int
	switch parts[0] {
	case msgIDPrefix:
		wantParts = 4
	case draftIDPrefix:
		wantParts = 5
	default:
		return bad("unknown format")
	}
	if len(parts) != wantParts {
		return bad("malformed")
	}
	folder, err := b64.DecodeString(parts[1])
	if err != nil || !validFolderName(string(folder)) {
		return bad("bad folder")
	}
	uv, err := parsePositiveUint32(parts[2])
	if err != nil {
		return bad("bad uidvalidity")
	}
	uid, err := parsePositiveUint32(parts[3])
	if err != nil {
		return bad("bad uid")
	}
	ref := msgRef{Folder: string(folder), UIDValidity: uv, UID: imap.UID(uid)}
	if wantParts == 4 {
		return ref, nil, nil
	}
	mac, err := b64.DecodeString(parts[4])
	if err != nil || len(mac) != sha256.Size {
		return bad("bad signature")
	}
	return ref, mac, nil
}

func parsePositiveUint32(s string) (uint32, error) {
	// Reject signs, leading zeros and whitespace so every ID has exactly
	// one textual form.
	if s == "" || s[0] == '0' || s[0] == '+' || s[0] == '-' {
		return 0, ErrInvalidID
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

func validFolderName(name string) bool {
	if name == "" || len(name) > maxFolderLen || !utf8.ValidString(name) {
		return false
	}
	return !strings.ContainsAny(name, "\x00\r\n")
}

// draftMAC binds a draft ID to the account, the draft's location and its
// exact content.
func draftMAC(key []byte, account string, ref msgRef, content []byte) []byte {
	sum := sha256.Sum256(normalizeForHash(content))
	m := hmac.New(sha256.New, key)
	writeField := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		m.Write(n[:])
		m.Write(b)
	}
	writeField([]byte(draftMACLabel))
	writeField([]byte(account))
	writeField([]byte(ref.Folder))
	var nums [8]byte
	binary.BigEndian.PutUint32(nums[:4], ref.UIDValidity)
	binary.BigEndian.PutUint32(nums[4:], uint32(ref.UID))
	writeField(nums[:])
	writeField(sum[:])
	return m.Sum(nil)
}

func formatDraftID(ref msgRef, mac []byte) string {
	return draftIDPrefix + "." + ref.body() + "." + b64.EncodeToString(mac)
}

// normalizeForHash makes the draft hash robust against servers that store
// LF line endings or append a trailing newline.
func normalizeForHash(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	return bytes.TrimRight(b, "\n")
}
