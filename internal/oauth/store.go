package oauth

import (
	"crypto/sha256"
	"sync"
	"time"
)

// store holds pending authorization codes in memory (5 min). A restart
// drops them; the user simply connects again. Token families are kept in
// the Journal (journal.go).
type store struct {
	mu       sync.Mutex
	codes    map[[32]byte]*codeEntry
	maxCodes int
}

type codeEntry struct {
	clientID    string
	redirectURI string
	challenge   string
	resource    string
	expires     time.Time
	redeemed    bool
	family      string // set on redemption, revoked on replay
}

func newStore() *store {
	return &store{codes: map[[32]byte]*codeEntry{}, maxCodes: 100}
}

func codeKey(code string) [32]byte { return sha256.Sum256([]byte(code)) }

// prune drops expired codes. Callers hold mu.
func (st *store) prune(now time.Time) {
	for k, c := range st.codes {
		if now.After(c.expires) {
			delete(st.codes, k)
		}
	}
}

// putCode stores a new code. Codes are only issued after the owner
// authenticated, so the cap only bounds memory.
func (st *store) putCode(code string, e *codeEntry, now time.Time) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.prune(now)
	if len(st.codes) >= st.maxCodes {
		return false
	}
	st.codes[codeKey(code)] = e
	return true
}

// redeemCode marks a code as used and returns a copy of its entry. On a
// second redemption it returns the family issued from the first one, which
// the caller revokes (RFC 6749 §4.1.2).
func (st *store) redeemCode(code, family string, now time.Time) (entry *codeEntry, replayedFamily string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	e, ok := st.codes[codeKey(code)]
	if !ok || now.After(e.expires) {
		return nil, ""
	}
	if e.redeemed {
		return nil, e.family
	}
	e.redeemed = true
	e.family = family
	cp := *e
	return &cp, ""
}
