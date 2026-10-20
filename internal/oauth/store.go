package oauth

import (
	"crypto/sha256"
	"sync"
	"time"
)

// store holds the short-lived authorization state in memory: codes (5 min),
// used refresh-token IDs and revoked token families. Losing it on restart
// invalidates pending codes and forgets reuse history (docs/DECISIONS.md
// D25); TOKEN_EPOCH remains the global kill switch.
type store struct {
	mu       sync.Mutex
	codes    map[[32]byte]*codeEntry
	used     map[string]usedRefresh // refresh token jti -> family
	revoked  map[string]time.Time   // family -> forget after
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

type usedRefresh struct {
	family  string
	expires time.Time
}

func newStore() *store {
	return &store{
		codes:    map[[32]byte]*codeEntry{},
		used:     map[string]usedRefresh{},
		revoked:  map[string]time.Time{},
		maxCodes: 100,
	}
}

func codeKey(code string) [32]byte { return sha256.Sum256([]byte(code)) }

// prune drops expired state. Callers hold mu.
func (st *store) prune(now time.Time) {
	for k, c := range st.codes {
		if now.After(c.expires) {
			delete(st.codes, k)
		}
	}
	for k, u := range st.used {
		if now.After(u.expires) {
			delete(st.used, k)
		}
	}
	for k, t := range st.revoked {
		if now.After(t) {
			delete(st.revoked, k)
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

// redeemCode marks a code as used and returns a copy of its entry. A second
// redemption revokes the token family issued from the first (RFC 6749
// §4.1.2) and fails.
func (st *store) redeemCode(code, family string, now time.Time, familyTTL time.Duration) (*codeEntry, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	e, ok := st.codes[codeKey(code)]
	if !ok || now.After(e.expires) {
		return nil, false
	}
	if e.redeemed {
		if e.family != "" {
			st.revoked[e.family] = now.Add(familyTTL)
		}
		return nil, false
	}
	e.redeemed = true
	e.family = family
	cp := *e
	return &cp, true
}

// useRefresh records a refresh token as used. Reuse of a used token revokes
// its whole family (rotation with reuse detection).
func (st *store) useRefresh(jti, family string, exp time.Time, now time.Time, familyTTL time.Duration) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.prune(now)
	if _, revoked := st.revoked[family]; revoked {
		return false
	}
	if _, reused := st.used[jti]; reused {
		st.revoked[family] = now.Add(familyTTL)
		return false
	}
	st.used[jti] = usedRefresh{family: family, expires: exp.Add(leeway)}
	return true
}

func (st *store) familyRevoked(family string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	_, ok := st.revoked[family]
	return ok
}
