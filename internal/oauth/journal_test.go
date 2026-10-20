package oauth

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// flakyJournal wraps a journal and can fail every call.
type flakyJournal struct {
	Journal
	mu   sync.Mutex
	down bool
}

func (f *flakyJournal) setDown(v bool) { f.mu.Lock(); f.down = v; f.mu.Unlock() }
func (f *flakyJournal) isDown() bool   { f.mu.Lock(); defer f.mu.Unlock(); return f.down }

func (f *flakyJournal) Update(ctx context.Context, fam string, d func([]FamilyEvent) (*FamilyEvent, error)) error {
	if f.isDown() {
		return errors.New("imap unreachable")
	}
	return f.Journal.Update(ctx, fam, d)
}

func (f *flakyJournal) Revocations(ctx context.Context, since time.Time) ([]FamilyEvent, error) {
	if f.isDown() {
		return nil, errors.New("imap unreachable")
	}
	return f.Journal.Revocations(ctx, since)
}

func durableJournal() *MemoryJournal {
	j := NewMemoryJournal(DefaultRefreshTTL)
	j.durable = true
	return j
}

func refreshForm(rt string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
}

// TestReuseDetectionSurvivesRestart: a second server instance sharing the
// durable journal (a restart) still detects reuse of a rotated token.
func TestReuseDetectionSurvivesRestart(t *testing.T) {
	j := durableJournal()
	e1 := newEnv(t, func(c *Config) { c.Journal = j })
	_, rt1 := e1.tokens(t)
	w, body := e1.token(t, refreshForm(rt1), true)
	if w.Code != 200 {
		t.Fatal(body)
	}
	at2, rt2 := body["access_token"].(string), body["refresh_token"].(string)

	e2 := newEnv(t, func(c *Config) { c.Journal = j; c.Now = e1.clock.Now }) // restart
	if err := e2.verify(at2); err != nil {
		t.Fatalf("valid access token rejected after restart: %v", err)
	}
	w, body = e2.token(t, refreshForm(rt1), true) // the already-rotated token
	wantTokenError(t, w, body, 400, "invalid_grant")
	w, body = e2.token(t, refreshForm(rt2), true) // family is revoked now
	wantTokenError(t, w, body, 400, "invalid_grant")
	if err := e2.verify(at2); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("access token of revoked family accepted: %v", err)
	}

	// A third instance learns the revocation from the journal on first use.
	e3 := newEnv(t, func(c *Config) { c.Journal = j; c.Now = e1.clock.Now })
	if err := e3.verify(at2); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("revocation not loaded after restart: %v", err)
	}
}

func TestRotationContinuesAcrossRestart(t *testing.T) {
	j := durableJournal()
	e1 := newEnv(t, func(c *Config) { c.Journal = j })
	_, rt := e1.tokens(t)
	for i := range 3 {
		e := newEnv(t, func(c *Config) { c.Journal = j; c.Now = e1.clock.Now })
		w, body := e.token(t, refreshForm(rt), true)
		if w.Code != 200 {
			t.Fatalf("rotation %d after restart: %v", i, body)
		}
		rt = body["refresh_token"].(string)
	}
}

func TestDurableJournalRejectsUnknownFamily(t *testing.T) {
	_, rt := newEnv(t, nil).tokens(t) // issued with a different (memory) journal
	e := newEnv(t, func(c *Config) { c.Journal = durableJournal() })
	w, body := e.token(t, refreshForm(rt), true)
	wantTokenError(t, w, body, 400, "invalid_grant")
}

func TestMemoryJournalAdoptsUnknownFamily(t *testing.T) {
	// AUTH_STATE=memory: a restart must not force a new login.
	_, rt := newEnv(t, nil).tokens(t)
	e := newEnv(t, nil)
	w, body := e.token(t, refreshForm(rt), true)
	if w.Code != 200 {
		t.Fatalf("memory mode rejected refresh after restart: %v", body)
	}
	w, body = e.token(t, refreshForm(rt), true) // and then detects reuse
	wantTokenError(t, w, body, 400, "invalid_grant")
}

func TestJournalOutage(t *testing.T) {
	fj := &flakyJournal{Journal: durableJournal()}
	e := newEnv(t, func(c *Config) { c.Journal = fj })
	at, rt := e.tokens(t)

	fj.setDown(true)
	w, body := e.token(t, refreshForm(rt), true)
	wantTokenError(t, w, body, 503, "temporarily_unavailable")
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
	w, body = e.token(t, codeForm(e.code(t)), true)
	wantTokenError(t, w, body, 503, "temporarily_unavailable")

	// A fresh instance cannot load revocations: not "invalid token" (the
	// client must keep its tokens), but an error.
	e2 := newEnv(t, func(c *Config) { c.Journal = fj; c.Now = e.clock.Now })
	if err := e2.verify(at); err == nil || errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("outage verify err = %v", err)
	}

	fj.setDown(false)
	w, body = e.token(t, refreshForm(rt), true) // nothing was revoked meanwhile
	if w.Code != 200 {
		t.Fatalf("after outage: %v", body)
	}
	if err := e2.verify(at); err != nil {
		t.Fatalf("after outage verify: %v", err)
	}
}

func TestFamilyState(t *testing.T) {
	now := time.Now()
	cases := []struct {
		events         []FamilyEvent
		gen            int
		known, revoked bool
	}{
		{nil, -1, false, false},
		{[]FamilyEvent{{Kind: EventIssued, Gen: 0}, {Kind: EventIssued, Gen: 1}}, 1, true, false},
		{[]FamilyEvent{{Kind: EventIssued, Gen: 3}, {Kind: EventRevoked, At: now}}, 3, true, true},
		{[]FamilyEvent{{Kind: EventRevoked}}, -1, true, true},
	}
	for i, tc := range cases {
		gen, known, revoked := familyState(tc.events)
		if gen != tc.gen || known != tc.known || revoked != tc.revoked {
			t.Errorf("%d: got %d %v %v", i, gen, known, revoked)
		}
	}
}
