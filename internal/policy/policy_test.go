package policy

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTest(t *testing.T, cfg Config) (*Memory, *time.Time) {
	t.Helper()
	m, err := NewMemory(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	return m, &now
}

func TestAllowlist(t *testing.T) {
	m, _ := newTest(t, Config{Allowlist: []string{"Bob@Example.org", "partner.example", "@team.example"}, MaxPerDay: 100})
	for _, ok := range []string{"bob@example.org", "BOB@EXAMPLE.ORG", "anyone@partner.example", "x@team.example"} {
		if err := m.Admit(t.Context(), []string{ok}); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"alice@example.org", "a@sub.partner.example", "a@partner.example.evil", "partner.example", "x@notteam.example"} {
		if err := m.Admit(t.Context(), []string{bad}); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: err = %v", bad, err)
		}
	}
	// One bad recipient rejects the whole message and names it.
	err := m.Admit(t.Context(), []string{"bob@example.org", "eve@evil.example"})
	if !errors.Is(err, ErrNotAllowed) || !strings.Contains(err.Error(), "eve@evil.example") {
		t.Fatalf("err = %v", err)
	}
	if err := m.CheckRecipients([]string{"bob@example.org"}); err != nil {
		t.Fatal(err)
	}
}

func TestNoAllowlistAllowsAll(t *testing.T) {
	m, _ := newTest(t, Config{MaxPerDay: 5})
	if m.Restricted() {
		t.Fatal("restricted without entries")
	}
	if err := m.Admit(t.Context(), []string{"anyone@anywhere.example"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Admit(t.Context(), nil); err == nil {
		t.Fatal("empty recipient list admitted")
	}
}

func TestRollingDailyCap(t *testing.T) {
	m, now := newTest(t, Config{MaxPerDay: 3})
	rc := []string{"a@example.org"}
	for i := range 3 {
		if err := m.Admit(t.Context(), rc); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		*now = now.Add(time.Hour)
	}
	if m.Remaining() != 0 {
		t.Fatalf("remaining = %d", m.Remaining())
	}
	err := m.Admit(t.Context(), rc)
	if !errors.Is(err, ErrDailyCap) || !strings.Contains(err.Error(), "21h0m0s") {
		t.Fatalf("err = %v", err)
	}
	// Not a calendar day: midnight does not reset the window.
	*now = now.Add(20*time.Hour + 59*time.Minute) // 23h59m after the first send
	if err := m.Admit(t.Context(), rc); !errors.Is(err, ErrDailyCap) {
		t.Fatalf("window reset early: %v", err)
	}
	*now = now.Add(time.Minute) // first send is now 24h old
	if err := m.Admit(t.Context(), rc); err != nil {
		t.Fatalf("window did not roll: %v", err)
	}
}

func TestCapZeroDisablesSending(t *testing.T) {
	m, _ := newTest(t, Config{MaxPerDay: 0})
	if err := m.Admit(t.Context(), []string{"a@example.org"}); !errors.Is(err, ErrSendingDisabled) {
		t.Fatalf("err = %v", err)
	}
}

func TestRejectedAllowlistDoesNotConsumeQuota(t *testing.T) {
	m, _ := newTest(t, Config{Allowlist: []string{"example.org"}, MaxPerDay: 1})
	if err := m.Admit(t.Context(), []string{"x@evil.example"}); !errors.Is(err, ErrNotAllowed) {
		t.Fatal(err)
	}
	if err := m.Admit(t.Context(), []string{"x@example.org"}); err != nil {
		t.Fatalf("quota consumed by rejected send: %v", err)
	}
}

func TestConcurrentAdmitIsAtomic(t *testing.T) {
	m, _ := newTest(t, Config{MaxPerDay: 20})
	var ok, capped atomic.Int32
	var wg sync.WaitGroup
	for range 200 {
		wg.Go(func() {
			switch err := m.Admit(t.Context(), []string{"a@example.org"}); {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrDailyCap):
				capped.Add(1)
			default:
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if ok.Load() != 20 || capped.Load() != 180 {
		t.Fatalf("ok=%d capped=%d", ok.Load(), capped.Load())
	}
}

func TestFromEnv(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	c, err := FromEnv(get)
	if err != nil || c.MaxPerDay != DefaultPerDay || len(c.Allowlist) != 0 {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	env[EnvAllowlist] = " a@example.org, example.net;@x.example\n"
	env[EnvMaxPerDay] = "5"
	c, err = FromEnv(get)
	if err != nil || c.MaxPerDay != 5 || strings.Join(c.Allowlist, "|") != "a@example.org|example.net|@x.example" {
		t.Fatalf("parsed: %+v %v", c, err)
	}
	for _, bad := range []string{"-1", "abc", "1001"} {
		env[EnvMaxPerDay] = bad
		if _, err := FromEnv(get); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestInvalidAllowlistEntries(t *testing.T) {
	for _, bad := range []string{"@", "a@", "a@b@c.example", "no_dot", "*.example.org", "a@-x..example", ".example.org"} {
		if _, err := NewMemory(Config{Allowlist: []string{bad}, MaxPerDay: 1}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
