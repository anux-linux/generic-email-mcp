// Package policy decides whether outgoing mail may be sent: an optional
// recipient allowlist and a cap on sends per rolling 24 hours.
package policy

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Env var names read by FromEnv.
const (
	EnvAllowlist  = "SEND_ALLOWLIST"
	EnvMaxPerDay  = "MAX_SENDS_PER_DAY"
	DefaultPerDay = 20
	maxPerDay     = 1000
	window        = 24 * time.Hour
)

// Errors returned by Admit and CheckRecipients.
var (
	ErrNotAllowed      = errors.New("recipient not permitted by SEND_ALLOWLIST")
	ErrDailyCap        = errors.New("daily send limit reached (MAX_SENDS_PER_DAY)")
	ErrSendingDisabled = errors.New("sending is disabled (MAX_SENDS_PER_DAY=0)")
)

// Config is the policy configuration.
type Config struct {
	// Allowlist entries are exact addresses ("bob@example.org") or domains
	// ("example.org" or "@example.org"), matched case-insensitively.
	// Subdomains do not match. Empty means every recipient is allowed.
	Allowlist []string
	// MaxPerDay caps sends (messages, not recipients) in any rolling
	// 24-hour window. 0 disables sending.
	MaxPerDay int
}

// FromEnv reads SEND_ALLOWLIST (comma or whitespace separated) and
// MAX_SENDS_PER_DAY (default 20).
func FromEnv(getenv func(string) string) (Config, error) {
	c := Config{MaxPerDay: DefaultPerDay}
	if v := strings.TrimSpace(getenv(EnvMaxPerDay)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > maxPerDay {
			return Config{}, fmt.Errorf("%s must be an integer in [0, %d]", EnvMaxPerDay, maxPerDay)
		}
		c.MaxPerDay = n
	}
	c.Allowlist = strings.FieldsFunc(getenv(EnvAllowlist), func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	})
	return c, nil
}

// Memory is an in-process Policy. State is lost on restart (see
// docs/DECISIONS.md); it is safe for concurrent use.
type Memory struct {
	addrs   map[string]bool
	domains map[string]bool
	max     int
	now     func() time.Time

	mu    sync.Mutex
	sends []time.Time // admitted sends within the window, oldest first
}

// NewMemory validates cfg and returns a policy.
func NewMemory(cfg Config) (*Memory, error) {
	if cfg.MaxPerDay < 0 || cfg.MaxPerDay > maxPerDay {
		return nil, fmt.Errorf("max sends per day must be in [0, %d]", maxPerDay)
	}
	m := &Memory{addrs: map[string]bool{}, domains: map[string]bool{}, max: cfg.MaxPerDay, now: time.Now}
	for _, e := range cfg.Allowlist {
		e = strings.ToLower(strings.TrimSpace(e))
		switch {
		case e == "":
		case strings.HasPrefix(e, "@") && validDomain(e[1:]):
			m.domains[e[1:]] = true
		case strings.Count(e, "@") == 1 && validDomain(e[strings.IndexByte(e, '@')+1:]) && e[0] != '@':
			m.addrs[e] = true
		case !strings.Contains(e, "@") && validDomain(e):
			m.domains[e] = true
		default:
			// Entries are configuration, not secrets, but keep logs clean.
			return nil, fmt.Errorf("invalid %s entry", EnvAllowlist)
		}
	}
	return m, nil
}

func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 || !strings.Contains(d, ".") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return !strings.Contains(d, "..")
}

// Restricted reports whether an allowlist is configured.
func (m *Memory) Restricted() bool { return len(m.addrs)+len(m.domains) > 0 }

// CheckRecipients reports recipients the allowlist rejects, without
// consuming quota. Used for early warnings at draft time.
func (m *Memory) CheckRecipients(rcpts []string) error {
	var bad []string
	for _, r := range rcpts {
		if !m.allowed(r) {
			bad = append(bad, r)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%w: %s", ErrNotAllowed, strings.Join(bad, ", "))
	}
	return nil
}

func (m *Memory) allowed(addr string) bool {
	if !m.Restricted() {
		return true
	}
	a := strings.ToLower(strings.TrimSpace(addr))
	at := strings.LastIndexByte(a, '@')
	if at <= 0 {
		return false
	}
	return m.addrs[a] || m.domains[a[at+1:]]
}

// Admit checks the allowlist and, atomically, the rolling cap; on success
// it records the send. Implements mail.SendPolicy.
func (m *Memory) Admit(_ context.Context, rcpts []string) error {
	if m.max == 0 {
		return ErrSendingDisabled
	}
	if len(rcpts) == 0 {
		return fmt.Errorf("%w: no recipients", ErrNotAllowed)
	}
	if err := m.CheckRecipients(rcpts); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	cut := 0
	for cut < len(m.sends) && now.Sub(m.sends[cut]) >= window {
		cut++
	}
	m.sends = m.sends[cut:]
	if len(m.sends) >= m.max {
		retry := m.sends[0].Add(window).Sub(now).Round(time.Minute)
		return fmt.Errorf("%w: %d sends in the last 24 hours; next send possible in about %s", ErrDailyCap, len(m.sends), retry)
	}
	m.sends = append(m.sends, now)
	return nil
}

// Remaining returns how many sends the cap still allows now.
func (m *Memory) Remaining() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	n := 0
	for _, t := range m.sends {
		if now.Sub(t) < window {
			n++
		}
	}
	return max(m.max-n, 0)
}
