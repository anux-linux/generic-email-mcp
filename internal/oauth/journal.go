package oauth

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Token families. A family is the chain of refresh tokens that starts with
// one authorization code. Every rotation records the next generation; a
// refresh token is valid only while its generation is the family's newest.
// Presenting an older generation is reuse (a copy was stolen or replayed)
// and revokes the family, including its access tokens.

// Event kinds.
const (
	EventIssued  = "issued"
	EventRevoked = "revoked"
)

// FamilyEvent is one journal entry.
type FamilyEvent struct {
	Family string
	Kind   string // EventIssued or EventRevoked
	Gen    int    // for EventIssued
	At     time.Time
}

// Journal stores family events. The server serializes all calls, so
// implementations need not be atomic across processes (run one instance).
type Journal interface {
	// Update loads the newest events of family (newest last), calls
	// decide, appends the event it returns (if non-nil) and returns
	// decide's error, or the append error.
	Update(ctx context.Context, family string, decide func(events []FamilyEvent) (*FamilyEvent, error)) error
	// Revocations returns revocation events recorded at or after since.
	Revocations(ctx context.Context, since time.Time) ([]FamilyEvent, error)
	// Durable reports whether events survive a restart. A durable journal
	// rejects refresh tokens of families it has never seen; a memory
	// journal adopts them (otherwise every restart would force a new login).
	Durable() bool
}

var (
	errFamilyRevoked = errors.New("token family revoked")
	errFamilyReused  = errors.New("refresh token reuse")
	errFamilyUnknown = errors.New("unknown token family")
	errJournal       = errors.New("authorization state unavailable")
)

// familyState summarizes events: the newest issued generation and whether
// the family is revoked.
func familyState(events []FamilyEvent) (gen int, known, revoked bool) {
	gen = -1
	for _, e := range events {
		switch e.Kind {
		case EventRevoked:
			revoked = true
		case EventIssued:
			known = true
			gen = max(gen, e.Gen)
		}
	}
	return gen, known || revoked, revoked
}

// MemoryJournal keeps the newest state per family in memory. It is lost on
// restart (AUTH_STATE=memory, and tests).
type MemoryJournal struct {
	mu      sync.Mutex
	events  map[string][]FamilyEvent
	durable bool
	ttl     time.Duration
}

// NewMemoryJournal returns an empty journal. Families are forgotten ttl
// after their last event (pass the refresh-token lifetime).
func NewMemoryJournal(ttl time.Duration) *MemoryJournal {
	return &MemoryJournal{events: map[string][]FamilyEvent{}, ttl: ttl}
}

func (j *MemoryJournal) Durable() bool { return j.durable }

func (j *MemoryJournal) Update(_ context.Context, family string, decide func([]FamilyEvent) (*FamilyEvent, error)) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	ev, err := decide(append([]FamilyEvent(nil), j.events[family]...))
	if ev != nil {
		for f, evs := range j.events {
			if last := evs[len(evs)-1]; ev.At.Sub(last.At) > j.ttl {
				delete(j.events, f)
			}
		}
		// The newest event carries the state; keep a short tail.
		evs := append(j.events[family], *ev)
		if len(evs) > 4 {
			evs = evs[len(evs)-4:]
		}
		j.events[family] = evs
	}
	return err
}

func (j *MemoryJournal) Revocations(_ context.Context, since time.Time) ([]FamilyEvent, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []FamilyEvent
	for _, evs := range j.events {
		for _, e := range evs {
			if e.Kind == EventRevoked && !e.At.Before(since) {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

// revocations caches revoked families for access-token checks, loading
// recent revocations from the journal once per process.
type revocations struct {
	mu      sync.Mutex
	loaded  bool
	revoked map[string]time.Time // family -> drop after
}

func (s *Server) familyRevoked(ctx context.Context, family string) (bool, error) {
	r := &s.revoked
	r.mu.Lock()
	defer r.mu.Unlock()
	now := s.cfg.Now()
	if !r.loaded {
		// Only revocations newer than the oldest still-valid access token
		// matter here; refresh tokens are checked against the journal.
		evs, err := s.journal.Revocations(ctx, now.Add(-s.cfg.AccessTTL-leeway))
		if err != nil {
			return false, errJournal
		}
		for _, e := range evs {
			r.revoked[e.Family] = e.At.Add(s.cfg.AccessTTL + leeway)
		}
		r.loaded = true
	}
	for f, until := range r.revoked {
		if now.After(until) {
			delete(r.revoked, f)
		}
	}
	_, ok := r.revoked[family]
	return ok, nil
}

func (s *Server) cacheRevocation(family string) {
	s.revoked.mu.Lock()
	s.revoked.revoked[family] = s.cfg.Now().Add(s.cfg.AccessTTL + leeway)
	s.revoked.mu.Unlock()
}

// updateFamily serializes journal updates.
func (s *Server) updateFamily(ctx context.Context, family string, decide func([]FamilyEvent) (*FamilyEvent, error)) error {
	s.famMu.Lock()
	defer s.famMu.Unlock()
	return s.journal.Update(ctx, family, decide)
}

// startFamily records generation 0 for a new family.
func (s *Server) startFamily(ctx context.Context, family string) error {
	err := s.updateFamily(ctx, family, func([]FamilyEvent) (*FamilyEvent, error) {
		return &FamilyEvent{Family: family, Kind: EventIssued, Gen: 0, At: s.cfg.Now()}, nil
	})
	if err != nil {
		return errJournal
	}
	return nil
}

// revokeFamily durably revokes family. Revocation is also cached for
// access-token checks even if the journal write fails.
func (s *Server) revokeFamily(ctx context.Context, family string) {
	s.cacheRevocation(family)
	_ = s.updateFamily(ctx, family, func([]FamilyEvent) (*FamilyEvent, error) {
		return &FamilyEvent{Family: family, Kind: EventRevoked, At: s.cfg.Now()}, nil
	})
}

// rotateFamily advances family from gen to gen+1, detecting reuse.
func (s *Server) rotateFamily(ctx context.Context, family string, gen int) error {
	var decided error
	err := s.updateFamily(ctx, family, func(evs []FamilyEvent) (*FamilyEvent, error) {
		cur, known, revoked := familyState(evs)
		now := s.cfg.Now()
		switch {
		case revoked:
			decided = errFamilyRevoked
		case !known && s.journal.Durable():
			decided = errFamilyUnknown
		case !known || gen == cur:
			return &FamilyEvent{Family: family, Kind: EventIssued, Gen: gen + 1, At: now}, nil
		default:
			decided = errFamilyReused
			return &FamilyEvent{Family: family, Kind: EventRevoked, At: now}, decided
		}
		return nil, decided
	})
	switch {
	case decided != nil:
		if errors.Is(decided, errFamilyReused) {
			s.cacheRevocation(family)
		}
		return decided
	case err != nil:
		return errJournal
	}
	return nil
}
