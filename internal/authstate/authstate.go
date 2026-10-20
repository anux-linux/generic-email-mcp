// Package authstate stores the OAuth token-family journal in the mailbox,
// adapting mail.RecordStore to oauth.Journal.
package authstate

import (
	"context"
	"strconv"
	"time"

	"github.com/anux-linux/generic-email-mcp/internal/mail"
	"github.com/anux-linux/generic-email-mcp/internal/oauth"
)

// Record fields.
const (
	fieldFamily = "fam"
	fieldKind   = "kind"
	fieldGen    = "gen"
	fieldAt     = "at"

	// The family state is carried by its newest event; a few more guard
	// against out-of-order appends.
	newestEvents = 3
)

// IMAP is a durable oauth.Journal backed by a protected mailbox folder.
type IMAP struct{ rs *mail.RecordStore }

var _ oauth.Journal = (*IMAP)(nil)

// New returns a journal on rs.
func New(rs *mail.RecordStore) *IMAP { return &IMAP{rs: rs} }

// Durable is true: events survive restarts.
func (*IMAP) Durable() bool { return true }

// Update implements oauth.Journal in one IMAP session.
func (j *IMAP) Update(ctx context.Context, family string, decide func([]oauth.FamilyEvent) (*oauth.FamilyEvent, error)) error {
	return j.rs.Update(ctx, fieldFamily, family, newestEvents, func(recs []mail.Record) (mail.Record, error) {
		ev, err := decide(toEvents(recs))
		if ev == nil {
			return nil, err
		}
		return toRecord(*ev), err
	})
}

// Revocations implements oauth.Journal.
func (j *IMAP) Revocations(ctx context.Context, since time.Time) ([]oauth.FamilyEvent, error) {
	recs, err := j.rs.Find(ctx, fieldKind, oauth.EventRevoked, since)
	if err != nil {
		return nil, err
	}
	var out []oauth.FamilyEvent
	for _, e := range toEvents(recs) {
		if !e.At.Before(since) {
			out = append(out, e)
		}
	}
	return out, nil
}

func toRecord(e oauth.FamilyEvent) mail.Record {
	r := mail.Record{fieldFamily: e.Family, fieldKind: e.Kind, fieldAt: e.At.UTC().Format(time.RFC3339Nano)}
	if e.Kind == oauth.EventIssued {
		r[fieldGen] = strconv.Itoa(e.Gen)
	}
	return r
}

// toEvents converts records, skipping malformed ones (a malformed record
// cannot make a family valid: only well-formed issued events advance it).
func toEvents(recs []mail.Record) []oauth.FamilyEvent {
	var out []oauth.FamilyEvent
	for _, r := range recs {
		at, err := time.Parse(time.RFC3339Nano, r[fieldAt])
		if err != nil || r[fieldFamily] == "" {
			continue
		}
		e := oauth.FamilyEvent{Family: r[fieldFamily], Kind: r[fieldKind], At: at}
		switch e.Kind {
		case oauth.EventIssued:
			if e.Gen, err = strconv.Atoi(r[fieldGen]); err != nil || e.Gen < 0 {
				continue
			}
		case oauth.EventRevoked:
		default:
			continue
		}
		out = append(out, e)
	}
	return out
}
