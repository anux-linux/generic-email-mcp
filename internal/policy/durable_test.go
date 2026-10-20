package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/anux-linux/generic-email-mcp/internal/mail"
	"github.com/anux-linux/generic-email-mcp/internal/testutil"
)

type fakeLedger struct {
	times     []time.Time
	recentErr error
	recordErr error
	blind     bool // Record succeeds but entries are never found
}

func (l *fakeLedger) Recent(_ context.Context, since time.Time, limit int) ([]time.Time, error) {
	if l.recentErr != nil {
		return nil, l.recentErr
	}
	var out []time.Time
	for _, t := range l.times {
		if !t.Before(since) {
			out = append(out, t)
		}
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

func (l *fakeLedger) Record(_ context.Context, t time.Time) error {
	if l.recordErr != nil {
		return l.recordErr
	}
	if l.blind {
		return nil
	}
	l.times = append(l.times, t)
	return nil
}

func TestLedgerIsSourceOfTruth(t *testing.T) {
	m, now := newTest(t, Config{MaxPerDay: 2})
	l := &fakeLedger{times: []time.Time{now.Add(-25 * time.Hour), now.Add(-time.Hour)}}
	rc := []string{"a@example.org"}
	if err := m.Admit(t.Context(), rc, l); err != nil {
		t.Fatal(err)
	}
	if len(l.times) != 3 || m.Remaining() != 0 {
		t.Fatalf("times=%d remaining=%d", len(l.times), m.Remaining())
	}
	if err := m.Admit(t.Context(), rc, l); !errors.Is(err, ErrDailyCap) {
		t.Fatalf("err = %v", err)
	}
	// A fresh process (empty memory) sees the same ledger.
	m2, _ := newTest(t, Config{MaxPerDay: 2})
	if err := m2.Admit(t.Context(), rc, l); !errors.Is(err, ErrDailyCap) {
		t.Fatalf("restart reset the cap: %v", err)
	}
}

func TestLedgerFailuresFailClosed(t *testing.T) {
	m, _ := newTest(t, Config{MaxPerDay: 5})
	rc := []string{"a@example.org"}
	if err := m.Admit(t.Context(), rc, &fakeLedger{recentErr: errors.New("imap down")}); !errors.Is(err, ErrLedger) {
		t.Fatalf("read failure: %v", err)
	}
	if err := m.Admit(t.Context(), rc, &fakeLedger{recordErr: errors.New("append failed")}); !errors.Is(err, ErrLedger) {
		t.Fatalf("write failure: %v", err)
	}
	if m.Remaining() != 5 {
		t.Fatalf("failed admits counted: %d", m.Remaining())
	}
	// A ledger whose search never finds entries must not fail open.
	if err := m.Admit(t.Context(), rc, &fakeLedger{blind: true}); !errors.Is(err, ErrLedger) {
		t.Fatalf("blind ledger: %v", err)
	}
}

// TestDurableCapAcrossRestart uses the real IMAP ledger: two "processes"
// (fresh mail.Client + policy) share one mailbox.
func TestDurableCapAcrossRestart(t *testing.T) {
	certs := testutil.NewTLS(t)
	is := testutil.StartIMAP(t, certs, nil)
	is.AddFolder(t, "Drafts", imap.MailboxAttrDrafts)
	is.AddFolder(t, "Sent", imap.MailboxAttrSent)
	is.AddFolder(t, "Trash", imap.MailboxAttrTrash)
	ss := testutil.StartSMTP(t, certs, is.Username, is.Password)

	process := func() *mail.Client {
		pol, err := NewMemory(Config{MaxPerDay: 2})
		if err != nil {
			t.Fatal(err)
		}
		c, err := mail.New(mail.Config{
			IMAPAddr: is.Addr, SMTPAddr: ss.Addr, Username: is.Username, Password: is.Password, SaveSent: true,
			DraftKey: []byte("0123456789abcdef0123456789abcdef"), TLSConfig: certs.Client, LedgerFolder: mail.DefaultLedgerFolder,
		}, pol)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	send := func(c *mail.Client) error {
		d, err := c.CreateDraft(t.Context(), mail.DraftInput{To: []string{"bob@example.net"}, Subject: "s", Body: "b"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.SendDraft(t.Context(), d.ID)
		return err
	}

	first := process()
	for i := range 2 {
		if err := send(first); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	second := process() // restart: in-memory state is gone
	err := send(second)
	if !errors.Is(err, mail.ErrPolicy) || !errors.Is(err, ErrDailyCap) {
		t.Fatalf("cap reset by restart: %v", err)
	}
	if n := len(ss.Messages()); n != 2 {
		t.Fatalf("smtp messages = %d", n)
	}
	if n := len(is.Messages(t, mail.DefaultLedgerFolder)); n != 2 {
		t.Fatalf("ledger entries = %d", n)
	}
}
