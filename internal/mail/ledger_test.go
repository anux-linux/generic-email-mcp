package mail

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func ledgerEnv(t *testing.T) *testEnv {
	t.Helper()
	env := newEnv(t, nil, true)
	env.client = env.newClient(func(c *Config) { c.LedgerFolder = DefaultLedgerFolder })
	return env
}

func TestLedgerRecordAndRecent(t *testing.T) {
	env := ledgerEnv(t)
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	err := env.client.withSession(ctx(t), func(s *session) error {
		l := &imapLedger{s: s, folder: DefaultLedgerFolder, account: env.imap.Username}
		if got, err := l.Recent(ctx(t), now.Add(-24*time.Hour), 10); err != nil || len(got) != 0 {
			t.Fatalf("missing folder: %v %v", got, err)
		}
		for _, at := range []time.Time{now.Add(-30 * time.Hour), now.Add(-3 * time.Hour), now.Add(-2 * time.Hour), now.Add(-1 * time.Hour)} {
			if err := l.Record(ctx(t), at); err != nil { // first call creates the folder
				return err
			}
		}
		got, err := l.Recent(ctx(t), now.Add(-24*time.Hour), 10)
		if err != nil {
			return err
		}
		if len(got) != 3 || !got[0].Equal(now.Add(-3*time.Hour)) || !got[2].Equal(now.Add(-time.Hour)) {
			t.Fatalf("recent = %v", got)
		}
		if got, _ := l.Recent(ctx(t), now.Add(-24*time.Hour), 2); len(got) != 2 || !got[1].Equal(now.Add(-time.Hour)) {
			t.Fatalf("limited = %v", got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	entries := env.imap.Messages(t, DefaultLedgerFolder)
	if len(entries) != 4 || !entries[0].HasFlag(imap.FlagSeen) {
		t.Fatalf("entries = %d", len(entries))
	}
	raw := string(entries[0].Raw)
	if !strings.HasPrefix(raw, "Date: ") || !strings.Contains(raw, "\r\n"+ledgerHeader+": 2026-10-19T06:00:00Z\r\n") || strings.Contains(raw, "example.net") {
		t.Fatalf("entry = %q", raw)
	}
}

func TestSendRecordsLedgerAndStillTrashesDraft(t *testing.T) {
	env := ledgerEnv(t)
	// Put messages in the ledger first so that UID 1..n exist there too: a
	// MOVE on the wrong selected folder would hit them.
	for range 3 {
		env.imap.AddMessage(t, "Drafts", plainMail("user@example.org", "foreign draft", "x"), baseDate, imap.FlagDraft)
	}
	draft, err := env.client.CreateDraft(ctx(t), DraftInput{To: []string{"bob@example.net"}, Subject: "ledger test", Body: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.client.withSession(ctx(t), func(s *session) error {
		l := &imapLedger{s: s, folder: DefaultLedgerFolder, account: env.imap.Username}
		for range 5 {
			if err := l.Record(ctx(t), time.Now().Add(-48*time.Hour)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	res, err := env.client.SendDraft(ctx(t), draft.ID)
	if err != nil || !res.DraftMoved || len(res.Warnings) != 0 {
		t.Fatalf("send: %v %+v", err, res)
	}
	if n := len(env.imap.Messages(t, DefaultLedgerFolder)); n != 6 {
		t.Fatalf("ledger entries = %d, want 6", n)
	}
	trash := env.imap.Messages(t, "Trash")
	if len(trash) != 1 || !strings.Contains(string(trash[0].Raw), "Subject: ledger test") {
		t.Fatalf("wrong message moved to Trash: %d", len(trash))
	}
	if n := len(env.imap.Messages(t, "Drafts")); n != 3 {
		t.Fatalf("drafts = %d, want the 3 foreign drafts", n)
	}
}

func TestLedgerFolderIsProtected(t *testing.T) {
	env := ledgerEnv(t)
	env.imap.AddFolder(t, DefaultLedgerFolder)
	uid := env.imap.AddMessage(t, DefaultLedgerFolder, plainMail("user@example.org", "entry", "x"), baseDate)
	ledgerID := msgRef{DefaultLedgerFolder, env.imap.UIDValidity(t, DefaultLedgerFolder), uid}.String()
	inUID := env.imap.AddMessage(t, "INBOX", plainMail("a@example.net", "x", "y"), baseDate)
	inboxID := msgRef{"INBOX", env.imap.UIDValidity(t, "INBOX"), inUID}.String()

	_, err := env.client.Move(ctx(t), []string{ledgerID}, Destination{Role: RoleTrash})
	mustErrIs(t, err, ErrProtected)
	_, err = env.client.Move(ctx(t), []string{inboxID}, Destination{Folder: DefaultLedgerFolder})
	mustErrIs(t, err, ErrProtected)
	if ErrorKind(err) != "protected" {
		t.Fatalf("kind = %q", ErrorKind(err))
	}
	if len(env.imap.Messages(t, DefaultLedgerFolder)) != 1 || len(env.imap.Messages(t, "INBOX")) != 1 {
		t.Fatal("protected folders changed")
	}
}

func TestLedgerMustNotBeARoleFolder(t *testing.T) {
	env := newEnv(t, nil, true)
	env.client = env.newClient(func(c *Config) { c.LedgerFolder = "Sent" })
	draft, err := env.client.CreateDraft(ctx(t), DraftInput{To: []string{"bob@example.net"}, Subject: "s", Body: "b"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = env.client.SendDraft(ctx(t), draft.ID)
	if !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), "sent folder") {
		t.Fatalf("err = %v", err)
	}
	if len(env.smtp.Messages()) != 0 {
		t.Fatal("sent")
	}
}

func TestLedgerConfig(t *testing.T) {
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	base := map[string]string{EnvUsername: "u@example.org", EnvPassword: "p"}
	cfg, err := ConfigFromEnv(get(base))
	if err != nil || cfg.LedgerFolder != DefaultLedgerFolder {
		t.Fatalf("default: %q %v", cfg.LedgerFolder, err)
	}
	base[EnvLedger] = "memory"
	if cfg, _ = ConfigFromEnv(get(base)); cfg.LedgerFolder != "" {
		t.Fatalf("memory mode: %q", cfg.LedgerFolder)
	}
	base[EnvLedger] = "imap"
	base[EnvLedgerFolder] = "Custom/Ledger"
	if cfg, _ = ConfigFromEnv(get(base)); cfg.LedgerFolder != "Custom/Ledger" {
		t.Fatalf("custom: %q", cfg.LedgerFolder)
	}
	base[EnvLedger] = "redis"
	if _, err := ConfigFromEnv(get(base)); err == nil {
		t.Fatal("bad mode accepted")
	}
	c := Config{Username: "u@example.org", Password: "p", DraftKey: testDraftKey, LedgerFolder: "inbox"}
	if _, err := New(c, &fakePolicy{}); err == nil {
		t.Fatal("INBOX accepted as ledger")
	}
}
