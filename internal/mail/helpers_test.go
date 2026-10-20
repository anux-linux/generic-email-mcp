package mail

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/anux-linux/generic-email-mcp/internal/testutil"
)

// fakePolicy records Admit calls and optionally rejects.
type fakePolicy struct {
	mu     sync.Mutex
	calls  [][]string
	reject error
}

func (p *fakePolicy) Admit(ctx context.Context, rcpts []string, ledger SendLedger) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, append([]string(nil), rcpts...))
	if p.reject != nil {
		return p.reject
	}
	if ledger != nil {
		return ledger.Record(ctx, time.Now())
	}
	return nil
}

func (p *fakePolicy) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

type testEnv struct {
	t      *testing.T
	certs  *testutil.TLS
	imap   *testutil.IMAPServer
	smtp   *testutil.SMTPServer
	policy *fakePolicy
	client *Client

	mu       sync.Mutex
	commands []string
}

var testDraftKey = bytes.Repeat([]byte{0x42}, 32)

// newEnv starts IMAP (caps nil = Dovecot-like) and SMTP servers with the
// standard folder set and returns a Client wired to both.
func newEnv(t *testing.T, caps imap.CapSet, specialUse bool) *testEnv {
	t.Helper()
	certs := testutil.NewTLS(t)
	is := testutil.StartIMAP(t, certs, caps)
	attr := func(a imap.MailboxAttr) []imap.MailboxAttr {
		if specialUse {
			return []imap.MailboxAttr{a}
		}
		return nil
	}
	is.AddFolder(t, "Drafts", attr(imap.MailboxAttrDrafts)...)
	is.AddFolder(t, "Sent", attr(imap.MailboxAttrSent)...)
	is.AddFolder(t, "Trash", attr(imap.MailboxAttrTrash)...)
	is.AddFolder(t, "Archive", attr(imap.MailboxAttrArchive)...)
	is.AddFolder(t, "Projects")
	ss := testutil.StartSMTP(t, certs, is.Username, is.Password)

	env := &testEnv{t: t, certs: certs, imap: is, smtp: ss, policy: &fakePolicy{}}
	env.client = env.newClient(func(*Config) {})
	return env
}

func (env *testEnv) config() Config {
	return Config{
		IMAPAddr:  env.imap.Addr,
		SMTPAddr:  env.smtp.Addr,
		Username:  env.imap.Username,
		Password:  env.imap.Password,
		FromName:  "Test User",
		SaveSent:  true,
		DraftKey:  testDraftKey,
		TLSConfig: env.certs.Client,
	}
}

func (env *testEnv) newClient(mod func(*Config)) *Client {
	env.t.Helper()
	cfg := env.config()
	mod(&cfg)
	c, err := New(cfg, env.policy)
	if err != nil {
		env.t.Fatal(err)
	}
	c.onIMAPCommand = func(name string) {
		env.mu.Lock()
		env.commands = append(env.commands, name)
		env.mu.Unlock()
	}
	return c
}

func (env *testEnv) seenCommands() []string {
	env.mu.Lock()
	defer env.mu.Unlock()
	return append([]string(nil), env.commands...)
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func mustErrIs(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("err = %v, want %v", err, target)
	}
}

var baseDate = time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)

// rawMail builds a simple RFC 5322 message with CRLF line endings.
func rawMail(headers map[string]string, body string) string {
	var b strings.Builder
	order := []string{"Date", "From", "To", "Cc", "Reply-To", "Subject", "Message-ID", "In-Reply-To", "References", "MIME-Version", "Content-Type", "Content-Transfer-Encoding"}
	if _, ok := headers["Date"]; !ok {
		headers["Date"] = "Tue, 10 Mar 2026 09:00:00 +0000"
	}
	for _, k := range order {
		if v, ok := headers[k]; ok {
			b.WriteString(k + ": " + v + "\r\n")
		}
	}
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	return b.String()
}

func plainMail(from, subject, body string) string {
	return rawMail(map[string]string{
		"From":         from,
		"To":           "user@example.org",
		"Subject":      subject,
		"Message-ID":   "<" + strings.ReplaceAll(strings.ToLower(subject), " ", "-") + "@sender.example>",
		"MIME-Version": "1.0",
		"Content-Type": "text/plain; charset=utf-8",
	}, body)
}

func findMessage(msgs []testutil.MessageInfo, uid imap.UID) *testutil.MessageInfo {
	for i := range msgs {
		if msgs[i].UID == uid {
			return &msgs[i]
		}
	}
	return nil
}
