package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/anux-linux/generic-email-mcp/internal/logging"
	"github.com/anux-linux/generic-email-mcp/internal/mail"
	"github.com/anux-linux/generic-email-mcp/internal/policy"
	"github.com/anux-linux/generic-email-mcp/internal/testutil"
)

// toolCaller calls tools from any goroutine: it returns errors instead of
// calling t.Fatal.
type toolCaller struct {
	ctx context.Context
	cs  *mcp.ClientSession
}

var errKindRE = regexp.MustCompile(`^Error \(([a-z_]+)\)`)

// call returns the result text, or the error kind of a tool error.
func (c toolCaller) call(name string, args map[string]any) (text, kind string, err error) {
	res, err := c.cs.CallTool(c.ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return "", "", fmt.Errorf("%s: protocol error: %w", name, err)
	}
	if len(res.Content) != 1 {
		return "", "", fmt.Errorf("%s: %d content blocks", name, len(res.Content))
	}
	text = res.Content[0].(*mcp.TextContent).Text
	if res.IsError {
		m := errKindRE.FindStringSubmatch(text)
		if m == nil {
			return "", "", fmt.Errorf("%s: malformed error %q", name, text)
		}
		return text, m[1], nil
	}
	return text, "", nil
}

// ok calls a tool that must succeed and decodes its payload into v.
func (c toolCaller) ok(name string, args map[string]any, v any) error {
	text, kind, err := c.call(name, args)
	if err != nil {
		return err
	}
	if kind != "" {
		return fmt.Errorf("%s: %s", name, text)
	}
	m := blockRE.FindStringSubmatch(text)
	if m == nil || m[1] != m[3] {
		return fmt.Errorf("%s: malformed untrusted block", name)
	}
	if v == nil {
		return nil
	}
	return json.Unmarshal([]byte(m[2]), v)
}

// TestConcurrentToolCalls runs the tools in parallel sessions against the
// real mail client, the IMAP test server and the stub SMTP server (run with
// -race). Parallel reads and writes must not interfere, and a burst of
// sends — every draft sent twice at once — must deliver exactly the daily
// cap, each draft at most once.
func TestConcurrentToolCalls(t *testing.T) {
	const (
		workers   = 8
		perWorker = 2 // drafts per worker
		dailyCap  = 3
	)
	certs := testutil.NewTLS(t)
	is := testutil.StartIMAP(t, certs, nil)
	for name, attr := range map[string]imap.MailboxAttr{"Drafts": imap.MailboxAttrDrafts, "Sent": imap.MailboxAttrSent,
		"Trash": imap.MailboxAttrTrash, "Archive": imap.MailboxAttrArchive} {
		is.AddFolder(t, name, attr)
	}
	ss := testutil.StartSMTP(t, certs, is.Username, is.Password)
	for w := range workers {
		is.AddMessage(t, "INBOX", fmt.Sprintf("From: s%d@example.net\r\nTo: user@example.org\r\nSubject: MARKER-SUBJECT-%d\r\n"+
			"Message-ID: <m%d@example.net>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nMARKER-BODY-%d\r\n", w, w, w, w),
			time.Date(2026, 3, 1, 9, w, 0, 0, time.UTC))
	}
	pol, err := policy.NewMemory(policy.Config{Allowlist: []string{"example.net"}, MaxPerDay: dailyCap})
	if err != nil {
		t.Fatal(err)
	}
	mc, err := mail.New(mail.Config{
		IMAPAddr: is.Addr, SMTPAddr: ss.Addr, Username: is.Username, Password: is.Password,
		SaveSent: true, DraftKey: []byte(draftKeyHex), TLSConfig: certs.Client, LedgerFolder: mail.DefaultLedgerFolder,
	}, pol)
	if err != nil {
		t.Fatal(err)
	}
	var logs syncBuffer
	logger := logging.New(&logs, logging.Options{Level: slog.LevelDebug})
	callers := make([]toolCaller, workers)
	for i := range callers {
		callers[i] = toolCaller{ctx: t.Context(), cs: connect(t, mc, Options{Logger: logger, Policy: pol})}
	}

	// Phase 1: each worker lists, searches, reads, flags and archives its
	// own message and creates drafts, all at the same time.
	errs := make(chan error, workers*perWorker*4)
	drafts := make([][]string, workers)
	archived := make([]string, workers)
	var wg sync.WaitGroup
	for w, c := range callers {
		wg.Go(func() {
			fail := func(err error) { errs <- fmt.Errorf("worker %d: %w", w, err) }
			if err := c.ok("mail_list_folders", map[string]any{}, nil); err != nil {
				fail(err)
				return
			}
			var sr searchOut
			if err := c.ok("mail_search", map[string]any{"subject": fmt.Sprintf("MARKER-SUBJECT-%d", w)}, &sr); err != nil {
				fail(err)
				return
			}
			if sr.TotalMatches != 1 {
				fail(fmt.Errorf("search found %d", sr.TotalMatches))
				return
			}
			id := sr.Messages[0].ID
			var msg messageOut
			if err := c.ok("mail_read", map[string]any{"id": id}, &msg); err != nil {
				fail(err)
				return
			}
			if !strings.Contains(msg.Body, fmt.Sprintf("MARKER-BODY-%d", w)) {
				fail(errors.New("read returned another message"))
				return
			}
			if err := c.ok("mail_mark_read", map[string]any{"ids": []string{id}}, nil); err != nil {
				fail(err)
				return
			}
			var mv moveOut
			if err := c.ok("mail_move", map[string]any{"ids": []string{id}, "destination": "archive"}, &mv); err != nil {
				fail(err)
				return
			}
			if len(mv.Moved) != 1 || mv.Moved[0].NewID == "" {
				fail(fmt.Errorf("move = %+v", mv))
				return
			}
			archived[w] = mv.Moved[0].NewID
			for j := range perWorker {
				var d draftOut
				args := map[string]any{"to": []string{fmt.Sprintf("r%d-%d@example.net", w, j)}, "subject": "s", "body": "MARKER-DRAFT"}
				if err := c.ok("mail_create_draft", args, &d); err != nil {
					fail(err)
					return
				}
				drafts[w] = append(drafts[w], d.DraftID)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		t.FailNow()
	}
	if n := len(is.Messages(t, "INBOX")); n != 0 {
		t.Fatalf("INBOX has %d messages after archiving all", n)
	}
	archive := is.Messages(t, "Archive")
	if len(archive) != workers {
		t.Fatalf("Archive has %d messages, want %d", len(archive), workers)
	}
	for _, m := range archive {
		if !m.HasFlag(imap.FlagSeen) {
			t.Fatal("archived message lost its \\Seen flag")
		}
	}
	var all []string
	for _, ds := range drafts {
		all = append(all, ds...)
	}
	if n := len(is.Messages(t, "Drafts")); n != len(all) {
		t.Fatalf("Drafts has %d messages, want %d", n, len(all))
	}

	// sendBurst sends each listed draft ID from its own goroutine, all at
	// once, and returns the delivered draft -> reported recipient.
	sendBurst := func(ids []string) map[string]string {
		t.Helper()
		type outcome struct{ draft, kind, rcpt string }
		results := make(chan outcome, len(ids))
		errs := make(chan error, len(ids))
		for i, d := range ids {
			c := callers[i%workers]
			wg.Go(func() {
				text, kind, err := c.call("mail_send_draft", map[string]any{"draft_id": d, "confirm": true})
				if err != nil {
					errs <- err
					return
				}
				o := outcome{draft: d, kind: kind}
				if kind == "" {
					var s sendOut
					m := blockRE.FindStringSubmatch(text)
					if m == nil || json.Unmarshal([]byte(m[2]), &s) != nil || len(s.To) != 1 {
						errs <- fmt.Errorf("bad send result %q", text)
						return
					}
					if !s.SavedToSent || !s.DraftToTrash {
						errs <- fmt.Errorf("post-send steps failed under concurrency: %+v", s)
					}
					o.rcpt = s.To[0]
				}
				results <- o
			})
		}
		wg.Wait()
		close(errs)
		close(results)
		for err := range errs {
			t.Error(err)
		}
		sent := map[string]string{}
		for o := range results {
			switch o.kind {
			case "":
				if _, dup := sent[o.draft]; dup {
					t.Errorf("draft %s sent twice", o.rcpt)
				}
				sent[o.draft] = o.rcpt
			case "policy", "already_sent":
			default:
				t.Errorf("unexpected error kind %q", o.kind)
			}
		}
		return sent
	}

	// Phase 2: one draft sent from every session at once is delivered
	// exactly once (the per-draft guard; the cap is not the limit here).
	if sent := sendBurst(slices.Repeat(all[:1], workers)); len(sent) != 1 || len(ss.Messages()) != 1 {
		t.Fatalf("hot draft: %d reported sends, %d SMTP messages; want 1 and 1", len(sent), len(ss.Messages()))
	}

	// Phase 3: every other draft sent twice at once: exactly the remaining
	// cap is delivered, each draft at most once.
	var burst []string
	for _, d := range all[1:] {
		burst = append(burst, d, d)
	}
	sent := sendBurst(burst)
	if len(sent) != dailyCap-1 {
		t.Fatalf("%d sends succeeded, want the remaining cap %d", len(sent), dailyCap-1)
	}
	smtp := ss.Messages()
	if len(smtp) != dailyCap {
		t.Fatalf("SMTP received %d messages, want %d", len(smtp), dailyCap)
	}
	rcpts := map[string]int{}
	for _, m := range smtp {
		if len(m.Rcpts) != 1 {
			t.Fatalf("SMTP recipients %v", m.Rcpts)
		}
		rcpts[m.Rcpts[0]]++
	}
	for _, r := range sent {
		if rcpts[r] != 1 {
			t.Fatalf("reported send to %s delivered %d times", r, rcpts[r])
		}
	}
	if len(rcpts) != dailyCap {
		t.Fatalf("%d distinct SMTP recipients, want %d", len(rcpts), dailyCap)
	}
	for folder, want := range map[string]int{mail.DefaultLedgerFolder: dailyCap, "Sent": dailyCap, "Trash": dailyCap, "Drafts": len(all) - dailyCap} {
		if n := len(is.Messages(t, folder)); n != want {
			t.Errorf("%s has %d messages, want %d", folder, n, want)
		}
	}
	for _, id := range archived {
		var msg messageOut
		if err := callers[0].ok("mail_read", map[string]any{"id": id}, &msg); err != nil {
			t.Errorf("archived message unreadable: %v", err)
		}
	}

	out := logs.String()
	for _, leak := range []string{"MARKER", "@example.net", "user@example.org", is.Password, draftKeyHex, "d1.", "m1."} {
		if strings.Contains(out, leak) {
			t.Errorf("log leaked %q", leak)
		}
	}
}
