package mail

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestErrorKind(t *testing.T) {
	cases := map[error]string{
		nil:                      "",
		context.DeadlineExceeded: "timeout",
		fmt.Errorf("x: %w", os.ErrDeadlineExceeded): "timeout",
		context.Canceled:                     "canceled",
		fmt.Errorf("%w: x", ErrInvalidInput): "invalid_input",
		ErrInvalidID:                         "invalid_id",
		ErrStaleID:                           "stale_id",
		ErrNotFound:                          "not_found",
		ErrFolderNotFound:                    "folder_not_found",
		ErrUnsupported:                       "unsupported",
		ErrDraftInvalid:                      "draft_invalid",
		ErrAlreadySent:                       "already_sent",
		fmt.Errorf("%w: cap", ErrPolicy):     "policy",
		ErrAuth:                              "auth",
		ErrForbidden:                         "forbidden",
		ErrUpstream:                          "upstream",
		errors.Join(context.DeadlineExceeded, ErrUpstream): "timeout",
		errors.New("something else"):                       "internal",
	}
	for err, want := range cases {
		if got := ErrorKind(err); got != want {
			t.Errorf("ErrorKind(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestParseRole(t *testing.T) {
	for _, s := range []string{"inbox", "Drafts", " SENT ", "trash", "archive", "junk"} {
		if _, ok := ParseRole(s); !ok {
			t.Errorf("%q not parsed", s)
		}
	}
	if r, ok := ParseRole("Projects"); ok || r != RoleNone {
		t.Error("unknown role accepted")
	}
}

func TestPrepareOutgoingRejectsForeignFrom(t *testing.T) {
	raw := []byte("From: other@example.net\r\nTo: a@example.net\r\nSubject: s\r\n\r\nb\r\n")
	if _, err := prepareOutgoing(raw, "user@example.org", time.Now()); !errors.Is(err, ErrDraftInvalid) {
		t.Fatalf("err = %v", err)
	}
	raw = []byte("From: user@example.org\r\nSubject: s\r\n\r\nb\r\n")
	if _, err := prepareOutgoing(raw, "user@example.org", time.Now()); !errors.Is(err, ErrDraftInvalid) {
		t.Fatalf("no recipients: err = %v", err)
	}
}

func TestPrepareOutgoingStripsBccRefreshesDate(t *testing.T) {
	raw := []byte("Date: Mon, 1 Jan 2024 00:00:00 +0000\r\nFrom: \"Me\" <USER@example.org>\r\nTo: a@example.net\r\nCc: b@example.net\r\nBcc: c@example.net, A@example.net\r\nSubject: =?utf-8?q?Gr=C3=BC=C3=9Fe?=\r\nMessage-Id: <x@example.org>\r\n\r\nbody\r\n")
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	out, err := prepareOutgoing(raw, "user@example.org", now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(out.rcpts, ",") != "a@example.net,b@example.net,c@example.net" {
		t.Fatalf("rcpts = %v", out.rcpts)
	}
	if strings.Contains(string(out.transmit), "Bcc") || !strings.Contains(string(out.sentCopy), "Bcc: c@example.net") {
		t.Fatal("Bcc handling wrong")
	}
	for _, m := range [][]byte{out.transmit, out.sentCopy} {
		if !strings.Contains(string(m), "Date: Tue, 20 Oct 2026 12:00:00 +0000") || strings.Contains(string(m), "2024") {
			t.Fatalf("date not refreshed: %q", m)
		}
		if !strings.HasSuffix(string(m), "\r\n\r\nbody\r\n") {
			t.Fatalf("body changed: %q", m)
		}
	}
	if out.result.Subject != "Grüße" || out.result.MessageID != "x@example.org" || len(out.result.Bcc) != 2 {
		t.Fatalf("result = %+v", out.result)
	}
}
