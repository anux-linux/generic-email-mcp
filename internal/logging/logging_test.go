package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type secretStruct struct{ Body string }

func TestHandlerRedactsAndScrubs(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, Options{Level: slog.LevelDebug})
	jwt := "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSJ9.c2lnbmF0dXJlLWJ5dGVz"
	log.Info("tool call for bob@example.net with Bearer abc.def-123 and password=hunter2",
		"tool", "mail_read",
		"duration_ms", 12,
		"outcome", "ok",
		"body", "SECRET BODY TEXT",
		"subject", "Quarterly numbers",
		"to", "alice@example.org",
		"error", errors.New("smtp 550 <eve@example.org> rejected"),
		"status", "token=abcdef123 sent to carol@example.org",
		"request_id", jwt,
		"addr", "x"+strings.Repeat("A", 40),
		"tool_meta", secretStruct{Body: "STRUCT BODY"},
		slog.Group("req", "path", "/mcp?code=SECRETCODE", "tool", "mail_send_draft"),
		"remaining", 3*time.Second,
	)
	out := buf.String()
	for _, leak := range []string{"bob@example.net", "abc.def-123", "hunter2", "SECRET BODY", "Quarterly", "alice@example.org",
		"eve@example.org", "abcdef123", "carol@example.org", "eyJhbGci", strings.Repeat("A", 40), "STRUCT BODY", "SECRETCODE"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q in %s", leak, out)
		}
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"severity":    "INFO",
		"message":     "tool call for [email] with Bearer [credentials] and password=[redacted]",
		"tool":        "mail_read",
		"duration_ms": float64(12),
		"outcome":     "ok",
		"body":        Redacted,
		"subject":     Redacted,
		"to":          Redacted,
		"error":       Redacted,
		"status":      "token=[redacted] sent to [email]",
		"request_id":  "[jwt]",
		"addr":        "[opaque]",
		"tool_meta":   Redacted,
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %#v, want %#v", k, m[k], v)
		}
	}
	grp, _ := m["req"].(map[string]any)
	if grp["path"] != Redacted || grp["tool"] != "mail_send_draft" {
		t.Errorf("group = %#v", grp)
	}
	if _, ok := m["time"]; !ok {
		t.Error("missing time")
	}
}

func TestWithAttrsAndGroupsAreRedacted(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, Options{}).With("subject", "Hello", "component", "mcp").WithGroup("g")
	log.Warn("x", "body", "secret", "tool", "t")
	out := buf.String()
	if strings.Contains(out, "Hello") || strings.Contains(out, "secret") {
		t.Fatalf("leak: %s", out)
	}
	if !strings.Contains(out, `"component":"mcp"`) || !strings.Contains(out, `"g":{`) || !strings.Contains(out, `"severity":"WARNING"`) {
		t.Fatalf("unexpected: %s", out)
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, Options{Level: slog.LevelWarn})
	log.Info("hidden")
	log.Error("shown")
	if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), `"severity":"ERROR"`) {
		t.Fatalf("got %s", buf.String())
	}
}

func TestScrubCapsLength(t *testing.T) {
	s := Scrub(strings.Repeat("ab ", 1000))
	if len(s) > 520 {
		t.Fatalf("len = %d", len(s))
	}
}

func TestScrubKeepsOrdinaryText(t *testing.T) {
	in := "tool call finished in 12ms (status 200, route /mcp)"
	if got := Scrub(in); got != in {
		t.Fatalf("got %q", got)
	}
}
