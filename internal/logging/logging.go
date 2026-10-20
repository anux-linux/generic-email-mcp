// Package logging provides a slog handler that cannot leak mail content or
// credentials: only allowlisted attribute keys keep their values, and every
// string that is kept (including the message) is scrubbed of addresses,
// tokens and long opaque strings. Output is JSON for Cloud Logging
// ("severity", "message", "time").
package logging

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"strings"
)

// Redacted replaces values of attributes whose key is not allowlisted.
const Redacted = "[redacted]"

// DefaultSafeKeys are attribute keys whose values are logged (after
// scrubbing). Everything else is redacted.
var DefaultSafeKeys = []string{
	"component", "tool", "outcome", "error_kind", "duration_ms", "count",
	"method", "route", "status", "bytes", "request_id", "trace", "version",
	"addr", "grant_type", "reason", "level", "remaining",
}

// Options configures NewHandler.
type Options struct {
	Level    slog.Leveler
	SafeKeys []string // replaces DefaultSafeKeys when non-nil
}

// NewHandler returns a JSON handler writing to w with redaction applied.
func NewHandler(w io.Writer, opts Options) slog.Handler {
	keys := opts.SafeKeys
	if keys == nil {
		keys = DefaultSafeKeys
	}
	safe := make(map[string]bool, len(keys))
	for _, k := range keys {
		safe[k] = true
	}
	inner := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       opts.Level,
		ReplaceAttr: cloudLoggingKeys,
	})
	return &redactor{inner: inner, safe: safe}
}

// New returns a logger using NewHandler.
func New(w io.Writer, opts Options) *slog.Logger { return slog.New(NewHandler(w, opts)) }

// cloudLoggingKeys maps slog's built-in keys to Cloud Logging's structured
// fields.
func cloudLoggingKeys(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return a
	}
	switch a.Key {
	case slog.LevelKey:
		lvl, _ := a.Value.Any().(slog.Level)
		sev := "DEFAULT"
		switch {
		case lvl >= slog.LevelError:
			sev = "ERROR"
		case lvl >= slog.LevelWarn:
			sev = "WARNING"
		case lvl >= slog.LevelInfo:
			sev = "INFO"
		default:
			sev = "DEBUG"
		}
		return slog.String("severity", sev)
	case slog.MessageKey:
		a.Key = "message"
	}
	return a
}

// redactor checks every attribute, including those inside groups, against
// the allowlist by its own key.
type redactor struct {
	inner slog.Handler
	safe  map[string]bool
}

func (r *redactor) Enabled(ctx context.Context, l slog.Level) bool { return r.inner.Enabled(ctx, l) }

func (r *redactor) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, Scrub(rec.Message), rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(r.clean(a))
		return true
	})
	return r.inner.Handle(ctx, out)
}

func (r *redactor) WithAttrs(attrs []slog.Attr) slog.Handler {
	cleaned := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		cleaned[i] = r.clean(a)
	}
	return &redactor{inner: r.inner.WithAttrs(cleaned), safe: r.safe}
}

func (r *redactor) WithGroup(name string) slog.Handler {
	return &redactor{inner: r.inner.WithGroup(name), safe: r.safe}
}

func (r *redactor) clean(a slog.Attr) slog.Attr {
	a.Value = a.Value.Resolve()
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		cleaned := make([]slog.Attr, len(attrs))
		for i, ga := range attrs {
			cleaned[i] = r.clean(ga)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(cleaned...)}
	}
	if !r.safe[a.Key] {
		return slog.String(a.Key, Redacted)
	}
	switch a.Value.Kind() {
	case slog.KindString:
		return slog.String(a.Key, Scrub(a.Value.String()))
	case slog.KindInt64, slog.KindUint64, slog.KindFloat64, slog.KindBool, slog.KindDuration, slog.KindTime:
		return a
	default:
		// Arbitrary values (errors, structs) can carry anything.
		return slog.String(a.Key, Redacted)
	}
}

var scrubbers = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+`), "$1 [credentials]"},
	{regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|client_secret|token|access_token|refresh_token|code|code_verifier|authorization)(["']?\s*[:=]\s*["']?)[^\s"'&,;]+`), "$1$2[redacted]"},
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`), "[jwt]"},
	{regexp.MustCompile(`[A-Za-z0-9!#$%&'*+/=?^_{|}~.-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+`), "[email]"},
	{regexp.MustCompile(`[A-Za-z0-9_+/=.-]{32,}`), "[opaque]"},
}

// Scrub removes credentials, addresses and long opaque strings (tokens,
// draft IDs, keys) from s and caps its length.
func Scrub(s string) string {
	for _, sc := range scrubbers {
		s = sc.re.ReplaceAllString(s, sc.repl)
	}
	const maxLen = 512
	if len(s) > maxLen {
		s = strings.ToValidUTF8(s[:maxLen], "") + "…"
	}
	return s
}
