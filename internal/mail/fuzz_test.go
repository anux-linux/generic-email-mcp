package mail

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// Fuzz targets for every parser that sees untrusted input. `go test` runs
// the seeds; scripts/check.sh can fuzz each for FUZZTIME.

func FuzzParseID(f *testing.F) {
	f.Add(msgRef{"INBOX", 7, 9}.String())
	f.Add(formatDraftID(msgRef{"Drafts", 1, 2}, make([]byte, 32)))
	f.Add("m1..0.0")
	f.Fuzz(func(t *testing.T, id string) {
		ref, mac, err := parseID(id)
		if err != nil {
			return
		}
		// Accepted IDs are canonical: re-encoding yields the same string.
		got := ref.String()
		if mac != nil {
			got = formatDraftID(ref, mac)
		}
		if got != id {
			t.Fatalf("non-canonical id accepted: %q -> %q", id, got)
		}
		if !validFolderName(ref.Folder) || ref.UID == 0 || ref.UIDValidity == 0 {
			t.Fatalf("invalid ref accepted: %+v", ref)
		}
	})
}

// FuzzGuard: the guard never panics, forwards only a prefix of its input,
// and never lets a line through that starts a forbidden command at a
// command boundary.
func FuzzGuard(f *testing.F) {
	f.Add([]byte("a1 NOOP\r\na2 EXPUNGE\r\n"))
	f.Add([]byte("a1 APPEND X {5}\r\nhello\r\na2 UID EXPUNGE 1\r\n"))
	f.Add([]byte("a1 LOGIN {3+}\r\nabc {1}\r\nx\r\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		rc := &recConn{}
		g := newGuardConn(rc)
		// Write in two chunks to exercise buffering.
		cut := len(in) / 3
		_, err1 := g.Write(in[:cut])
		var err2 error
		if err1 == nil {
			_, err2 = g.Write(in[cut:])
		}
		out := rc.buf.Bytes()
		if !bytes.HasPrefix(in, out) {
			t.Fatal("guard altered the stream")
		}
		if err := errors.Join(err1, err2); err != nil && !errors.Is(err, ErrForbidden) {
			t.Fatalf("unexpected error %v", err)
		}
		// Re-scan what reached the wire with an independent checker.
		check := newGuardConn(&recConn{})
		if _, err := check.Write(out); errors.Is(err, ErrForbidden) {
			t.Fatalf("forbidden command reached the wire: %q", out)
		}
	})
}

// FuzzHTMLToText: output is clean text, bounded, and content inside a
// display:none element never leaks, whatever HTML follows it.
func FuzzHTMLToText(f *testing.F) {
	f.Add("<p>hello</p>")
	f.Add(`</div><div style="display:block">x</div>`)
	f.Add("<style>.a{display:block}</style><p class=a>t</p>")
	f.Add("<table><tr><td><a href='https://x'>l</a></td></tr></table><pre> a </pre>")
	f.Fuzz(func(t *testing.T, tail string) {
		src := `<div style="display:none">SECRETMARKER</div>` + tail
		out, _, _ := htmlToText(src, 4096)
		if strings.Contains(out, "SECRETMARKER") {
			t.Fatalf("hidden content leaked: %q", out)
		}
		assertCleanText(t, out)
		if len(out) > 4096+1024 {
			t.Fatalf("output %d bytes", len(out))
		}
	})
}

func assertCleanText(t *testing.T, s string) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Fatal("invalid UTF-8")
	}
	for _, r := range s {
		if r != '\n' && r != '\t' && isInvisible(r) {
			t.Fatalf("invisible rune %U survived", r)
		}
		if r == '\r' {
			t.Fatal("CR survived")
		}
	}
}

func FuzzCleanText(f *testing.F) {
	f.Add("a\u200bb\r\nc\U000E0041")
	f.Add("\xff\xfe")
	f.Fuzz(func(t *testing.T, s string) {
		out := cleanText(s)
		assertCleanText(t, out)
		if cleanText(out) != out {
			t.Fatal("cleanText not idempotent")
		}
		h := cleanHeader(s, 50)
		assertCleanText(t, h)
		if strings.ContainsAny(h, "\n\t") || utf8.RuneCountInString(h) > 50 {
			t.Fatalf("header not single-line/bounded: %q", h)
		}
		for _, r := range h {
			if unicode.IsSpace(r) && r != ' ' {
				t.Fatalf("non-space whitespace %U", r)
			}
		}
	})
}

func FuzzDecodeTextPart(f *testing.F) {
	f.Add([]byte("aGVsbG8="), "base64", "utf-8", false)
	f.Add([]byte("Gr=FC=DF"), "quoted-printable", "iso-8859-1", true)
	f.Add([]byte{0xff, 0x00, 0x80}, "8bit", "", false)
	f.Fuzz(func(t *testing.T, raw []byte, enc, cs string, html bool) {
		out := decodeTextPart(textPart{encoding: enc, charset: cs, html: html}, raw)
		if !utf8.ValidString(out) {
			t.Fatal("decoded text is not valid UTF-8")
		}
	})
}

// FuzzPrepareOutgoing: whatever a stored draft contains, the transmitted
// message never carries a Bcc header and recipients are bounded.
func FuzzPrepareOutgoing(f *testing.F) {
	f.Add([]byte("From: me@example.org\r\nTo: a@example.net\r\nBcc: b@example.net\r\nSubject: x\r\n\r\nbody\r\n"))
	f.Add([]byte("From: me@example.org\r\nbcc: x@y.z\r\nBCC: q@r.s\r\nTo: a@b.c\r\n\r\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		out, err := prepareOutgoing(raw, "me@example.org", time.Unix(0, 0))
		if err != nil {
			return
		}
		hdr, _, _ := bytes.Cut(out.transmit, []byte("\r\n\r\n"))
		for line := range bytes.SplitSeq(hdr, []byte("\r\n")) {
			if k, _, ok := bytes.Cut(line, []byte(":")); ok && strings.EqualFold(strings.TrimSpace(string(k)), "bcc") {
				t.Fatalf("Bcc transmitted: %q", out.transmit)
			}
		}
		if len(out.rcpts) == 0 || len(out.rcpts) > maxRecipients {
			t.Fatalf("recipients = %d", len(out.rcpts))
		}
	})
}

func FuzzParseHiddenCSS(f *testing.F) {
	f.Add(".a{display:none} @media x{.b{display:none}} #c{visibility:hidden}")
	f.Add("}}}{{{@;;")
	f.Fuzz(func(t *testing.T, css string) {
		hr := hiddenRules{classes: map[string]bool{}, ids: map[string]bool{}}
		parseHiddenCSS(css, &hr)
	})
}
