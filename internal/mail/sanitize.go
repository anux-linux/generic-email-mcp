package mail

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
)

// isInvisible reports runes that render as nothing (or nearly nothing) and
// are known carriers for hidden instructions: control and format characters
// (zero-width space/joiners, bidi overrides, BOM, soft hyphen, Unicode tag
// characters U+E0000–E007F used for "ASCII smuggling"), variation selectors
// (used for "emoji smuggling"), the combining grapheme joiner and Hangul
// fillers. Newline and tab are handled by the callers.
func isInvisible(r rune) bool {
	switch {
	case unicode.Is(unicode.Cc, r), unicode.Is(unicode.Cf, r):
		return true
	case r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF:
		return true
	case r == 0x034F, r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0:
		return true
	}
	return false
}

// cleanText normalizes body text: valid UTF-8, LF line endings, invisible
// characters removed, other Unicode whitespace mapped to plain spaces.
func cleanText(s string) string {
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == '\r':
			if i < len(s) && s[i] == '\n' {
				continue // CRLF → LF
			}
			b.WriteByte('\n')
		case r == '\n', r == '\t':
			b.WriteRune(r)
		case r == 0x2028, r == 0x2029:
			b.WriteByte('\n')
		case isInvisible(r):
		case unicode.IsSpace(r):
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// cleanHeader makes a single-line display string from a decoded header
// value and caps its length in runes.
func cleanHeader(s string, maxRunes int) string {
	s = cleanText(decodeLegacy(s))
	s = strings.Join(strings.Fields(s), " ")
	return truncateRunes(s, maxRunes)
}

// decodeLegacy interprets invalid UTF-8 (raw 8-bit headers or bodies
// without a declared charset) as Windows-1252, the de-facto default.
func decodeLegacy(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	out, err := charmap.Windows1252.NewDecoder().String(s)
	if err != nil {
		return strings.ToValidUTF8(s, "�")
	}
	return out
}

// truncateRunes cuts s to at most n runes.
func truncateRunes(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	i := 0
	for range n {
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
	}
	return s[:i]
}

// truncateBytes cuts s to at most n bytes on a rune boundary.
func truncateBytes(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n], true
}

// tidyLines trims trailing whitespace on every line, collapses runs of more
// than one blank line and trims the result.
func tidyLines(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	blank := 0
	for line := range strings.SplitSeq(s, "\n") {
		line = strings.TrimRight(line, " \t")
		if line == "" {
			blank++
			if blank > 1 {
				continue
			}
		} else {
			blank = 0
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return strings.TrimSpace(b.String())
}
