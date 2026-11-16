package logging

import (
	"regexp"
	"strings"
	"testing"
)

var (
	emailRE = regexp.MustCompile(`[A-Za-z0-9._%+-]@[A-Za-z0-9]`)
	jwtRE   = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.`)
)

// FuzzScrub: scrubbed output never contains an e-mail address or a JWT and
// is bounded in length.
func FuzzScrub(f *testing.F) {
	f.Add("mail bob@example.net with Bearer abc and eyJhbGciOi.eyJzdWIiOi.sig")
	f.Add("a@b.co,c@d.org")
	f.Add("bob@localhost and 0@0..")
	// Invalid UTF-8 between the parts of an address, in a string long
	// enough to be truncated (the 2026-11-16 weekly-run finding).
	f.Add("user@\xf5example.org " + strings.Repeat("x ", 300))
	f.Fuzz(func(t *testing.T, s string) {
		out := Scrub(s)
		if emailRE.MatchString(out) || jwtRE.MatchString(out) {
			t.Fatalf("Scrub(%q) = %q", s, out)
		}
		if len(out) > 520 {
			t.Fatalf("len %d", len(out))
		}
	})
}
