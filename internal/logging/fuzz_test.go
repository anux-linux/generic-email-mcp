package logging

import (
	"regexp"
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
