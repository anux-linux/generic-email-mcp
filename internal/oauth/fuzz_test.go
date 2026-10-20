package oauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// FuzzVerifyAccessToken: no input other than a token this server signed is
// ever accepted, and every rejection is the same ErrInvalidToken.
func FuzzVerifyAccessToken(f *testing.F) {
	f.Add("eyJhbGciOiJub25lIiwidHlwIjoiYXQrand0In0.eyJzdWIiOiJvd25lciJ9.")
	f.Add("a.b.c")
	f.Add(strings.Repeat("A", 5000))
	f.Fuzz(func(t *testing.T, tok string) {
		env := newEnv(t, nil)
		_, err := env.s.VerifyAccessToken(t.Context(), tok, nil)
		if err == nil {
			t.Fatalf("forged token accepted: %q", tok)
		}
		if !errors.Is(err, auth.ErrInvalidToken) || err.Error() != "invalid token" {
			t.Fatalf("unexpected error %v", err)
		}
	})
}

// FuzzTokenEndpoint: arbitrary bodies never produce a 5xx or tokens.
func FuzzTokenEndpoint(f *testing.F) {
	f.Add("grant_type=authorization_code&code=x&redirect_uri=y&code_verifier=z", true)
	f.Add("grant_type=refresh_token&refresh_token=a.b.c&client_id=x&client_secret=y", false)
	f.Add("%zz&&==;", true)
	f.Fuzz(func(t *testing.T, body string, basic bool) {
		env := newEnv(t, nil)
		r := httptest.NewRequest(http.MethodPost, PathToken, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if basic {
			r.SetBasicAuth(testClientID, testSecret)
		}
		w := env.do(r)
		if w.Code >= 500 || w.Code == 200 {
			t.Fatalf("status %d for %q", w.Code, body)
		}
		var m map[string]any
		if json.Unmarshal(w.Body.Bytes(), &m) != nil || m["error"] == nil || m["access_token"] != nil {
			t.Fatalf("body %q", w.Body.String())
		}
	})
}

// FuzzAuthorize: arbitrary queries never redirect anywhere but the
// registered callback, and never issue a code without credentials.
func FuzzAuthorize(f *testing.F) {
	f.Add("response_type=code&client_id=" + testClientID + "&redirect_uri=https%3A%2F%2Fevil.example")
	f.Add(authParams().Encode())
	f.Add("redirect_uri=" + ClaudeCallback + "&redirect_uri=https://evil.example")
	f.Fuzz(func(t *testing.T, query string) {
		env := newEnv(t, nil)
		r := httptest.NewRequest(http.MethodGet, PathAuthorize, nil)
		r.URL.RawQuery = query
		w := env.do(r)
		if loc := w.Header().Get("Location"); loc != "" && !strings.HasPrefix(loc, ClaudeCallback+"?") {
			t.Fatalf("redirect to %q", loc)
		}
		if strings.Contains(w.Header().Get("Location"), "code=") {
			t.Fatal("code issued without credentials")
		}
		if w.Code >= 500 {
			t.Fatalf("status %d", w.Code)
		}
	})
}

func FuzzParseHash(f *testing.F) {
	f.Add("$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$a2V5a2V5a2V5a2V5a2V5a2V5")
	f.Add("$2b$10$abcdefghijklmnopqrstuv")
	f.Fuzz(func(t *testing.T, s string) {
		h, err := parseHash(s)
		if err != nil {
			return
		}
		if h.bcrypt == nil && (h.memory > maxArgonMemory || h.time > maxArgonTime) {
			t.Fatalf("unbounded parameters accepted: %+v", h)
		}
	})
}
