package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const (
	testIssuer   = "https://mail-mcp.example.run.app"
	testClientID = "claude-client-0123456789"
	testSecret   = "s3cr3t:with%special&chars-0123456789abcdef"
	testPassword = "correct horse battery staple"
	testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-plus-extra-entropy"
)

var (
	hashOnce sync.Once
	testHash string
)

// passwordHashForTests uses the cheapest parameters parseHash accepts, so
// the many logins in these tests stay fast; production uses HashPassword.
func passwordHashForTests(t *testing.T) string {
	hashOnce.Do(func() {
		salt := []byte("0123456789abcdef")
		key := argon2.IDKey([]byte(testPassword), salt, 1, 19*1024, 1, 32)
		testHash = fmt.Sprintf("$argon2id$v=19$m=%d,t=1,p=1$%s$%s", 19*1024,
			base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	})
	return testHash
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

type env struct {
	s     *Server
	mux   *http.ServeMux
	clock *clock
}

func newEnv(t *testing.T, mod func(*Config)) *env {
	t.Helper()
	ck := &clock{now: time.Now().Truncate(time.Second)}
	cfg := Config{
		Issuer: testIssuer, Resource: testIssuer + "/mcp",
		ClientID: testClientID, ClientSecret: testSecret,
		SigningKey: []byte(strings.Repeat("k", 32)), CSRFKey: []byte(strings.Repeat("c", 32)),
		Epoch: "1", PasswordHash: passwordHashForTests(t), Now: ck.Now,
	}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.Register(mux, func(_ string, h http.Handler) http.Handler { return h })
	return &env{s: s, mux: mux, clock: ck}
}

func challengeFor(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func authParams() url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {ClaudeCallback},
		"state":                 {"st-123"},
		"code_challenge":        {challengeFor(testVerifier)},
		"code_challenge_method": {"S256"},
		"scope":                 {"mail"},
		"resource":              {testIssuer + "/mcp"},
	}
}

func (e *env) do(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	return w
}

func (e *env) authorize(t *testing.T, q url.Values, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, PathAuthorize+"?"+q.Encode(), nil)
	if user != "" || pass != "" {
		r.SetBasicAuth(user, pass)
	}
	return e.do(r)
}

// code runs a successful authorization and returns the code.
func (e *env) code(t *testing.T) string {
	t.Helper()
	w := e.authorize(t, authParams(), DefaultUsername, testPassword)
	if w.Code != http.StatusFound {
		t.Fatalf("authorize: %d %s", w.Code, w.Body)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("state") != "st-123" || loc.Query().Get("iss") != testIssuer {
		t.Fatalf("redirect = %s", loc)
	}
	return loc.Query().Get("code")
}

func (e *env) token(t *testing.T, form url.Values, basic bool) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, PathToken, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		r.SetBasicAuth(url.QueryEscape(testClientID), url.QueryEscape(testSecret))
	}
	w := e.do(r)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w, body
}

func codeForm(code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {ClaudeCallback}, "code_verifier": {testVerifier}}
}

func (e *env) tokens(t *testing.T) (access, refresh string) {
	t.Helper()
	w, body := e.token(t, codeForm(e.code(t)), true)
	if w.Code != http.StatusOK {
		t.Fatalf("token: %d %v", w.Code, body)
	}
	return body["access_token"].(string), body["refresh_token"].(string)
}

func (e *env) verify(tok string) error {
	_, err := e.s.VerifyAccessToken(context.Background(), tok, nil)
	return err
}

func wantTokenError(t *testing.T, w *httptest.ResponseRecorder, body map[string]any, status int, code string) {
	t.Helper()
	if w.Code != status || body["error"] != code {
		t.Fatalf("got %d %v, want %d %s", w.Code, body, status, code)
	}
}

func TestMetadata(t *testing.T) {
	e := newEnv(t, nil)
	for _, p := range []string{PathResourceMetadata, PathResourceMetadata + "/mcp"} {
		w := e.do(httptest.NewRequest(http.MethodGet, p, nil))
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		if w.Code != 200 || m["resource"] != testIssuer+"/mcp" || m["authorization_servers"].([]any)[0] != testIssuer ||
			w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("%s: %d %v", p, w.Code, m)
		}
	}
	for _, p := range []string{PathASMetadata, PathASMetadata + "/mcp"} {
		w := e.do(httptest.NewRequest(http.MethodGet, p, nil))
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		if w.Code != 200 || m["issuer"] != testIssuer || m["token_endpoint"] != testIssuer+"/token" ||
			m["authorization_endpoint"] != testIssuer+"/authorize" {
			t.Fatalf("%s: %d %v", p, w.Code, m)
		}
		for _, absent := range []string{"registration_endpoint", "jwks_uri"} {
			if _, ok := m[absent]; ok {
				t.Errorf("%s advertised", absent)
			}
		}
		if s := w.Body.String(); !strings.Contains(s, `"code_challenge_methods_supported":["S256"]`) ||
			!strings.Contains(s, `"grant_types_supported":["authorization_code","refresh_token"]`) ||
			!strings.Contains(s, `"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"]`) {
			t.Fatalf("metadata = %s", s)
		}
	}
}

func TestAuthorizeNeverRedirectsToUnregisteredURI(t *testing.T) {
	e := newEnv(t, nil)
	cases := map[string]func(url.Values){
		"unknown client":   func(q url.Values) { q.Set("client_id", "someone-else-123") },
		"missing client":   func(q url.Values) { q.Del("client_id") },
		"other host":       func(q url.Values) { q.Set("redirect_uri", "https://evil.example/api/mcp/auth_callback") },
		"trailing slash":   func(q url.Values) { q.Set("redirect_uri", ClaudeCallback+"/") },
		"extra query":      func(q url.Values) { q.Set("redirect_uri", ClaudeCallback+"?x=1") },
		"http downgrade":   func(q url.Values) { q.Set("redirect_uri", "http://claude.ai/api/mcp/auth_callback") },
		"case change":      func(q url.Values) { q.Set("redirect_uri", "https://Claude.ai/api/mcp/auth_callback") },
		"missing redirect": func(q url.Values) { q.Del("redirect_uri") },
		"repeated redirect": func(q url.Values) {
			q["redirect_uri"] = []string{ClaudeCallback, "https://evil.example/cb"}
		},
	}
	for name, mod := range cases {
		q := authParams()
		mod(q)
		w := e.authorize(t, q, DefaultUsername, testPassword)
		if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
			t.Errorf("%s: %d location=%q", name, w.Code, w.Header().Get("Location"))
		}
	}
}

func TestAuthorizeErrorRedirects(t *testing.T) {
	e := newEnv(t, nil)
	cases := map[string]struct {
		mod  func(url.Values)
		code string
	}{
		"implicit flow":      {func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type"},
		"no pkce":            {func(q url.Values) { q.Del("code_challenge"); q.Del("code_challenge_method") }, "invalid_request"},
		"plain pkce":         {func(q url.Values) { q.Set("code_challenge_method", "plain") }, "invalid_request"},
		"short challenge":    {func(q url.Values) { q.Set("code_challenge", "abc") }, "invalid_request"},
		"wrong resource":     {func(q url.Values) { q.Set("resource", "https://other.example/mcp") }, "invalid_target"},
		"repeated state":     {func(q url.Values) { q["state"] = []string{"a", "b"} }, "invalid_request"},
		"repeated challenge": {func(q url.Values) { q["code_challenge"] = []string{challengeFor(testVerifier), "x"} }, "invalid_request"},
	}
	for name, tc := range cases {
		q := authParams()
		tc.mod(q)
		w := e.authorize(t, q, DefaultUsername, testPassword)
		loc, _ := url.Parse(w.Header().Get("Location"))
		if w.Code != http.StatusFound || !strings.HasPrefix(loc.String(), ClaudeCallback+"?") || loc.Query().Get("error") != tc.code ||
			loc.Query().Get("code") != "" || loc.Query().Get("iss") != testIssuer {
			t.Errorf("%s: %d %s", name, w.Code, loc)
		}
	}
	// Resource with a trailing slash is the same resource (RFC 3986 §6.2.3).
	q := authParams()
	q.Set("resource", testIssuer+"/mcp/")
	if w := e.authorize(t, q, DefaultUsername, testPassword); w.Code != http.StatusFound || strings.Contains(w.Header().Get("Location"), "error=") {
		t.Fatalf("trailing-slash resource rejected: %s", w.Header().Get("Location"))
	}
}

func TestBasicLogin(t *testing.T) {
	e := newEnv(t, nil)
	w := e.authorize(t, authParams(), "", "")
	if w.Code != http.StatusUnauthorized || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), `Basic realm="generic-email-mcp"`) {
		t.Fatalf("challenge: %d %v", w.Code, w.Header())
	}
	if w := e.authorize(t, authParams(), DefaultUsername, "wrong password"); w.Code != http.StatusUnauthorized || w.Header().Get("Location") != "" {
		t.Fatalf("wrong password: %d", w.Code)
	}
	if w := e.authorize(t, authParams(), "intruder", testPassword); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong user: %d", w.Code)
	}
	if code := e.code(t); len(code) < 32 {
		t.Fatalf("weak code %q", code)
	}
	if w := e.authorize(t, authParams(), DefaultUsername, testPassword); w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authorize response cacheable")
	}
}

func TestLoginFailuresAreRateLimited(t *testing.T) {
	e := newEnv(t, nil)
	for range 5 { // exhausts the burst of 5
		e.authorize(t, authParams(), DefaultUsername, "nope")
	}
	w := e.authorize(t, authParams(), DefaultUsername, testPassword)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("got %d, want 429 even for the right password", w.Code)
	}
}

func TestCodeExchangeAndAccessToken(t *testing.T) {
	e := newEnv(t, nil)
	w, body := e.token(t, codeForm(e.code(t)), true)
	if w.Code != 200 || body["token_type"] != "Bearer" || body["expires_in"] != float64(3600) || body["scope"] != "mail" ||
		w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("token: %d %v %v", w.Code, body, w.Header())
	}
	info, err := e.s.VerifyAccessToken(t.Context(), body["access_token"].(string), nil)
	if err != nil || info.UserID != "owner" || info.Scopes[0] != "mail" || info.Expiration.Sub(e.clock.Now()) != time.Hour {
		t.Fatalf("verify: %v %+v", err, info)
	}
	// client_secret_post works too.
	f := codeForm(e.code(t))
	f.Set("client_id", testClientID)
	f.Set("client_secret", testSecret)
	if w, body := e.token(t, f, false); w.Code != 200 {
		t.Fatalf("client_secret_post: %d %v", w.Code, body)
	}
}

func TestClientAuthentication(t *testing.T) {
	e := newEnv(t, nil)
	post := func(id, secret string) url.Values {
		f := codeForm("x")
		f.Set("client_id", id)
		f.Set("client_secret", secret)
		return f
	}
	w, body := e.token(t, post(testClientID, testSecret+"x"), false)
	wantTokenError(t, w, body, 401, "invalid_client")
	w, body = e.token(t, post("other-client-123", testSecret), false)
	wantTokenError(t, w, body, 401, "invalid_client")
	w, body = e.token(t, codeForm("x"), false) // no client authentication at all
	wantTokenError(t, w, body, 401, "invalid_client")

	r := httptest.NewRequest(http.MethodPost, PathToken, strings.NewReader(codeForm("x").Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(url.QueryEscape(testClientID), "wrong")
	w = e.do(r)
	if w.Code != 401 || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("basic failure: %d %v", w.Code, w.Header())
	}
	// Both methods at once is a protocol error.
	r = httptest.NewRequest(http.MethodPost, PathToken, strings.NewReader(post(testClientID, testSecret).Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(url.QueryEscape(testClientID), url.QueryEscape(testSecret))
	if w = e.do(r); w.Code != 400 {
		t.Fatalf("two methods: %d", w.Code)
	}
	// Five failures exhaust the burst: even correct credentials are refused.
	e.token(t, post(testClientID, "x"), false)
	w, body = e.token(t, post(testClientID, testSecret), false)
	wantTokenError(t, w, body, 429, "invalid_client")
}

func TestTokenEndpointRequestValidation(t *testing.T) {
	e := newEnv(t, nil)
	r := httptest.NewRequest(http.MethodGet, PathToken, nil)
	if w := e.do(r); w.Code != 405 {
		t.Fatalf("GET: %d", w.Code)
	}
	r = httptest.NewRequest(http.MethodPost, PathToken, strings.NewReader(`{"grant_type":"authorization_code"}`))
	r.Header.Set("Content-Type", "application/json")
	if w := e.do(r); w.Code != 400 {
		t.Fatalf("json body: %d", w.Code)
	}
	f := codeForm("x")
	f["code"] = []string{"a", "b"}
	w, body := e.token(t, f, true)
	wantTokenError(t, w, body, 400, "invalid_request")
	w, body = e.token(t, url.Values{"grant_type": {"password"}}, true)
	wantTokenError(t, w, body, 400, "unsupported_grant_type")
	w, body = e.token(t, url.Values{"grant_type": {"client_credentials"}}, true)
	wantTokenError(t, w, body, 400, "unsupported_grant_type")
	f = codeForm("x")
	f.Set("code_verifier", "short")
	w, body = e.token(t, f, true)
	wantTokenError(t, w, body, 400, "invalid_request")
	f = codeForm("x")
	f.Set("resource", "https://other.example/mcp")
	w, body = e.token(t, f, true)
	wantTokenError(t, w, body, 400, "invalid_target")
}

func TestBadPKCEConsumesCode(t *testing.T) {
	e := newEnv(t, nil)
	code := e.code(t)
	f := codeForm(code)
	f.Set("code_verifier", strings.Repeat("a", 43))
	w, body := e.token(t, f, true)
	wantTokenError(t, w, body, 400, "invalid_grant")
	w, body = e.token(t, codeForm(code), true)
	wantTokenError(t, w, body, 400, "invalid_grant")
}

func TestRedirectURIMustMatchAtTokenEndpoint(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.RedirectURIs = []string{ClaudeCallback, "http://localhost:6274/oauth/callback"} })
	f := codeForm(e.code(t))
	f.Set("redirect_uri", "http://localhost:6274/oauth/callback")
	w, body := e.token(t, f, true)
	wantTokenError(t, w, body, 400, "invalid_grant")
}

func TestExpiredCode(t *testing.T) {
	e := newEnv(t, nil)
	code := e.code(t)
	e.clock.add(DefaultCodeTTL + time.Second)
	w, body := e.token(t, codeForm(code), true)
	wantTokenError(t, w, body, 400, "invalid_grant")
}

func TestReplayedCodeRevokesIssuedTokens(t *testing.T) {
	e := newEnv(t, nil)
	code := e.code(t)
	w, body := e.token(t, codeForm(code), true)
	if w.Code != 200 {
		t.Fatal(body)
	}
	access, refresh := body["access_token"].(string), body["refresh_token"].(string)
	if err := e.verify(access); err != nil {
		t.Fatal(err)
	}
	w, body = e.token(t, codeForm(code), true)
	wantTokenError(t, w, body, 400, "invalid_grant")
	if err := e.verify(access); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("access token survived code replay: %v", err)
	}
	w, body = e.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}, true)
	wantTokenError(t, w, body, 400, "invalid_grant")
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	e := newEnv(t, nil)
	_, rt1 := e.tokens(t)
	refresh := func(rt string) (*httptest.ResponseRecorder, map[string]any) {
		return e.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, true)
	}
	w, body := refresh(rt1)
	if w.Code != 200 {
		t.Fatal(body)
	}
	at2, rt2 := body["access_token"].(string), body["refresh_token"].(string)
	if rt2 == rt1 {
		t.Fatal("refresh token not rotated")
	}
	if err := e.verify(at2); err != nil {
		t.Fatal(err)
	}
	// Reusing the old token is theft: the whole family dies.
	w, body = refresh(rt1)
	wantTokenError(t, w, body, 400, "invalid_grant")
	w, body = refresh(rt2)
	wantTokenError(t, w, body, 400, "invalid_grant")
	if err := e.verify(at2); err == nil {
		t.Fatal("access token of revoked family still valid")
	}
	// Other families are unaffected.
	at3, rt3 := e.tokens(t)
	if err := e.verify(at3); err != nil {
		t.Fatal(err)
	}
	f := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt3}, "scope": {"mail admin"}}
	w, body = e.token(t, f, true)
	wantTokenError(t, w, body, 400, "invalid_scope")
	// An access token is not a refresh token.
	w, body = refresh(at3)
	wantTokenError(t, w, body, 400, "invalid_grant")
}

func TestRefreshTokenExpiry(t *testing.T) {
	e := newEnv(t, nil)
	_, rt := e.tokens(t)
	e.clock.add(DefaultRefreshTTL + time.Minute)
	w, body := e.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, true)
	wantTokenError(t, w, body, 400, "invalid_grant")
}

func TestForgedAndMisboundAccessTokens(t *testing.T) {
	e := newEnv(t, nil)
	at, rt := e.tokens(t)
	key := []byte(strings.Repeat("k", 32))
	mint := func(method jwt.SigningMethod, k any, typ string, mod func(*tokenClaims)) string {
		c := tokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer: testIssuer, Subject: subject, Audience: jwt.ClaimStrings{testIssuer + "/mcp"},
				IssuedAt: jwt.NewNumericDate(e.clock.Now()), ExpiresAt: jwt.NewNumericDate(e.clock.Now().Add(time.Hour)), ID: "jti-1",
			},
			ClientID: testClientID, Scope: Scope, Epoch: "1", Family: "fam-1",
		}
		if mod != nil {
			mod(&c)
		}
		tok := jwt.NewWithClaims(method, c)
		tok.Header["typ"] = typ
		s, err := tok.SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if err := e.verify(mint(jwt.SigningMethodHS256, key, typAccess, nil)); err != nil {
		t.Fatalf("control token rejected: %v", err)
	}
	cases := map[string]string{
		"wrong audience":   mint(jwt.SigningMethodHS256, key, typAccess, func(c *tokenClaims) { c.Audience = jwt.ClaimStrings{"https://other.example/mcp"} }),
		"issuer as aud":    mint(jwt.SigningMethodHS256, key, typAccess, func(c *tokenClaims) { c.Audience = jwt.ClaimStrings{testIssuer} }),
		"wrong issuer":     mint(jwt.SigningMethodHS256, key, typAccess, func(c *tokenClaims) { c.Issuer = "https://evil.example" }),
		"wrong key":        mint(jwt.SigningMethodHS256, []byte(strings.Repeat("x", 32)), typAccess, nil),
		"HS512":            mint(jwt.SigningMethodHS512, key, typAccess, nil),
		"alg none":         mint(jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, typAccess, nil),
		"refresh typ":      mint(jwt.SigningMethodHS256, key, typRefresh, nil),
		"no typ":           mint(jwt.SigningMethodHS256, key, "JWT", nil),
		"wrong epoch":      mint(jwt.SigningMethodHS256, key, typAccess, func(c *tokenClaims) { c.Epoch = "0" }),
		"other client":     mint(jwt.SigningMethodHS256, key, typAccess, func(c *tokenClaims) { c.ClientID = "x" }),
		"no scope":         mint(jwt.SigningMethodHS256, key, typAccess, func(c *tokenClaims) { c.Scope = "" }),
		"no expiry":        mint(jwt.SigningMethodHS256, key, typAccess, func(c *tokenClaims) { c.ExpiresAt = nil }),
		"expired":          mint(jwt.SigningMethodHS256, key, typAccess, func(c *tokenClaims) { c.ExpiresAt = jwt.NewNumericDate(e.clock.Now().Add(-time.Minute)) }),
		"issued in future": mint(jwt.SigningMethodHS256, key, typAccess, func(c *tokenClaims) { c.IssuedAt = jwt.NewNumericDate(e.clock.Now().Add(time.Hour)) }),
		"refresh token":    rt,
		"garbage":          "not.a.jwt",
		"empty":            "",
		"truncated":        at[:len(at)-3],
	}
	for name, tok := range cases {
		if err := e.verify(tok); !errors.Is(err, auth.ErrInvalidToken) || err.Error() != "invalid token" {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// Access tokens expire after an hour (plus 30 s leeway).
	e.clock.add(time.Hour + time.Minute)
	if err := e.verify(at); err == nil {
		t.Fatal("expired access token accepted")
	}
}

func TestEpochChangeRevokesAllTokens(t *testing.T) {
	e := newEnv(t, nil)
	at, rt := e.tokens(t)
	e2 := newEnv(t, func(c *Config) { c.Epoch = "2"; c.Now = e.clock.Now })
	if err := e2.verify(at); err == nil {
		t.Fatal("access token survived epoch change")
	}
	w, body := e2.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, true)
	wantTokenError(t, w, body, 400, "invalid_grant")
}

var hiddenRE = regexp.MustCompile(`name="(request|csrf)" value="([^"]+)"`)

func TestFormLogin(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.LoginMode = LoginForm })
	get := func() (request, csrf string, cookie *http.Cookie) {
		w := e.authorize(t, authParams(), "", "")
		if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action 'self' https://claude.ai") ||
			!strings.Contains(w.Body.String(), `type="password"`) {
			t.Fatalf("form: %d %v", w.Code, w.Header())
		}
		for _, m := range hiddenRE.FindAllStringSubmatch(w.Body.String(), -1) {
			if m[1] == "request" {
				request = m[2]
			} else {
				csrf = m[2]
			}
		}
		for _, c := range w.Result().Cookies() {
			if c.Name == csrfCookie {
				if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
					t.Fatalf("cookie flags: %+v", c)
				}
				cookie = c
			}
		}
		return request, csrf, cookie
	}
	post := func(request, csrf, password string, cookie *http.Cookie, site string) *httptest.ResponseRecorder {
		f := url.Values{"request": {request}, "csrf": {csrf}, "password": {password}}
		r := httptest.NewRequest(http.MethodPost, PathAuthorize, strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", site)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		return e.do(r)
	}

	req, csrf, cookie := get()
	if w := post(req, csrf, testPassword, cookie, "cross-site"); w.Code != http.StatusForbidden {
		t.Errorf("cross-site POST: %d", w.Code)
	}
	if w := post(req, csrf, testPassword, nil, "same-origin"); w.Code != http.StatusForbidden {
		t.Errorf("no cookie: %d", w.Code)
	}
	if w := post(req, "forged", testPassword, cookie, "same-origin"); w.Code != http.StatusForbidden {
		t.Errorf("csrf mismatch: %d", w.Code)
	}
	if w := post(req[:len(req)-2]+"xx", csrf, testPassword, cookie, "same-origin"); w.Code != http.StatusForbidden {
		t.Errorf("tampered request: %d", w.Code)
	}
	if w := post(req, csrf, "wrong", cookie, "same-origin"); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Wrong password") {
		t.Errorf("wrong password: %d", w.Code)
	}
	w := post(req, csrf, testPassword, cookie, "same-origin")
	loc, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusSeeOther || loc.Query().Get("code") == "" || loc.Query().Get("state") != "st-123" {
		t.Fatalf("login: %d %s", w.Code, loc)
	}
	if w, body := e.token(t, codeForm(loc.Query().Get("code")), true); w.Code != 200 {
		t.Fatalf("token after form login: %v", body)
	}

	req, csrf, cookie = get()
	e.clock.add(formTTL + time.Second)
	if w := post(req, csrf, testPassword, cookie, "same-origin"); w.Code != http.StatusForbidden {
		t.Errorf("expired form: %d", w.Code)
	}
	// Basic credentials are not accepted in form mode, and POST is not
	// accepted in basic mode.
	if w := e.authorize(t, authParams(), DefaultUsername, testPassword); w.Code != 200 || w.Header().Get("Location") != "" {
		t.Errorf("basic in form mode: %d", w.Code)
	}
	eb := newEnv(t, nil)
	r := httptest.NewRequest(http.MethodPost, PathAuthorize, strings.NewReader("x=1"))
	if w := eb.do(r); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST in basic mode: %d", w.Code)
	}
}

func TestPasswordHashes(t *testing.T) {
	h, err := HashPassword(testPassword)
	if err != nil || !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Fatalf("hash = %q %v", h, err)
	}
	ph, err := parseHash(h)
	if err != nil || !ph.verify(testPassword) || ph.verify(testPassword+"x") {
		t.Fatalf("argon2id verify: %v", err)
	}
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	bc, _ := bcrypt.GenerateFromPassword([]byte(testPassword), 10)
	if ph, err := parseHash(string(bc)); err != nil || !ph.verify(testPassword) || ph.verify("x") {
		t.Fatalf("bcrypt: %v", err)
	}
	weak, _ := bcrypt.GenerateFromPassword([]byte(testPassword), 4)
	for name, bad := range map[string]string{
		"bcrypt cost 4":  string(weak),
		"plaintext":      testPassword,
		"argon2i":        strings.Replace(h, "argon2id", "argon2i", 1),
		"huge memory":    strings.Replace(h, "m=65536", "m=1048576", 1),
		"tiny memory":    strings.Replace(h, "m=65536", "m=8", 1),
		"bad version":    strings.Replace(h, "v=19", "v=16", 1),
		"truncated salt": "$argon2id$v=19$m=65536,t=3,p=1$AAAA$" + strings.Split(h, "$")[5],
	} {
		if _, err := parseHash(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	base := func() Config {
		return Config{
			Issuer: testIssuer, Resource: testIssuer + "/mcp", ClientID: testClientID, ClientSecret: testSecret,
			SigningKey: make([]byte, 32), CSRFKey: make([]byte, 32), Epoch: "1", PasswordHash: passwordHashForTests(t),
		}
	}
	if _, err := New(base()); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Config){
		"http issuer":        func(c *Config) { c.Issuer = "http://mail.example"; c.Resource = c.Issuer + "/mcp" },
		"issuer path":        func(c *Config) { c.Issuer = testIssuer + "/x"; c.Resource = c.Issuer + "/mcp" },
		"trailing slash":     func(c *Config) { c.Issuer = testIssuer + "/"; c.Resource = testIssuer + "/mcp" },
		"resource elsewhere": func(c *Config) { c.Resource = "https://other.example/mcp" },
		"short secret":       func(c *Config) { c.ClientSecret = "short" },
		"bad client id":      func(c *Config) { c.ClientID = "has space" },
		"http redirect":      func(c *Config) { c.RedirectURIs = []string{"http://evil.example/cb"} },
		"fragment redirect":  func(c *Config) { c.RedirectURIs = []string{ClaudeCallback + "#x"} },
		"short key":          func(c *Config) { c.SigningKey = make([]byte, 16) },
		"no hash":            func(c *Config) { c.PasswordHash = "" },
		"bad mode":           func(c *Config) { c.LoginMode = "magic" },
		"no epoch":           func(c *Config) { c.Epoch = "" },
	} {
		c := base()
		mod(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s accepted", name)
		} else if strings.Contains(err.Error(), testSecret) {
			t.Errorf("%s: error leaks the secret", name)
		}
	}
	// Loopback http is allowed for local testing (e.g. MCP Inspector).
	c := base()
	c.Issuer, c.Resource = "http://127.0.0.1:8080", "http://127.0.0.1:8080/mcp"
	c.RedirectURIs = []string{"http://localhost:6274/oauth/callback"}
	if _, err := New(c); err != nil {
		t.Fatalf("loopback rejected: %v", err)
	}
}
