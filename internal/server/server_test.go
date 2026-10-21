package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/argon2"

	"github.com/anux-linux/generic-email-mcp/internal/logging"
	"github.com/anux-linux/generic-email-mcp/internal/mail"
	"github.com/anux-linux/generic-email-mcp/internal/mcptools"
	"github.com/anux-linux/generic-email-mcp/internal/oauth"
)

const (
	clientID     = "claude-client-0123456789"
	clientSecret = "client-secret-0123456789abcdefghijklmnop"
	password     = "owner password for tests"
	verifier     = "a-verifier-with-enough-entropy-0123456789abcdefgh"
)

// stubMailbox serves a folder list; other operations are not needed here.
type stubMailbox struct{ mail.Mailbox }

func (stubMailbox) ListFolders(context.Context) ([]mail.Folder, error) {
	return []mail.Folder{{Name: "INBOX", Role: mail.RoleInbox, Selectable: true}}, nil
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func cheapHash() string {
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(password), salt, 1, 19*1024, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=1,p=1$%s$%s", 19*1024,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

type testServer struct {
	URL  string
	logs *syncBuf
	srv  *httptest.Server
}

// start serves the full handler on a loopback listener whose URL is the
// issuer (http is allowed for loopback).
func start(t *testing.T) *testServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	logs := &syncBuf{}
	logger := logging.New(logs, logging.Options{})
	os, err := oauth.New(oauth.Config{
		Issuer: base, Resource: base + "/mcp", ClientID: clientID, ClientSecret: clientSecret,
		SigningKey: bytes.Repeat([]byte{1}, 32), CSRFKey: bytes.Repeat([]byte{2}, 32), Epoch: "1",
		PasswordHash: cheapHash(), Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := Handler(Deps{
		BaseURL: base, OAuth: os, Logger: logger, TrustedProxyHops: 1,
		MCP: mcptools.NewServer(stubMailbox{}, mcptools.Options{Logger: logger}),
	})
	srv := &httptest.Server{Listener: ln, Config: NewHTTPServer(base, h, logger)}
	srv.Start()
	t.Cleanup(srv.Close)
	return &testServer{URL: base, logs: logs, srv: srv}
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func getJSON(t *testing.T, u string, v any) {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d", u, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

func postToken(t *testing.T, ts *testServer, form url.Values) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

type bearer struct {
	token string
	rt    http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.rt.RoundTrip(r)
}

func TestEndToEndOAuthAndMCP(t *testing.T) {
	ts := start(t)

	// 1. Unauthenticated MCP request: 401 pointing at the resource metadata.
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	wantChallenge := fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, ts.URL)
	if resp.StatusCode != 401 || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), wantChallenge) {
		t.Fatalf("challenge: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	// 2. Discovery.
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	getJSON(t, ts.URL+"/.well-known/oauth-protected-resource", &prm)
	var asm struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	getJSON(t, prm.AuthorizationServers[0]+"/.well-known/oauth-authorization-server", &asm)
	if prm.Resource != ts.URL+"/mcp" || asm.TokenEndpoint != ts.URL+"/token" {
		t.Fatalf("discovery: %+v %+v", prm, asm)
	}

	// 3. Authorization with the owner's Basic credentials.
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {oauth.ClaudeCallback},
		"state": {"xyz"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"}, "resource": {prm.Resource},
	}
	req, _ := http.NewRequest(http.MethodGet, asm.AuthorizationEndpoint+"?"+q.Encode(), nil)
	req.SetBasicAuth("owner", password)
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if resp.StatusCode != http.StatusFound || code == "" {
		t.Fatalf("authorize: %d %s", resp.StatusCode, loc)
	}

	// 4. Code exchange.
	status, tok := postToken(t, ts, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {oauth.ClaudeCallback}, "code_verifier": {verifier}, "resource": {prm.Resource}})
	if status != 200 {
		t.Fatalf("token: %d %v", status, tok)
	}

	// 5. MCP over Streamable HTTP with the access token.
	callTools := func(access string) error {
		client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil)
		cs, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
			Endpoint:   ts.URL + "/mcp",
			HTTPClient: &http.Client{Transport: bearer{access, http.DefaultTransport}},
		}, nil)
		if err != nil {
			return err
		}
		defer cs.Close()
		tools, err := cs.ListTools(t.Context(), nil)
		if err != nil {
			return err
		}
		if len(tools.Tools) != 7 {
			return fmt.Errorf("tools = %d", len(tools.Tools))
		}
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "mail_list_folders", Arguments: map[string]any{}})
		if err != nil {
			return err
		}
		if res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, `"name": "INBOX"`) {
			return fmt.Errorf("tool result: %+v", res)
		}
		return nil
	}
	if err := callTools(tok["access_token"].(string)); err != nil {
		t.Fatal(err)
	}

	// 6. Refresh rotation over HTTP.
	status, tok2 := postToken(t, ts, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}})
	if status != 200 || tok2["refresh_token"] == tok["refresh_token"] {
		t.Fatalf("refresh: %d %v", status, tok2)
	}
	if err := callTools(tok2["access_token"].(string)); err != nil {
		t.Fatal(err)
	}
	if err := callTools("forged.token.value"); err == nil {
		t.Fatal("forged token accepted")
	}

	// Logs: no codes, tokens, secrets or passwords.
	out := ts.logs.String()
	for _, leak := range []string{code, tok["access_token"].(string)[:40], tok["refresh_token"].(string)[:40], clientSecret, password, verifier, "xyz"} {
		if strings.Contains(out, leak) {
			t.Errorf("log leaked %q", leak)
		}
	}
	for _, want := range []string{`"route":"authorize"`, `"route":"token"`, `"route":"mcp"`, `"tool":"mail_list_folders"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s", want)
		}
	}
}

func TestSecurityHeadersAndHealth(t *testing.T) {
	ts := start(t)
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ok\n" {
		t.Fatalf("health: %d %q", resp.StatusCode, body)
	}
	for k, v := range map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
		"Cache-Control":           "no-store",
	} {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q", k, got)
		}
	}
	if resp.Header.Get("Cross-Origin-Opener-Policy") != "" {
		t.Error("COOP would break the OAuth popup")
	}
	resp, _ = http.Get(ts.URL + "/nope")
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("unknown path: %d", resp.StatusCode)
	}
}

func TestHSTSOnlyForHTTPS(t *testing.T) {
	h := secure(nil, true, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if !strings.HasPrefix(w.Header().Get("Strict-Transport-Security"), "max-age=63072000") {
		t.Fatal("no HSTS")
	}
}

// Cloud Run answers paths starting with /_ah/ and some paths ending in "z"
// (such as /healthz) itself; a route there would never be reached.
func TestNoCloudRunReservedPaths(t *testing.T) {
	for _, p := range []string{PathHealth, PathMCP, oauth.PathAuthorize, oauth.PathToken,
		oauth.PathResourceMetadata, oauth.PathResourceMetadata + PathMCP, oauth.PathASMetadata} {
		if strings.HasSuffix(p, "z") || strings.HasPrefix(p, "/_ah/") {
			t.Errorf("%s is reserved on Cloud Run", p)
		}
	}
}

func TestSetupMode(t *testing.T) {
	h := Handler(Deps{})
	for path, want := range map[string]int{"/health": 200, "/mcp": 503, "/authorize": 503, "/token": 503, "/.well-known/oauth-protected-resource": 503} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != want {
			t.Errorf("%s: %d, want %d", path, w.Code, want)
		}
	}
}

func TestMCPRejectsCrossSiteBrowserRequests(t *testing.T) {
	ts := start(t)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Authorization", "Bearer x")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestInvalidBearerResponseIsGeneric(t *testing.T) {
	ts := start(t)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJvd25lciJ9.")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 401 || strings.TrimSpace(string(body)) != "invalid token" || resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
}

func TestBodyLimits(t *testing.T) {
	ts := start(t)
	big := strings.NewReader("grant_type=refresh_token&refresh_token=" + strings.Repeat("a", maxOAuthBody))
	resp, err := http.Post(ts.URL+"/token", "application/x-www-form-urlencoded", big)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("token: %d", resp.StatusCode)
	}
	resp, err = http.Post(ts.URL+"/mcp", "application/json", bytes.NewReader(make([]byte, maxMCPBody+1)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("mcp: %d", resp.StatusCode)
	}
}

func TestTokenEndpointRateLimitPerIP(t *testing.T) {
	ts := start(t)
	limited := 0
	for range 30 {
		// GET is answered with 405 before client authentication, so only
		// the per-IP bucket is exercised (not the auth-failure limiter).
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/token", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.7")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited != 10 { // burst of 20 per IP
		t.Fatalf("limited = %d, want 10", limited)
	}
	// Another client IP still gets through.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/token", nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.9")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Fatal("other IP limited")
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Add("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
	r.Header.Add("X-Forwarded-For", "3.3.3.3")
	for hops, want := range map[int]string{0: "10.0.0.1", 1: "3.3.3.3", 2: "2.2.2.2", 4: "10.0.0.1"} {
		if got := clientIP(r, hops); got != want {
			t.Errorf("hops %d: %s, want %s", hops, got, want)
		}
	}
	r.Header.Set("X-Forwarded-For", "not-an-ip")
	if got := clientIP(r, 1); got != "10.0.0.1" {
		t.Errorf("garbage XFF: %s", got)
	}
}

func TestIPLimiterBounded(t *testing.T) {
	l := newIPLimiter(1, 1, 1e9, 1e9)
	l.max = 3
	for i := range 10 {
		l.allow(fmt.Sprintf("10.0.0.%d", i))
	}
	if len(l.clients) > 3 {
		t.Fatalf("map grew to %d", len(l.clients))
	}
}

func TestPanicRecovery(t *testing.T) {
	logs := &syncBuf{}
	h := secure(logging.New(logs, logging.Options{}), false, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(errors.New("boom with secret@example.org"))
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 500 || strings.Contains(logs.String(), "secret@") || !strings.Contains(logs.String(), "handler panic") {
		t.Fatalf("%d %s", w.Code, logs.String())
	}
}
