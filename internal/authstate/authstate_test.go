package authstate

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"golang.org/x/crypto/argon2"

	"github.com/anux-linux/generic-email-mcp/internal/mail"
	"github.com/anux-linux/generic-email-mcp/internal/oauth"
	"github.com/anux-linux/generic-email-mcp/internal/testutil"
)

const (
	issuer   = "https://mail-mcp.example.run.app"
	clientID = "claude-client-0123456789"
	secret   = "client-secret-0123456789abcdefghijklmnop"
	password = "owner password for tests"
	verifier = "a-verifier-with-enough-entropy-0123456789abcdefgh"
)

func cheapHash() string {
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(password), salt, 1, 19*1024, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=1,p=1$%s$%s", 19*1024,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

type world struct {
	is    *testutil.IMAPServer
	certs *testutil.TLS
}

func newWorld(t *testing.T) *world {
	certs := testutil.NewTLS(t)
	is := testutil.StartIMAP(t, certs, nil)
	is.AddFolder(t, "Drafts", imap.MailboxAttrDrafts)
	is.AddFolder(t, "Sent", imap.MailboxAttrSent)
	is.AddFolder(t, "Trash", imap.MailboxAttrTrash)
	return &world{is: is, certs: certs}
}

// process builds a fresh mail client + authorization server, as after a
// restart; all durable state is in the IMAP server.
func (w *world) process(t *testing.T) *oauth.Server {
	t.Helper()
	mc, err := mail.New(mail.Config{
		IMAPAddr: w.is.Addr, SMTPAddr: "127.0.0.1:1", Username: w.is.Username, Password: w.is.Password,
		DraftKey: []byte(strings.Repeat("d", 32)), TLSConfig: w.certs.Client, StateFolder: mail.DefaultStateFolder,
	}, noPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := oauth.New(oauth.Config{
		Issuer: issuer, Resource: issuer + "/mcp", ClientID: clientID, ClientSecret: secret,
		SigningKey: []byte(strings.Repeat("k", 32)), CSRFKey: []byte(strings.Repeat("c", 32)), Epoch: "1",
		PasswordHash: cheapHash(), Journal: New(mc.Records()),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type noPolicy struct{}

func (noPolicy) Admit(context.Context, []string, mail.SendLedger) error { return nil }

func serve(s *oauth.Server, r *http.Request) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	s.Register(mux, func(_ string, h http.Handler) http.Handler { return h })
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func tokenReq(s *oauth.Server, form url.Values) (int, map[string]any) {
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	w := serve(s, r)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}

func login(t *testing.T, s *oauth.Server) map[string]any {
	t.Helper()
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {oauth.ClaudeCallback},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	r := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	r.SetBasicAuth("owner", password)
	w := serve(s, r)
	loc, _ := url.Parse(w.Header().Get("Location"))
	code, body := tokenReq(s, url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {oauth.ClaudeCallback}, "code_verifier": {verifier}})
	if code != 200 {
		t.Fatalf("login: %d %v", code, body)
	}
	return body
}

func refresh(s *oauth.Server, rt string) (int, map[string]any) {
	return tokenReq(s, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}})
}

func TestReuseDetectedAcrossRestartsWithIMAP(t *testing.T) {
	w := newWorld(t)
	p1 := w.process(t)
	tok := login(t, p1)
	rt1 := tok["refresh_token"].(string)
	code, tok2 := refresh(p1, rt1)
	if code != 200 {
		t.Fatal(tok2)
	}

	p2 := w.process(t) // restart: memory is empty
	if code, body := refresh(p2, rt1); code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("rotated token accepted after restart: %d %v", code, body)
	}
	if code, _ := refresh(p2, tok2["refresh_token"].(string)); code != 400 {
		t.Fatal("family not revoked after reuse")
	}
	p3 := w.process(t)
	if _, err := p3.VerifyAccessToken(t.Context(), tok2["access_token"].(string), nil); err == nil {
		t.Fatal("access token of revoked family accepted after restart")
	}

	// A fresh login keeps rotating across restarts.
	rt := login(t, p3)["refresh_token"].(string)
	for i := range 2 {
		code, body := refresh(w.process(t), rt)
		if code != 200 {
			t.Fatalf("rotation %d: %v", i, body)
		}
		rt = body["refresh_token"].(string)
	}
	recs := w.is.Messages(t, mail.DefaultStateFolder)
	if len(recs) < 6 {
		t.Fatalf("state records = %d", len(recs))
	}
	for _, m := range recs {
		if strings.Contains(string(m.Raw), secret) || strings.Contains(string(m.Raw), "eyJ") {
			t.Fatal("state record contains a secret or token")
		}
	}
}

func TestToEventsSkipsMalformed(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	evs := toEvents([]mail.Record{
		{"fam": "f", "kind": "issued", "gen": "2", "at": now},
		{"fam": "f", "kind": "issued", "gen": "x", "at": now},
		{"fam": "f", "kind": "issued", "gen": "-1", "at": now},
		{"fam": "f", "kind": "weird", "at": now},
		{"fam": "f", "kind": "revoked", "at": "yesterday"},
		{"kind": "revoked", "at": now},
		{"fam": "f", "kind": "revoked", "at": now},
	})
	if len(evs) != 2 || evs[0].Gen != 2 || evs[1].Kind != oauth.EventRevoked {
		t.Fatalf("events = %+v", evs)
	}
}
