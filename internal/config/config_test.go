package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/anux-linux/generic-email-mcp/internal/mail"
)

// A cheap but parseable argon2id hash (password irrelevant here).
const testHash = "$argon2id$v=19$m=19456,t=1,p=1$MDEyMzQ1Njc4OWFiY2RlZg$Yo8w0JmYbYbqZ1pYcjWQ0z2PQK6oFzA9eM3Y2yVdD3Q"

var (
	secretKey    = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("K"), 32))
	clientSecret = "client-secret-0123456789abcdefghijklmnop"
	mailPassword = "mail-password-value"
)

func fullEnv() map[string]string {
	return map[string]string{
		EnvBaseURL:          "https://email-mcp-abc.a.run.app",
		EnvClientID:         "claude-client-0123456789",
		EnvClientSecret:     clientSecret,
		EnvSigningKey:       secretKey,
		EnvPasswordHash:     testHash,
		mail.EnvUsername:    "me@example.org",
		mail.EnvPassword:    mailPassword,
		"MAX_SENDS_PER_DAY": "5",
		"SEND_ALLOWLIST":    "example.org",
	}
}

func load(m map[string]string) (*Config, error) { return Load(func(k string) string { return m[k] }) }

func TestLoadFull(t *testing.T) {
	c, err := load(fullEnv())
	if err != nil {
		t.Fatal(err)
	}
	if c.Setup() || c.Port != "8080" || c.TrustedProxyHops != 1 || c.OAuth.Resource != "https://email-mcp-abc.a.run.app/mcp" ||
		c.OAuth.Epoch != "1" || c.Policy.MaxPerDay != 5 || c.Mail.LedgerFolder != mail.DefaultLedgerFolder {
		t.Fatalf("cfg = %+v", c)
	}
	// One secret, independent derived keys.
	if bytes.Equal(c.OAuth.SigningKey, c.OAuth.CSRFKey) || bytes.Equal(c.OAuth.SigningKey, c.Mail.DraftKey) ||
		len(c.Mail.DraftKey) != 32 || bytes.Contains(c.OAuth.SigningKey, []byte("KKKK")) {
		t.Fatal("keys not derived independently")
	}
	again, _ := load(fullEnv())
	if !bytes.Equal(again.Mail.DraftKey, c.Mail.DraftKey) {
		t.Fatal("derivation not deterministic (draft IDs would break on restart)")
	}
}

func TestSetupModeStillValidatesSecrets(t *testing.T) {
	env := fullEnv()
	delete(env, EnvBaseURL)
	c, err := load(env)
	if err != nil || !c.Setup() {
		t.Fatalf("setup mode: %v", err)
	}
	delete(env, EnvClientSecret)
	if _, err := load(env); err == nil {
		t.Fatal("missing client secret accepted in setup mode")
	}
}

func TestLoadErrorsNameSettingsNotValues(t *testing.T) {
	env := fullEnv()
	env[EnvBaseURL] = "http://email-mcp.example/path"
	env[EnvSigningKey] = "c2hvcnQ=" // "short"
	env[EnvPasswordHash] = "plaintext-" + clientSecret
	env[EnvLogLevel] = "chatty"
	env[EnvProxyHops] = "9"
	env["MAX_SENDS_PER_DAY"] = "-3"
	_, err := load(env)
	if err == nil {
		t.Fatal("accepted")
	}
	msg := err.Error()
	for _, want := range []string{EnvBaseURL, EnvSigningKey, "password hash", EnvLogLevel, EnvProxyHops, "MAX_SENDS_PER_DAY"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error lacks %s:\n%s", want, msg)
		}
	}
	for _, leak := range []string{clientSecret, mailPassword, "c2hvcnQ="} {
		if strings.Contains(msg, leak) {
			t.Errorf("error leaks %q", leak)
		}
	}
}

func TestDecodeKeyVariants(t *testing.T) {
	raw := bytes.Repeat([]byte{0xfb, 0xff}, 16) // encodes differently in std and url alphabets
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		got, err := decodeKey(enc.EncodeToString(raw))
		if err != nil || !bytes.Equal(got, raw) {
			t.Errorf("%v: %v", enc, err)
		}
	}
	for _, bad := range []string{"", "!!!", base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		if _, err := decodeKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRedirectURIsAndLoginMode(t *testing.T) {
	env := fullEnv()
	env[EnvRedirectURIs] = "https://claude.ai/api/mcp/auth_callback, http://localhost:6274/oauth/callback"
	env[EnvAuthorizeMode] = "FORM"
	c, err := load(env)
	if err != nil || len(c.OAuth.RedirectURIs) != 2 || c.OAuth.LoginMode != "form" {
		t.Fatalf("%v %+v", err, c.OAuth.RedirectURIs)
	}
	env[EnvRedirectURIs] = "http://evil.example/cb"
	if _, err := load(env); err == nil {
		t.Fatal("non-https redirect accepted")
	}
}
