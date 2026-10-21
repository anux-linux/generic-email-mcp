// Package config loads the whole service configuration from environment
// variables. Secrets (mail password, signing key, client secret, password
// hash) arrive as env vars injected from Secret Manager by Cloud Run.
// Error messages name settings, never their values.
package config

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/anux-linux/generic-email-mcp/internal/mail"
	"github.com/anux-linux/generic-email-mcp/internal/oauth"
	"github.com/anux-linux/generic-email-mcp/internal/policy"
)

// Env var names (mail and policy variables are defined in their packages).
const (
	EnvBaseURL       = "BASE_URL"
	EnvPort          = "PORT"
	EnvLogLevel      = "LOG_LEVEL"
	EnvProxyHops     = "TRUSTED_PROXY_HOPS"
	EnvClientID      = "OAUTH_CLIENT_ID"
	EnvClientSecret  = "OAUTH_CLIENT_SECRET"
	EnvRedirectURIs  = "OAUTH_REDIRECT_URIS"
	EnvSigningKey    = "TOKEN_SIGNING_KEY"
	EnvTokenEpoch    = "TOKEN_EPOCH"
	EnvPasswordHash  = "AUTHORIZE_PASSWORD_HASH"
	EnvAuthorizeUser = "AUTHORIZE_USERNAME"
	EnvAuthorizeMode = "AUTHORIZE_LOGIN"
)

// Config is the complete service configuration.
type Config struct {
	Port             string
	BaseURL          string // empty: setup mode (only /health)
	LogLevel         slog.Level
	TrustedProxyHops int

	Mail   mail.Config
	Policy policy.Config
	OAuth  oauth.Config // Logger and Now are set by the caller
}

// Setup reports whether the service runs in setup mode.
func (c *Config) Setup() bool { return c.BaseURL == "" }

// Load reads and validates the configuration. In setup mode (BASE_URL
// unset) everything else is still validated, so a broken secret fails the
// first deployment instead of the second.
func Load(getenv func(string) string) (*Config, error) {
	var errs []error
	c := &Config{
		Port:    strings.TrimSpace(getenv(EnvPort)),
		BaseURL: strings.TrimSpace(getenv(EnvBaseURL)),
	}
	if c.Port == "" {
		c.Port = "8080"
	}
	if n, err := strconv.Atoi(c.Port); err != nil || n < 1 || n > 65535 {
		errs = append(errs, fmt.Errorf("%s must be a TCP port", EnvPort))
	}
	if c.BaseURL != "" {
		if err := oauth.ValidateBaseURL(c.BaseURL); err != nil {
			errs = append(errs, fmt.Errorf("%s %w", EnvBaseURL, err))
		}
	}
	if v := strings.TrimSpace(getenv(EnvLogLevel)); v != "" {
		if err := c.LogLevel.UnmarshalText([]byte(v)); err != nil {
			errs = append(errs, fmt.Errorf("%s must be debug, info, warn or error", EnvLogLevel))
		}
	}
	c.TrustedProxyHops = 1
	if v := strings.TrimSpace(getenv(EnvProxyHops)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 5 {
			errs = append(errs, fmt.Errorf("%s must be 0-5", EnvProxyHops))
		}
		c.TrustedProxyHops = n
	}

	master, err := decodeKey(getenv(EnvSigningKey))
	if err != nil {
		errs = append(errs, fmt.Errorf("%s %w", EnvSigningKey, err))
	}
	keys := deriveKeys(master)

	mc, err := mail.ConfigFromEnv(getenv)
	if err != nil {
		errs = append(errs, err)
	}
	mc.DraftKey = keys.draft
	if err := mc.Validate(); err != nil && master != nil {
		errs = append(errs, err)
	}
	c.Mail = mc

	if c.Policy, err = policy.FromEnv(getenv); err != nil {
		errs = append(errs, err)
	} else if _, err := policy.NewMemory(c.Policy); err != nil {
		errs = append(errs, err)
	}

	epoch := strings.TrimSpace(getenv(EnvTokenEpoch))
	if epoch == "" {
		epoch = "1"
	}
	var redirects []string
	for r := range strings.FieldsFuncSeq(getenv(EnvRedirectURIs), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		redirects = append(redirects, r)
	}
	c.OAuth = oauth.Config{
		Issuer:       c.BaseURL,
		Resource:     c.BaseURL + "/mcp",
		ClientID:     strings.TrimSpace(getenv(EnvClientID)),
		ClientSecret: strings.TrimSpace(getenv(EnvClientSecret)),
		RedirectURIs: redirects,
		SigningKey:   keys.jwt,
		CSRFKey:      keys.csrf,
		Epoch:        epoch,
		PasswordHash: strings.TrimSpace(getenv(EnvPasswordHash)),
		Username:     strings.TrimSpace(getenv(EnvAuthorizeUser)),
		LoginMode:    strings.ToLower(strings.TrimSpace(getenv(EnvAuthorizeMode))),
	}
	probe := c.OAuth
	if c.Setup() || len(errs) > 0 {
		// Validate the remaining OAuth settings against a placeholder URL.
		probe.Issuer, probe.Resource = "https://setup.invalid", "https://setup.invalid/mcp"
	}
	if probe.SigningKey == nil {
		probe.SigningKey, probe.CSRFKey = make([]byte, 32), make([]byte, 32) // already reported
	}
	if _, err := oauth.New(probe); err != nil {
		errs = append(errs, fmt.Errorf("oauth: %w", err))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return c, nil
}

// decodeKey accepts standard or URL-safe base64, padded or not, of at least
// 32 bytes.
func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("is required")
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			if len(b) < 32 {
				return nil, errors.New("must decode to at least 32 bytes")
			}
			return b, nil
		}
	}
	return nil, errors.New("must be base64")
}

type derivedKeys struct{ jwt, csrf, draft []byte }

// deriveKeys splits the one signing secret into independent keys (HKDF-
// SHA256 with distinct labels), so a token key can never verify a draft ID
// or a login form and vice versa.
func deriveKeys(master []byte) derivedKeys {
	if master == nil {
		return derivedKeys{}
	}
	derive := func(label string) []byte {
		k, err := hkdf.Key(sha256.New, master, nil, "generic-email-mcp/"+label+"/v1", 32)
		if err != nil {
			panic(err) // only for invalid lengths
		}
		return k
	}
	return derivedKeys{jwt: derive("jwt"), csrf: derive("login-form"), draft: derive("draft-id")}
}
