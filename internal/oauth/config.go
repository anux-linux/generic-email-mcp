// Package oauth is a minimal OAuth 2.1 authorization server for exactly one
// pre-registered confidential client (claude.ai) and one resource owner.
// It issues HS256 JWT access tokens bound to the MCP resource and rotating
// refresh tokens; the same binary verifies the access tokens on /mcp.
//
// Supported: authorization_code with PKCE S256 (mandatory) and
// refresh_token grants; client_secret_basic and client_secret_post; RFC 8414
// and RFC 9728 metadata; RFC 8707 resource indicators; RFC 9207 iss. No
// dynamic client registration, no implicit or password grants.
package oauth

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"
)

// Defaults.
const (
	DefaultAccessTTL  = time.Hour
	DefaultRefreshTTL = 30 * 24 * time.Hour
	DefaultCodeTTL    = 5 * time.Minute
	DefaultUsername   = "owner"
	ClaudeCallback    = "https://claude.ai/api/mcp/auth_callback"
	Scope             = "mail"

	LoginBasic = "basic"
	LoginForm  = "form"

	minKeyLen    = 32
	minSecretLen = 32
)

// Config configures the authorization server.
type Config struct {
	Issuer       string // BASE_URL, e.g. https://svc-123.europe-west1.run.app
	Resource     string // protected resource (MCP endpoint) URL
	ClientID     string
	ClientSecret string
	RedirectURIs []string // exact-match allowlist

	SigningKey []byte // HS256 key for access and refresh tokens
	CSRFKey    []byte // HMAC key for the login form (form mode)
	Epoch      string // embedded in every token; changing it revokes all

	PasswordHash string // owner password: argon2id PHC string or bcrypt
	Username     string // HTTP Basic username (basic mode)
	LoginMode    string // LoginBasic or LoginForm

	AccessTTL  time.Duration
	RefreshTTL time.Duration
	CodeTTL    time.Duration

	// Journal stores token families (refresh rotation, reuse detection,
	// revocation). Nil means an in-memory journal.
	Journal Journal

	Logger *slog.Logger
	Now    func() time.Time
}

func (c *Config) setDefaults() {
	if c.AccessTTL == 0 {
		c.AccessTTL = DefaultAccessTTL
	}
	if c.RefreshTTL == 0 {
		c.RefreshTTL = DefaultRefreshTTL
	}
	if c.CodeTTL == 0 {
		c.CodeTTL = DefaultCodeTTL
	}
	if c.Username == "" {
		c.Username = DefaultUsername
	}
	if c.LoginMode == "" {
		c.LoginMode = LoginBasic
	}
	if len(c.RedirectURIs) == 0 {
		c.RedirectURIs = []string{ClaudeCallback}
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

func (c *Config) validate() error {
	var errs []error
	if err := ValidateBaseURL(c.Issuer); err != nil {
		errs = append(errs, fmt.Errorf("issuer: %w", err))
	}
	if !strings.HasPrefix(c.Resource, c.Issuer+"/") {
		errs = append(errs, errors.New("resource must be below the issuer URL"))
	}
	if !validClientID(c.ClientID) {
		errs = append(errs, errors.New("client id must be 8-128 characters of [A-Za-z0-9._~-]"))
	}
	if len(c.ClientSecret) < minSecretLen {
		errs = append(errs, fmt.Errorf("client secret must be at least %d characters", minSecretLen))
	}
	for _, u := range c.RedirectURIs {
		if err := validRedirectURI(u); err != nil {
			errs = append(errs, err)
		}
	}
	if len(c.SigningKey) < minKeyLen || len(c.CSRFKey) < minKeyLen {
		errs = append(errs, fmt.Errorf("signing keys must be at least %d bytes", minKeyLen))
	}
	if c.Epoch == "" || len(c.Epoch) > 64 {
		errs = append(errs, errors.New("token epoch must be 1-64 characters"))
	}
	if _, err := parseHash(c.PasswordHash); err != nil {
		errs = append(errs, fmt.Errorf("password hash: %w", err))
	}
	if c.LoginMode != LoginBasic && c.LoginMode != LoginForm {
		errs = append(errs, errors.New("login mode must be basic or form"))
	}
	if strings.ContainsAny(c.Username, ":\r\n") {
		errs = append(errs, errors.New("username must not contain ':' or line breaks"))
	}
	if c.AccessTTL < time.Minute || c.RefreshTTL < c.AccessTTL || c.CodeTTL < 10*time.Second || c.CodeTTL > 10*time.Minute {
		errs = append(errs, errors.New("token lifetimes are invalid"))
	}
	return errors.Join(errs...)
}

// ValidateBaseURL checks a service base URL: https (http only for loopback
// hosts, for local testing), no path, query, fragment or user info.
func ValidateBaseURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errors.New("must be an absolute URL like https://host")
	}
	if u.Path != "" {
		return errors.New("must not have a path or trailing slash")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return errors.New("must use https")
		}
	default:
		return errors.New("must use https")
	}
	return nil
}

func validRedirectURI(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil || u.Opaque != "" {
		return fmt.Errorf("redirect URI %q is not an absolute URL without fragment", s)
	}
	if u.Scheme == "https" || u.Scheme == "http" && isLoopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("redirect URI %q must use https (http only for loopback)", s)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validClientID(s string) bool {
	if len(s) < 8 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._~-", c) >= 0) {
			return false
		}
	}
	return true
}
