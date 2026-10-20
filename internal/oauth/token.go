package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

type tokenError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func tokenFail(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, tokenError{Error: code, Description: desc})
}

var tokenParams = []string{"grant_type", "code", "redirect_uri", "code_verifier", "refresh_token", "client_id", "client_secret", "scope", "resource"}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		tokenFail(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/x-www-form-urlencoded" {
		tokenFail(w, http.StatusBadRequest, "invalid_request", "content type must be application/x-www-form-urlencoded")
		return
	}
	if err := r.ParseForm(); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			tokenFail(w, http.StatusRequestEntityTooLarge, "invalid_request", "request too large")
			return
		}
		tokenFail(w, http.StatusBadRequest, "invalid_request", "malformed body")
		return
	}
	form := r.PostForm
	for _, p := range tokenParams {
		if len(form[p]) > 1 {
			tokenFail(w, http.StatusBadRequest, "invalid_request", "parameter "+p+" repeated")
			return
		}
	}
	if status, code, desc := s.authenticateClient(w, r, form); code != "" {
		tokenFail(w, status, code, desc)
		return
	}
	if res := form.Get("resource"); res != "" && !oauthex.MatchesResource([]string{res}, s.cfg.Resource) {
		tokenFail(w, http.StatusBadRequest, "invalid_target", "unknown resource")
		return
	}
	switch form.Get("grant_type") {
	case "authorization_code":
		s.grantAuthorizationCode(w, form)
	case "refresh_token":
		s.grantRefreshToken(w, form)
	case "":
		tokenFail(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
	default:
		tokenFail(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

// authenticateClient implements client_secret_basic and client_secret_post
// (exactly one). Secrets are compared in constant time; failures are
// globally rate limited.
func (s *Server) authenticateClient(w http.ResponseWriter, r *http.Request, form url.Values) (int, string, string) {
	if s.clientFailures.Tokens() < 1 {
		retryAfter(w)
		return http.StatusTooManyRequests, "invalid_client", "too many failed attempts"
	}
	id, secret, basic := r.BasicAuth()
	_, hasPost := form["client_secret"]
	switch {
	case basic && hasPost:
		return http.StatusBadRequest, "invalid_request", "use exactly one client authentication method"
	case basic:
		// RFC 6749 §2.3.1: both parts are form-urlencoded inside Basic.
		var err1, err2 error
		id, err1 = url.QueryUnescape(id)
		secret, err2 = url.QueryUnescape(secret)
		if err1 != nil || err2 != nil {
			return s.clientFailed(w, basic)
		}
		if fid := form.Get("client_id"); fid != "" && fid != id {
			return http.StatusBadRequest, "invalid_request", "client_id mismatch"
		}
	case hasPost:
		id, secret = form.Get("client_id"), form.Get("client_secret")
	default:
		return s.clientFailed(w, false)
	}
	idOK := equalSecret(id, s.cfg.ClientID)
	secretOK := equalSecret(secret, s.cfg.ClientSecret)
	if !idOK || !secretOK {
		return s.clientFailed(w, basic)
	}
	return 0, "", ""
}

func (s *Server) clientFailed(w http.ResponseWriter, basic bool) (int, string, string) {
	s.clientFailures.Allow()
	s.cfg.Logger.Warn("client authentication failed", "component", "oauth", "reason", "bad_client")
	if basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	}
	return http.StatusUnauthorized, "invalid_client", "client authentication failed"
}

func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~", c) >= 0) {
			return false
		}
	}
	return true
}

func (s *Server) grantAuthorizationCode(w http.ResponseWriter, form url.Values) {
	code, verifier, redirectURI := form.Get("code"), form.Get("code_verifier"), form.Get("redirect_uri")
	if code == "" || redirectURI == "" {
		tokenFail(w, http.StatusBadRequest, "invalid_request", "code and redirect_uri are required")
		return
	}
	if !validVerifier(verifier) {
		tokenFail(w, http.StatusBadRequest, "invalid_request", "code_verifier is required (43-128 unreserved characters)")
		return
	}
	now := s.cfg.Now()
	family := randomID()
	// The code is consumed by this attempt whatever the outcome below.
	entry, ok := s.store.redeemCode(code, family, now, s.cfg.RefreshTTL)
	if !ok {
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "invalid, expired or already used code")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if entry.redirectURI != redirectURI || entry.clientID != s.cfg.ClientID ||
		subtle.ConstantTimeCompare([]byte(challenge), []byte(entry.challenge)) != 1 {
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "code does not match redirect_uri or PKCE verifier")
		return
	}
	resp, err := s.issue(family, entry.resource)
	if err != nil {
		tokenFail(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	s.cfg.Logger.Info("tokens issued", "component", "oauth", "grant_type", "authorization_code")
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) grantRefreshToken(w http.ResponseWriter, form url.Values) {
	raw := form.Get("refresh_token")
	if raw == "" {
		tokenFail(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	if sc := strings.Fields(form.Get("scope")); len(sc) > 1 || len(sc) == 1 && sc[0] != Scope {
		tokenFail(w, http.StatusBadRequest, "invalid_scope", "only scope "+Scope+" can be granted")
		return
	}
	c, err := s.parse(raw, typRefresh, s.cfg.Issuer)
	if err != nil {
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")
		return
	}
	if !s.store.useRefresh(c.ID, c.Family, c.ExpiresAt.Time, s.cfg.Now(), s.cfg.RefreshTTL) {
		s.cfg.Logger.Warn("refresh token reuse or revoked family", "component", "oauth", "reason", "refresh_reuse")
		tokenFail(w, http.StatusBadRequest, "invalid_grant", "refresh token was already used or revoked")
		return
	}
	resp, err := s.issue(c.Family, c.Resource)
	if err != nil {
		tokenFail(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	s.cfg.Logger.Info("tokens issued", "component", "oauth", "grant_type", "refresh_token")
	writeJSON(w, http.StatusOK, resp)
}
