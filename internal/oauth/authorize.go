package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

// authRequest is a validated authorization request.
type authRequest struct {
	ClientID    string `json:"c"`
	RedirectURI string `json:"r"`
	State       string `json:"s,omitempty"`
	Challenge   string `json:"p"`
	Resource    string `json:"res"`
}

// authError is an authorization error. Without a trusted redirect URI it is
// shown to the user instead of redirecting (RFC 6749 §4.1.2.1).
type authError struct {
	code, desc string
	redirect   bool
}

var singleParams = []string{"response_type", "client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "resource"}

// parseAuthRequest validates q. The returned request is usable for an error
// redirect whenever err.redirect is true.
func (s *Server) parseAuthRequest(q url.Values) (authRequest, *authError) {
	req := authRequest{ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"), State: q.Get("state")}
	if len(q["client_id"]) != 1 || req.ClientID != s.cfg.ClientID {
		return req, &authError{code: "invalid_request", desc: "unknown client_id"}
	}
	if len(q["redirect_uri"]) != 1 || !slices.Contains(s.cfg.RedirectURIs, req.RedirectURI) {
		return req, &authError{code: "invalid_request", desc: "redirect_uri is not registered"}
	}
	redirectErr := func(code, desc string) (authRequest, *authError) {
		return req, &authError{code: code, desc: desc, redirect: true}
	}
	for _, p := range singleParams {
		if len(q[p]) > 1 {
			return redirectErr("invalid_request", "parameter "+p+" repeated")
		}
	}
	if len(req.State) > 2048 {
		return redirectErr("invalid_request", "state too long")
	}
	if q.Get("response_type") != "code" {
		return redirectErr("unsupported_response_type", "only response_type=code is supported")
	}
	if q.Get("code_challenge_method") != "S256" {
		return redirectErr("invalid_request", "PKCE with code_challenge_method=S256 is required")
	}
	req.Challenge = q.Get("code_challenge")
	if !validChallenge(req.Challenge) {
		return redirectErr("invalid_request", "code_challenge must be a base64url SHA-256 value")
	}
	req.Resource = s.cfg.Resource
	if res := q.Get("resource"); res != "" && !oauthex.MatchesResource([]string{res}, s.cfg.Resource) {
		return redirectErr("invalid_target", "unknown resource")
	}
	// Any requested scope is reduced to the only one this server grants.
	return req, nil
}

func validChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(c)
	return err == nil
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.Method == http.MethodGet:
		req, aerr := s.parseAuthRequest(r.URL.Query())
		if aerr != nil {
			s.authFailure(w, r, req, aerr)
			return
		}
		if s.cfg.LoginMode == LoginForm {
			s.renderForm(w, req, "", http.StatusOK)
			return
		}
		s.basicLogin(w, r, req)
	case r.Method == http.MethodPost && s.cfg.LoginMode == LoginForm:
		s.formLogin(w, r)
	default:
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) authFailure(w http.ResponseWriter, r *http.Request, req authRequest, e *authError) {
	if !e.redirect {
		http.Error(w, "Authorization request rejected: "+e.desc+".", http.StatusBadRequest)
		return
	}
	s.redirect(w, r, req, url.Values{"error": {e.code}, "error_description": {e.desc}}, http.StatusFound)
}

// redirect sends the user agent back to the (validated) redirect URI with
// params, state and iss (RFC 9207).
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, req authRequest, params url.Values, status int) {
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	if req.State != "" {
		q.Set("state", req.State)
	}
	q.Set("iss", s.cfg.Issuer)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), status)
}

// grant issues an authorization code and redirects.
func (s *Server) grant(w http.ResponseWriter, r *http.Request, req authRequest, status int) {
	code := randomID()
	now := s.cfg.Now()
	ok := s.store.putCode(code, &codeEntry{
		clientID: req.ClientID, redirectURI: req.RedirectURI, challenge: req.Challenge,
		resource: req.Resource, expires: now.Add(s.cfg.CodeTTL),
	}, now)
	if !ok {
		s.redirect(w, r, req, url.Values{"error": {"temporarily_unavailable"}}, status)
		return
	}
	s.cfg.Logger.Info("authorization code issued", "component", "oauth")
	s.redirect(w, r, req, url.Values{"code": {code}}, status)
}

// basicLogin authenticates the owner with an HTTP Basic challenge.
func (s *Server) basicLogin(w http.ResponseWriter, r *http.Request, req authRequest) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		s.basicChallenge(w)
		return
	}
	err := s.checkPassword(r, pass)
	if errors.Is(err, errRateLimited) {
		retryAfter(w)
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}
	userOK := equalSecret(user, s.cfg.Username)
	if err == nil && !userOK {
		s.loginFailures.Allow()
	}
	if err != nil || !userOK {
		s.cfg.Logger.Warn("owner authentication failed", "component", "oauth", "reason", "bad_credentials")
		s.basicChallenge(w)
		return
	}
	s.grant(w, r, req, http.StatusFound)
}

func (s *Server) basicChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="generic-email-mcp", charset="UTF-8"`)
	http.Error(w, "Authentication required.", http.StatusUnauthorized)
}

// Form mode: a single password field. CSRF defence: the form carries an
// HMAC-signed copy of the validated request that embeds a random token,
// which must also arrive in a __Host- SameSite=Strict cookie; cross-origin
// POSTs are rejected outright (Sec-Fetch-Site / Origin).

const (
	csrfCookie = "__Host-mcp_login"
	formTTL    = 10 * time.Minute
)

type signedRequest struct {
	authRequest
	CSRF    string `json:"x"`
	Expires int64  `json:"e"`
}

func (s *Server) sealRequest(req authRequest, csrf string) string {
	b, _ := json.Marshal(signedRequest{authRequest: req, CSRF: csrf, Expires: s.cfg.Now().Add(formTTL).Unix()})
	payload := base64.RawURLEncoding.EncodeToString(b)
	return payload + "." + base64.RawURLEncoding.EncodeToString(s.formMAC(payload))
}

func (s *Server) formMAC(payload string) []byte {
	m := hmac.New(sha256.New, s.cfg.CSRFKey)
	m.Write([]byte("generic-email-mcp/login-form/v1\x00" + payload))
	return m.Sum(nil)
}

func (s *Server) openRequest(sealed string) (*signedRequest, error) {
	payload, sig, ok := strings.Cut(sealed, ".")
	mac, err := base64.RawURLEncoding.DecodeString(sig)
	if !ok || err != nil || !hmac.Equal(mac, s.formMAC(payload)) {
		return nil, errors.New("bad signature")
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}
	var sr signedRequest
	if err := json.Unmarshal(b, &sr); err != nil {
		return nil, err
	}
	if s.cfg.Now().Unix() > sr.Expires {
		return nil, errors.New("expired")
	}
	// Re-check against the current configuration.
	if sr.ClientID != s.cfg.ClientID || !slices.Contains(s.cfg.RedirectURIs, sr.RedirectURI) || !validChallenge(sr.Challenge) {
		return nil, errors.New("stale request")
	}
	return &sr, nil
}

var formTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize mailbox access</title><style>` + formStyle + `</style></head>
<body><main>
<h1>Authorize mailbox access</h1>
<p><strong>{{.Client}}</strong> is requesting access to your mailbox through this server.</p>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
<form method="post" action="/authorize" autocomplete="off">
<input type="hidden" name="request" value="{{.Request}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label for="password">Owner password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required autofocus maxlength="1024">
<button type="submit">Authorize</button>
</form>
<p class="small">Only continue if you started connecting this mailbox yourself.</p>
</main></body></html>`))

const formStyle = `body{font:16px system-ui,sans-serif;margin:0;padding:16px;color:#111;background:#fff}` +
	`main{max-width:420px;margin:10vh auto}input,button{font:inherit;width:100%;box-sizing:border-box;padding:10px;margin:6px 0}` +
	`.err{color:#b00020}.small{font-size:13px;color:#555}` +
	`@media (prefers-color-scheme:dark){body{color:#eee;background:#121212}.small{color:#aaa}.err{color:#ff8a80}}`

// formCSP allows exactly the inline style above and form submission to
// self plus the redirect origins (Chrome applies form-action to the
// redirect that follows the POST).
func formCSP(redirectURIs []string) string {
	sum := sha256.Sum256([]byte(formStyle))
	origins := []string{"'self'"}
	for _, ru := range redirectURIs {
		if u, err := url.Parse(ru); err == nil {
			if o := u.Scheme + "://" + u.Host; !slices.Contains(origins, o) {
				origins = append(origins, o)
			}
		}
	}
	return fmt.Sprintf("default-src 'none'; style-src 'sha256-%s'; form-action %s; frame-ancestors 'none'; base-uri 'none'",
		base64.StdEncoding.EncodeToString(sum[:]), strings.Join(origins, " "))
}

func (s *Server) renderForm(w http.ResponseWriter, req authRequest, msg string, status int) {
	csrf := randomID()
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: csrf, Path: "/", MaxAge: int(formTTL / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	client := "Claude"
	if u, err := url.Parse(req.RedirectURI); err == nil {
		client += " (" + u.Host + ")"
	}
	w.Header().Set("Content-Security-Policy", s.formCSP)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = formTmpl.Execute(w, map[string]string{"Client": client, "Error": msg, "Request": s.sealRequest(req, csrf), "CSRF": csrf})
}

var crossOrigin = http.NewCrossOriginProtection()

func (s *Server) formLogin(w http.ResponseWriter, r *http.Request) {
	if err := crossOrigin.Check(r); err != nil {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	sr, err := s.openRequest(r.PostForm.Get("request"))
	cookie, cerr := r.Cookie(csrfCookie)
	formTok := r.PostForm.Get("csrf")
	if err != nil || cerr != nil || formTok == "" ||
		subtle.ConstantTimeCompare([]byte(formTok), []byte(sr.CSRF)) != 1 ||
		subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(sr.CSRF)) != 1 {
		http.Error(w, "The login form expired or was tampered with. Start the connection again from Claude.", http.StatusForbidden)
		return
	}
	switch err := s.checkPassword(r, r.PostForm.Get("password")); {
	case errors.Is(err, errRateLimited):
		retryAfter(w)
		s.renderForm(w, sr.authRequest, "Too many failed attempts. Wait a minute and try again.", http.StatusTooManyRequests)
		return
	case err != nil:
		s.cfg.Logger.Warn("owner authentication failed", "component", "oauth", "reason", "bad_credentials")
		s.renderForm(w, sr.authRequest, "Wrong password.", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	s.grant(w, r, sr.authRequest, http.StatusSeeOther)
}
