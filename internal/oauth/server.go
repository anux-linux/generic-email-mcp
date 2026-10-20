package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/time/rate"
)

// Paths served by the authorization server.
const (
	PathAuthorize        = "/authorize"
	PathToken            = "/token"
	PathResourceMetadata = "/.well-known/oauth-protected-resource"
	PathASMetadata       = "/.well-known/oauth-authorization-server"
)

// Server is the authorization server plus the access-token verifier.
type Server struct {
	cfg   Config
	hash  *passwordHash
	store *store

	// Global limiters for failed owner logins and failed client
	// authentication: 5 immediate attempts, then one per minute.
	loginFailures  *rate.Limiter
	clientFailures *rate.Limiter
	// hashSem serializes argon2id verifications (64 MiB each).
	hashSem chan struct{}

	formCSP string
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	cfg.setDefaults()
	cfg.SigningKey = slices.Clone(cfg.SigningKey)
	cfg.CSRFKey = slices.Clone(cfg.CSRFKey)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	h, _ := parseHash(cfg.PasswordHash)
	s := &Server{
		cfg:            cfg,
		hash:           h,
		store:          newStore(),
		loginFailures:  rate.NewLimiter(rate.Every(time.Minute), 5),
		clientFailures: rate.NewLimiter(rate.Every(time.Minute), 5),
		hashSem:        make(chan struct{}, 1),
	}
	s.formCSP = formCSP(cfg.RedirectURIs)
	return s, nil
}

// ResourceMetadataURL is advertised in WWW-Authenticate on /mcp.
func (s *Server) ResourceMetadataURL() string { return s.cfg.Issuer + PathResourceMetadata }

// Register adds the OAuth endpoints to mux. wrap is applied to /authorize
// and /token (rate limiting, body limits, logging live in the caller).
func (s *Server) Register(mux *http.ServeMux, wrap func(name string, h http.Handler) http.Handler) {
	prm := auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               s.cfg.Resource,
		AuthorizationServers:   []string{s.cfg.Issuer},
		ScopesSupported:        []string{Scope},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "Mailbox (generic-email-mcp)",
	})
	asm := s.authServerMetadataHandler()
	// RFC 9728 §3.1 / RFC 8414 §3.1: the well-known suffix may be followed
	// by the resource path or issuer path; serve both forms.
	resourcePath := strings.TrimPrefix(s.cfg.Resource, s.cfg.Issuer)
	for _, p := range []string{PathResourceMetadata, PathResourceMetadata + resourcePath} {
		mux.Handle(p, wrap("resource_metadata", prm))
	}
	for _, p := range []string{PathASMetadata, PathASMetadata + resourcePath} {
		mux.Handle(p, wrap("as_metadata", asm))
	}
	mux.Handle(PathAuthorize, wrap("authorize", http.HandlerFunc(s.handleAuthorize)))
	mux.Handle(PathToken, wrap("token", http.HandlerFunc(s.handleToken)))
}

// asMetadata is RFC 8414 metadata. A local type, because
// oauthex.AuthServerMeta always emits jwks_uri, which this server (HS256)
// does not have.
type asMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	AuthorizationResponseIssSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

func (s *Server) authServerMetadataHandler() http.Handler {
	body, err := json.Marshal(asMetadata{
		Issuer:                            s.cfg.Issuer,
		AuthorizationEndpoint:             s.cfg.Issuer + PathAuthorize,
		TokenEndpoint:                     s.cfg.Issuer + PathToken,
		ScopesSupported:                   []string{Scope},
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		AuthorizationResponseIssSupported: true,
	})
	if err != nil {
		panic(err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet, http.MethodHead:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "public, max-age=300")
			_, _ = w.Write(body)
		default:
			w.Header().Set("Allow", "GET, OPTIONS")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

// checkPassword verifies the owner password under the global failure
// limiter. It returns errRateLimited when attempts are exhausted.
func (s *Server) checkPassword(r *http.Request, password string) error {
	if s.loginFailures.Tokens() < 1 {
		return errRateLimited
	}
	select {
	case s.hashSem <- struct{}{}:
	case <-r.Context().Done():
		return r.Context().Err()
	}
	ok := len(password) <= 1024 && s.hash.verify(password)
	<-s.hashSem
	if !ok {
		s.loginFailures.Allow()
		return errBadCredentials
	}
	return nil
}

var (
	errRateLimited    = errors.New("too many failed attempts; try again later")
	errBadCredentials = errors.New("invalid credentials")
)

// equalSecret compares in constant time independent of length.
func equalSecret(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// retryAfter is sent with 429 responses of the failure limiters (one token
// per minute).
func retryAfter(w http.ResponseWriter) { w.Header().Set("Retry-After", "60") }
