package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

// JWT "typ" header values. Distinct types prevent using a refresh token as
// an access token or vice versa (RFC 8725 §3.11).
const (
	typAccess  = "at+jwt" // RFC 9068
	typRefresh = "rt+jwt"
	leeway     = 30 * time.Second
	subject    = "owner"
)

// tokenClaims are shared by access and refresh tokens.
type tokenClaims struct {
	jwt.RegisteredClaims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	Epoch    string `json:"epoch"`
	Family   string `json:"fam"`
	Resource string `json:"resource,omitempty"` // refresh tokens: bound resource
}

func randomID() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func (s *Server) sign(typ, audience, family, resource string, ttl time.Duration) (string, time.Time, error) {
	now := s.cfg.Now()
	exp := now.Add(ttl)
	c := tokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        randomID(),
		},
		ClientID: s.cfg.ClientID,
		Scope:    Scope,
		Epoch:    s.cfg.Epoch,
		Family:   family,
		Resource: resource,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	t.Header["typ"] = typ
	signed, err := t.SignedString(s.cfg.SigningKey)
	return signed, exp, err
}

var errBadToken = errors.New("invalid token")

// parse verifies signature (HS256 only), typ, issuer, audience, exp/nbf/iat,
// epoch and client.
func (s *Server) parse(raw, typ, audience string) (*tokenClaims, error) {
	if len(raw) > 4096 {
		return nil, errBadToken
	}
	p := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(s.cfg.Issuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(leeway),
		jwt.WithTimeFunc(s.cfg.Now),
		jwt.WithStrictDecoding(),
	)
	var c tokenClaims
	tok, err := p.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) {
		if t.Header["typ"] != typ {
			return nil, errBadToken
		}
		return s.cfg.SigningKey, nil
	})
	if err != nil || !tok.Valid {
		return nil, errBadToken
	}
	if c.Epoch != s.cfg.Epoch || c.ClientID != s.cfg.ClientID || c.Subject != subject || c.ID == "" || c.Family == "" {
		return nil, errBadToken
	}
	if !slices.Contains(strings.Fields(c.Scope), Scope) {
		return nil, errBadToken
	}
	return &c, nil
}

// VerifyAccessToken implements auth.TokenVerifier for the MCP endpoint.
// Every failure maps to auth.ErrInvalidToken with a fixed message, so the
// 401 body never reflects token contents.
func (s *Server) VerifyAccessToken(_ context.Context, raw string, _ *http.Request) (*auth.TokenInfo, error) {
	c, err := s.parse(raw, typAccess, s.cfg.Resource)
	if err != nil || s.store.familyRevoked(c.Family) {
		return nil, fmt.Errorf("%w", auth.ErrInvalidToken)
	}
	return &auth.TokenInfo{
		Scopes:     strings.Fields(c.Scope),
		Expiration: c.ExpiresAt.Time,
		UserID:     c.Subject,
	}, nil
}

// tokenResponse is the RFC 6749 §5.1 success body.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// issue mints an access/refresh pair for family.
func (s *Server) issue(family, resource string) (*tokenResponse, error) {
	at, _, err := s.sign(typAccess, s.cfg.Resource, family, "", s.cfg.AccessTTL)
	if err != nil {
		return nil, err
	}
	rt, _, err := s.sign(typRefresh, s.cfg.Issuer, family, resource, s.cfg.RefreshTTL)
	if err != nil {
		return nil, err
	}
	return &tokenResponse{
		AccessToken: at, TokenType: "Bearer", ExpiresIn: int64(s.cfg.AccessTTL / time.Second),
		RefreshToken: rt, Scope: Scope,
	}, nil
}
