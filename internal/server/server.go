// Package server assembles the HTTP service: OAuth endpoints, the
// bearer-protected MCP endpoint and /health, with timeouts, body limits,
// rate limits, security headers and log-safe request logging.
package server

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/time/rate"

	"github.com/anux-linux/generic-email-mcp/internal/oauth"
)

// Limits.
const (
	maxOAuthBody   = 16 << 10
	maxMCPBody     = 1 << 20
	maxHeaderBytes = 16 << 10
	PathMCP        = "/mcp"
	// Not /healthz: Cloud Run reserves some paths ending in "z" and answers
	// them itself, so they never reach the container (docs/VERIFY.md H13).
	PathHealth      = "/health"
	readHeaderLimit = 5 * time.Second
)

// Deps are the server's collaborators. With BaseURL empty the server runs
// in setup mode: only /health works, everything else returns 503. This
// lets the first deployment start before the service URL is known.
type Deps struct {
	BaseURL          string
	OAuth            *oauth.Server
	MCP              *mcp.Server
	Logger           *slog.Logger
	TrustedProxyHops int // proxies that append to X-Forwarded-For (Cloud Run: 1)
}

// Handler returns the root handler.
func Handler(d Deps) http.Handler {
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	mux := http.NewServeMux()
	mux.Handle(PathHealth, logged(d.Logger, "health", http.HandlerFunc(health)))

	if d.BaseURL == "" || d.OAuth == nil || d.MCP == nil {
		mux.Handle("/", logged(d.Logger, "setup", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Service not configured yet: set BASE_URL and redeploy.", http.StatusServiceUnavailable)
		})))
		return secure(d.Logger, false, mux)
	}

	limits := newIPLimiter(rate.Every(2*time.Second), 20, rate.Every(200*time.Millisecond), 60)
	d.OAuth.Register(mux, func(name string, h http.Handler) http.Handler {
		if name == "authorize" || name == "token" {
			h = limitBody(maxOAuthBody, h)
			h = limits.middleware(d.TrustedProxyHops, h)
		}
		return logged(d.Logger, name, h)
	})

	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return d.MCP }, &mcp.StreamableHTTPOptions{
		Stateless:           true, // no sessions: restarts and scale-to-zero lose nothing
		JSONResponse:        true, // one JSON body per POST; no long-lived streams
		Logger:              slog.New(minLevel{d.Logger.Handler(), slog.LevelWarn}),
		MaxRequestBodyBytes: maxMCPBody,
	})
	protected := auth.RequireBearerToken(d.OAuth.VerifyAccessToken, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: d.OAuth.ResourceMetadataURL(),
		Scopes:              []string{oauth.Scope},
	})(mcpHandler)
	mux.Handle(PathMCP, logged(d.Logger, "mcp", limitBody(maxMCPBody, http.NewCrossOriginProtection().Handler(protected))))

	return secure(d.Logger, strings.HasPrefix(d.BaseURL, "https://"), mux)
}

// NewHTTPServer returns an http.Server with conservative timeouts. Tool
// calls take up to 45 s, inside Cloud Run's 60 s request timeout.
func NewHTTPServer(addr string, h http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: readHeaderLimit,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}

func health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

// secure adds security headers and panic recovery to every response.
// Cross-Origin-Opener-Policy is deliberately not set: it would sever the
// popup's opener relation that claude.ai's OAuth flow relies on.
func secure(logger *slog.Logger, https bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if https {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("Cache-Control", "no-store")
		defer func() {
			if p := recover(); p != nil {
				if p == http.ErrAbortHandler {
					panic(p)
				}
				// The panic value may contain request data; not logged.
				logger.Error("handler panic", "component", "http")
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func limitBody(n int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > n {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, n)
		next.ServeHTTP(w, r)
	})
}

// logged writes one line per request: route name, method, status, duration
// and size. Never the path, query (authorization codes!), headers or IP.
func logged(logger *slog.Logger, route string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		level := slog.LevelInfo
		if rec.status >= 500 {
			level = slog.LevelError
		} else if rec.status >= 400 && rec.status != http.StatusUnauthorized {
			level = slog.LevelWarn
		}
		if route == "health" && rec.status == http.StatusOK {
			level = slog.LevelDebug
		}
		logger.LogAttrs(r.Context(), level, "http request",
			slog.String("route", route),
			slog.String("method", r.Method),
			slog.Int("status", rec.status),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
			slog.Int64("bytes", rec.bytes))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status, s.wroteHeader = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach Flush/deadlines.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Flush keeps streaming responses working through the recorder.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
