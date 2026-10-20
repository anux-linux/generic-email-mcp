package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipLimiter combines a token bucket per client IP with a global bucket.
// The per-IP map is bounded; when full, idle entries are dropped and, as a
// last resort, the map is reset (the global bucket still applies).
type ipLimiter struct {
	perRate  rate.Limit
	perBurst int
	global   *rate.Limiter

	mu      sync.Mutex
	clients map[string]*clientLimiter
	max     int
	now     func() time.Time
}

type clientLimiter struct {
	lim  *rate.Limiter
	seen time.Time
}

func newIPLimiter(perRate rate.Limit, perBurst int, globalRate rate.Limit, globalBurst int) *ipLimiter {
	return &ipLimiter{
		perRate: perRate, perBurst: perBurst,
		global:  rate.NewLimiter(globalRate, globalBurst),
		clients: map[string]*clientLimiter{},
		max:     10000,
		now:     time.Now,
	}
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	now := l.now()
	c, ok := l.clients[ip]
	if !ok {
		if len(l.clients) >= l.max {
			for k, v := range l.clients {
				if now.Sub(v.seen) > 10*time.Minute {
					delete(l.clients, k)
				}
			}
			if len(l.clients) >= l.max {
				l.clients = map[string]*clientLimiter{}
			}
		}
		c = &clientLimiter{lim: rate.NewLimiter(l.perRate, l.perBurst)}
		l.clients[ip] = c
	}
	c.seen = now
	okIP := c.lim.AllowN(now, 1)
	l.mu.Unlock()
	return okIP && l.global.AllowN(now, 1)
}

func (l *ipLimiter) middleware(hops int, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r, hops)) {
			w.Header().Set("Retry-After", "10")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP returns the address appended by the hops-th trusted proxy from
// the right of X-Forwarded-For (Cloud Run's front end appends the client
// address), or the TCP peer when there is no such entry. Left-most entries
// are client-controlled and never used.
func clientIP(r *http.Request, hops int) string {
	if hops > 0 {
		var parts []string
		for _, v := range r.Header.Values("X-Forwarded-For") {
			for p := range strings.SplitSeq(v, ",") {
				parts = append(parts, strings.TrimSpace(p))
			}
		}
		if len(parts) >= hops {
			if ip := net.ParseIP(parts[len(parts)-hops]); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// minLevel drops records below min (used for the SDK's chatty logger).
type minLevel struct {
	slog.Handler
	min slog.Level
}

func (h minLevel) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= h.min && h.Handler.Enabled(ctx, l)
}

func (h minLevel) WithAttrs(a []slog.Attr) slog.Handler {
	return minLevel{h.Handler.WithAttrs(a), h.min}
}

func (h minLevel) WithGroup(n string) slog.Handler { return minLevel{h.Handler.WithGroup(n), h.min} }
