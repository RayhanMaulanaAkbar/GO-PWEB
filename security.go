package main

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// ---------- Login rate limiter ----------

// limiter remembers recent failed logins per key.
type limiter struct {
	mu     sync.Mutex
	fails  map[string][]time.Time
	max    int
	window time.Duration
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{
		fails:  map[string][]time.Time{},
		max:    max,
		window: window,
	}
}

// recent returns failures still inside the window.
func (l *limiter) recent(key string, now time.Time) []time.Time {
	var keep []time.Time

	for _, t := range l.fails[key] {
		if now.Sub(t) < l.window {
			keep = append(keep, t)
		}
	}

	if len(keep) == 0 {
		delete(l.fails, key)
	} else {
		l.fails[key] = keep
	}

	return keep
}

// blocked returns how long the caller must wait.
func (l *limiter) blocked(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	list := l.recent(key, now)

	if len(list) < l.max {
		return 0
	}

	return list[0].Add(l.window).Sub(now)
}

func (l *limiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.fails[key] = append(l.fails[key], time.Now())
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.fails, key)
}

// 5 wrong passwords per minute per IP address.
var loginLimiter = newLimiter(5, time.Minute)

// clientIP returns the address of the caller.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)

	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// ---------- Middleware wrapped around the whole app ----------

// securityHeaders adds protective headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")

		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "+
				"style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "+
				"frame-ancestors 'none'")

		next.ServeHTTP(w, r)
	})
}

// limitBody refuses request bodies larger than 1 MB.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(w, r)
	})
}
