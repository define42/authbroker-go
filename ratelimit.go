package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// loginRateLimiter throttles authentication endpoints (login, webauthn login
// finish) and applies a per-key lockout when too many failures accumulate.
// It is an in-memory limiter — the broker runs as a single instance.
type loginRateLimiter struct {
	mu sync.Mutex

	window      time.Duration
	maxAttempts int
	lockout     time.Duration

	entries map[string]*loginRateEntry
	now     func() time.Time
}

type loginRateEntry struct {
	failures    []time.Time
	lockedUntil time.Time
}

func newLoginRateLimiter(window time.Duration, maxAttempts int, lockout time.Duration) *loginRateLimiter {
	return &loginRateLimiter{
		window:      window,
		maxAttempts: maxAttempts,
		lockout:     lockout,
		entries:     map[string]*loginRateEntry{},
		now:         time.Now,
	}
}

// allow returns (true, 0) if the key may attempt now. If the key is currently
// locked out, allow returns (false, retryAfter) so the caller can surface
// Retry-After. The check itself does not consume a slot — callers must call
// recordFailure on auth failure to advance the limiter, and recordSuccess on
// success to reset.
func (l *loginRateLimiter) allow(key string) (bool, time.Duration) {
	if l == nil || key == "" {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry := l.entries[key]
	if entry == nil {
		return true, 0
	}
	if !entry.lockedUntil.IsZero() && now.Before(entry.lockedUntil) {
		return false, entry.lockedUntil.Sub(now)
	}
	if !entry.lockedUntil.IsZero() && !now.Before(entry.lockedUntil) {
		entry.lockedUntil = time.Time{}
		entry.failures = entry.failures[:0]
	}
	return true, 0
}

func (l *loginRateLimiter) recordFailure(key string) {
	if l == nil || key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry := l.entries[key]
	if entry == nil {
		entry = &loginRateEntry{}
		l.entries[key] = entry
	}
	cutoff := now.Add(-l.window)
	kept := entry.failures[:0]
	for _, t := range entry.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	entry.failures = kept
	entry.failures = append(entry.failures, now)
	if len(entry.failures) >= l.maxAttempts {
		entry.lockedUntil = now.Add(l.lockout)
	}
}

func (l *loginRateLimiter) recordSuccess(key string) {
	if l == nil || key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// sweep removes entries with no recent activity. Called periodically by the
// background sweeper to bound memory usage.
func (l *loginRateLimiter) sweep(now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.window)
	for key, entry := range l.entries {
		if !entry.lockedUntil.IsZero() && now.Before(entry.lockedUntil) {
			continue
		}
		hasRecent := false
		for _, t := range entry.failures {
			if t.After(cutoff) {
				hasRecent = true
				break
			}
		}
		if !hasRecent {
			delete(l.entries, key)
		}
	}
}

// clientIP extracts the best-effort caller IP. Trusts no proxy headers by
// default; deployments behind a known reverse proxy must terminate TLS and
// forward via a header that the operator wires into a separate middleware.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}
