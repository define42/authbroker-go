package main

import (
	"fmt"
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

// allowAndRecord is the "every call counts" variant of allow: when the key
// is not locked, it returns (true, 0) AND immediately records a failure so
// the bucket fills under burst load even though the request itself did not
// fail in the usual sense. Use this from preauth write paths (authorize,
// webauthn login begin, login GET) where unauthenticated callers can
// otherwise spam the underlying store without ever tripping the limiter.
// Callers that DO have a notion of success/failure should keep using
// allow() + recordFailure()/recordSuccess() so a legitimate login can
// reset the bucket.
func (l *loginRateLimiter) allowAndRecord(key string) (bool, time.Duration) {
	if l == nil || key == "" {
		return true, 0
	}
	allowed, retry := l.allow(key)
	if !allowed {
		return false, retry
	}
	l.recordFailure(key)
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

type trustedProxySet struct {
	nets []*net.IPNet
}

func newTrustedProxySet(values []string) (trustedProxySet, error) {
	set := trustedProxySet{}
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "/") {
			_, ipNet, err := net.ParseCIDR(raw)
			if err != nil {
				return trustedProxySet{}, fmt.Errorf("trusted proxy %q: %w", raw, err)
			}
			set.nets = append(set.nets, ipNet)
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			return trustedProxySet{}, fmt.Errorf("trusted proxy %q is not an IP or CIDR", raw)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		set.nets = append(set.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return set, nil
}

func (s trustedProxySet) empty() bool {
	return len(s.nets) == 0
}

func (s trustedProxySet) containsString(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return false
	}
	for _, ipNet := range s.nets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func (b *Broker) clientIP(r *http.Request) string {
	remote := clientIP(r)
	if b == nil || r == nil || b.proxies.empty() || !b.proxies.containsString(remote) {
		return remote
	}
	if ip := clientIPFromTrustedChain(r.Header.Get(b.cfg.ClientIPHeader), b.proxies); ip != "" {
		return ip
	}
	return remote
}

// clientIPFromTrustedChain returns the rightmost header entry that is NOT a
// trusted proxy. Trusted hops appended to X-Forwarded-For are stripped from
// the right, and the first untrusted entry left is the real client. Taking
// the leftmost entry instead would be spoofable: most proxies append rather
// than replace the header, so an attacker can prepend any value and have it
// surface as the client IP.
//
// Entries may carry a port suffix (Caddy appends host:port for example).
// parseIPEntry handles both bare IPs and host:port forms so a multi-hop chain
// doesn't silently skip the legitimate proxy entry and fall through to the
// leftmost parseable IP.
func clientIPFromTrustedChain(value string, trusted trustedProxySet) string {
	parts := strings.Split(value, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		raw := parseIPEntry(parts[i])
		if raw == "" {
			continue
		}
		if trusted.containsString(raw) {
			continue
		}
		return raw
	}
	// All header entries are trusted proxies (or unparseable). Surface the
	// leftmost parseable entry — by XFF convention that is the original
	// client, even though it ended up inside our trusted set.
	for _, part := range parts {
		if ip := parseIPEntry(part); ip != "" {
			return ip
		}
	}
	return ""
}

// parseIPEntry accepts either a bare IP or a host:port form (with IPv6
// addresses optionally bracketed) and returns the canonical IP literal, or ""
// if the entry is not parseable.
func parseIPEntry(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if ip := net.ParseIP(raw); ip != nil {
		return raw
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		host = strings.Trim(strings.TrimSpace(host), "[]")
		if ip := net.ParseIP(host); ip != nil {
			return host
		}
	}
	return ""
}
