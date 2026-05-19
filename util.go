package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

func randomB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64RawURL(b)
}

func base64RawURL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeB64URL(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty base64url")
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func normalizeChallenge(ch string) string {
	b, err := decodeB64URL(ch)
	if err != nil {
		return ch
	}
	return base64RawURL(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// loadRootCAs reads a PEM file containing one or more root certificates and
// returns a *x509.CertPool seeded with the system roots plus those certs. If
// path is empty, returns (nil, nil) — callers should leave RootCAs unset so
// the system pool is used.
func loadRootCAs(path string) (*x509.CertPool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	pem, err := readOperatorFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ca cert %q: %w", path, err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certificates parsed from %q", path)
	}
	return pool, nil
}

// readOperatorFile reads a file whose path was supplied by the local operator
// (CLI flag, env var, or JSON config). The single nolint:gosec annotation here
// covers every caller so the justification lives in one place.
func readOperatorFile(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // path is supplied by the local operator.
}

func uniqueNonEmpty(values ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
