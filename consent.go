package main

import (
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// consentRequestExpiry is how long a pending AuthorizationRequest sits in the
// store after we redirect the user to /consent, before we drop it. Long enough
// for a human to read the prompt; short enough that abandoned grants do not
// accumulate.
const consentRequestExpiry = 5 * time.Minute

// proceedAfterAuthn is the post-authentication branch of the authorize flow.
// It either redirects to the consent page (when the client requires consent
// and the user has not yet approved every requested scope) or completes the
// grant by issuing an authorization code. handleAuthorize and handleLoginPost
// both funnel through here so the consent gate lives in one place.
func (b *Broker) proceedAfterAuthn(w http.ResponseWriter, r *http.Request, ar AuthorizationRequest, sess Session) error {
	client, ok := b.lookupClient(ar.ClientID)
	if !ok {
		// Client may have been deleted between authorize and login. Fail
		// closed.
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return nil
	}
	if !client.RequireConsent {
		return b.issueCodeRedirect(w, r, ar, sess)
	}
	rec, found, err := b.store.GetConsent(sess.UserID, client.ClientID)
	if err != nil {
		return err
	}
	if found && consentCovers(rec, requestedScopeList(ar.Scope)) {
		return b.issueCodeRedirect(w, r, ar, sess)
	}

	// Re-stash the AR so the consent endpoint can consume it on submit. The
	// AR ID is unguessable (32 random bytes) so leaking it in a redirect URL
	// does not expose other users' pending grants.
	ar.ExpiresAt = time.Now().Add(consentRequestExpiry)
	if err := b.putAuthRequest(ar); err != nil {
		return err
	}
	http.Redirect(w, r, "/consent?request_id="+url.QueryEscape(ar.ID), http.StatusFound)
	return nil
}

func (b *Broker) handleConsentGet(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.validSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	rid := strings.TrimSpace(r.URL.Query().Get("request_id"))
	if rid == "" {
		http.Error(w, "missing request_id", http.StatusBadRequest)
		return
	}
	ar, ok, err := b.store.GetAuthRequest(rid)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if !ok || time.Now().After(ar.ExpiresAt) {
		http.Error(w, "consent request expired", http.StatusBadRequest)
		return
	}
	client, ok := b.lookupClient(ar.ClientID)
	if !ok {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consentTemplate.Execute(w, map[string]any{
		"DisplayName": b.cfg.DisplayName,
		"ClientID":    client.ClientID,
		"RequestID":   ar.ID,
		"Scopes":      requestedScopeList(ar.Scope),
		"UserID":      sess.UserID,
		"CSRFToken":   sess.CSRFToken,
	})
}

//nolint:funlen // Consent POST validates the AR, records the grant, and audits — splitting would obscure the linear flow.
func (b *Broker) handleConsentPost(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.validSession(r)
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !verifySessionCSRF(r, sess) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	rid := strings.TrimSpace(r.Form.Get("request_id"))
	if rid == "" {
		http.Error(w, "missing request_id", http.StatusBadRequest)
		return
	}
	ar, ok, err := b.store.ConsumeAuthRequest(rid)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if !ok || time.Now().After(ar.ExpiresAt) {
		http.Error(w, "consent request expired", http.StatusBadRequest)
		return
	}

	decision := r.Form.Get("decision")
	if decision != "approve" {
		b.auditEvent(r, auditEventConsent, auditOutcomeFailure,
			slog.String("user_id", sess.UserID),
			slog.String("client_id", ar.ClientID),
			slog.String("reason", "denied"))
		redirectOAuthError(w, r, ar.RedirectURI, ar.State, "access_denied", "user denied consent")
		return
	}

	scopes := requestedScopeList(ar.Scope)
	merged := scopes
	if existing, found, _ := b.store.GetConsent(sess.UserID, ar.ClientID); found {
		merged = mergeScopeSets(existing.Scopes, scopes)
	}
	consent := ConsentRecord{
		UserID:    sess.UserID,
		ClientID:  ar.ClientID,
		Scopes:    merged,
		GrantedAt: time.Now(),
	}
	if err := b.store.PutConsent(consent); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	b.auditEvent(r, auditEventConsent, auditOutcomeSuccess,
		slog.String("user_id", sess.UserID),
		slog.String("client_id", ar.ClientID),
		slog.String("scope", strings.Join(scopes, " ")))
	if err := b.issueCodeRedirect(w, r, ar, sess); err != nil {
		log.Printf("issue code after consent: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
	}
}

func requestedScopeList(scope string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range strings.Fields(scope) {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// consentCovers reports whether every scope in want is present in rec.Scopes.
// When a client later requests an additional scope, this returns false so the
// user is prompted again for the delta.
func consentCovers(rec ConsentRecord, want []string) bool {
	granted := map[string]bool{}
	for _, s := range rec.Scopes {
		granted[s] = true
	}
	for _, s := range want {
		if !granted[s] {
			return false
		}
	}
	return true
}

func mergeScopeSets(a, b []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
