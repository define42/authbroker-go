package main

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestBrokerLoadsDurableRuntimeState(t *testing.T) {
	path := filepath.Join(t.TempDir(), defaultDataFile)
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	state := StoredRuntimeState{
		Sessions: map[string]Session{
			"sid": {UserID: "johndoe", ExpiresAt: now.Add(time.Hour), AuthTime: now},
		},
		AuthRequests: map[string]AuthorizationRequest{
			"rid": {ID: "rid", ClientID: "demo-web", RedirectURI: "http://app.example/callback", ExpiresAt: now.Add(time.Minute)},
		},
		AuthCodes: map[string]AuthCode{
			hashSecret("code"): {UserID: "johndoe", ClientID: "demo-web", RedirectURI: "http://app.example/callback", ExpiresAt: now.Add(time.Minute)},
		},
		RefreshTokens: map[string]RefreshToken{
			hashSecret("refresh"): {UserID: "johndoe", ClientID: "demo-web", Scope: "openid", AuthTime: now, ExpiresAt: now.Add(time.Hour)},
		},
		RevokedJTIs: map[string]time.Time{
			"jti": now.Add(time.Hour),
		},
	}
	if err := store.ReplaceRuntimeState(state); err != nil {
		t.Fatalf("persist runtime state: %v", err)
	}

	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatalf("reload store: %v", err)
	}
	broker, err := NewBroker(Config{
		Issuer:        "http://broker.example",
		KeyID:         "test-key",
		SigningKeyPEM: mustGeneratedKeyPEM(t),
	}, reloaded)
	if err != nil {
		t.Fatalf("create broker: %v", err)
	}

	if got := broker.sessions["sid"].UserID; got != "johndoe" {
		t.Fatalf("loaded session user = %q, want johndoe", got)
	}
	if _, ok := broker.authRequests["rid"]; !ok {
		t.Fatal("authorization request was not loaded")
	}
	if got := broker.authCodes[hashSecret("code")].UserID; got != "johndoe" {
		t.Fatalf("loaded authorization code user = %q, want johndoe", got)
	}
	if got := broker.refresh[hashSecret("refresh")].Scope; got != "openid" {
		t.Fatalf("loaded refresh token scope = %q, want openid", got)
	}
	if _, ok := broker.revokedJTIs["jti"]; !ok {
		t.Fatal("revoked token id was not loaded")
	}
}

func TestBrokerPersistsRuntimeStateMutations(t *testing.T) {
	path := filepath.Join(t.TempDir(), defaultDataFile)
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	broker, err := NewBroker(Config{
		Issuer:        "http://broker.example",
		KeyID:         "test-key",
		SigningKeyPEM: mustGeneratedKeyPEM(t),
	}, store)
	if err != nil {
		t.Fatalf("create broker: %v", err)
	}

	sessionRecorder := httptest.NewRecorder()
	sess, err := broker.createSession(sessionRecorder, "johndoe", true)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	authReq := AuthorizationRequest{
		ClientID:    "demo-web",
		RedirectURI: "http://app.example/callback",
		Scope:       "openid offline_access",
		ExpiresAt:   time.Now().Add(time.Minute),
	}
	redirectRecorder := httptest.NewRecorder()
	redirectReq := httptest.NewRequest("GET", "/oauth2/authorize", nil)
	if err := broker.issueCodeRedirect(redirectRecorder, redirectReq, authReq, sess); err != nil {
		t.Fatalf("issue code redirect: %v", err)
	}
	if _, err := broker.issueUserTokens("johndoe", "demo-web", "openid offline_access", "", sess.AuthTime, true); err != nil {
		t.Fatalf("issue user tokens: %v", err)
	}

	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatalf("reload store: %v", err)
	}
	state := reloaded.RuntimeState()
	if len(state.Sessions) != 1 {
		t.Fatalf("persisted sessions = %d, want 1", len(state.Sessions))
	}
	if len(state.AuthCodes) != 1 {
		t.Fatalf("persisted authorization codes = %d, want 1", len(state.AuthCodes))
	}
	if len(state.RefreshTokens) != 1 {
		t.Fatalf("persisted refresh tokens = %d, want 1", len(state.RefreshTokens))
	}
}

