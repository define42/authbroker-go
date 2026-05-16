package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
			"code": {Code: "code", UserID: "johndoe", ClientID: "demo-web", RedirectURI: "http://app.example/callback", ExpiresAt: now.Add(time.Minute)},
		},
		RefreshTokens: map[string]RefreshToken{
			"refresh": {Token: "refresh", UserID: "johndoe", ClientID: "demo-web", Scope: "openid", AuthTime: now, ExpiresAt: now.Add(time.Hour)},
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
	if got := broker.authCodes["code"].UserID; got != "johndoe" {
		t.Fatalf("loaded authorization code user = %q, want johndoe", got)
	}
	if got := broker.refresh["refresh"].Scope; got != "openid" {
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
	sess, err := broker.createSession(sessionRecorder, "johndoe")
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

func TestSharedStorePreservesRuntimeMutationsAcrossBrokers(t *testing.T) {
	path := filepath.Join(t.TempDir(), defaultDataFile)
	brokerA := mustNewDurableBroker(t, path)
	brokerB := mustNewDurableBroker(t, path)

	if _, err := brokerA.createSession(httptest.NewRecorder(), "alice"); err != nil {
		t.Fatalf("broker A create session: %v", err)
	}
	if _, err := brokerB.createSession(httptest.NewRecorder(), "bob"); err != nil {
		t.Fatalf("broker B create session: %v", err)
	}

	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatalf("reload shared store: %v", err)
	}
	state := reloaded.RuntimeState()
	if len(state.Sessions) != 2 {
		t.Fatalf("shared sessions = %d, want 2", len(state.Sessions))
	}
}

func TestSharedStoreConsumesAuthorizationCodeOnceAcrossBrokers(t *testing.T) {
	path := filepath.Join(t.TempDir(), defaultDataFile)
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if _, err := store.UpsertProfile(UserProfile{Subject: "alice"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	brokerA := mustNewDurableBrokerWithStore(t, store)
	brokerB := mustNewDurableBroker(t, path)
	now := time.Now()
	if err := store.ReplaceRuntimeState(StoredRuntimeState{
		AuthCodes: map[string]AuthCode{
			"shared-code": {
				Code:        "shared-code",
				UserID:      "alice",
				ClientID:    "demo-web",
				RedirectURI: "http://app.example/callback",
				Scope:       "openid",
				AuthTime:    now,
				ExpiresAt:   now.Add(time.Minute),
			},
		},
	}); err != nil {
		t.Fatalf("seed authorization code: %v", err)
	}

	first := httptest.NewRecorder()
	brokerA.tokenAuthorizationCode(first, tokenRequest(t, "shared-code"), Client{ClientID: "demo-web"})
	if first.Code != 0 && first.Code != 200 {
		t.Fatalf("first code exchange status = %d, want 200", first.Code)
	}

	second := httptest.NewRecorder()
	brokerB.tokenAuthorizationCode(second, tokenRequest(t, "shared-code"), Client{ClientID: "demo-web"})
	if second.Code != 400 {
		t.Fatalf("second code exchange status = %d, want 400", second.Code)
	}
}

func TestSharedStoreMergesUserUpdatesAcrossStores(t *testing.T) {
	path := filepath.Join(t.TempDir(), defaultDataFile)
	storeA, err := NewStore(path)
	if err != nil {
		t.Fatalf("create store A: %v", err)
	}
	storeB, err := NewStore(path)
	if err != nil {
		t.Fatalf("create store B: %v", err)
	}

	if _, err := storeA.UpsertProfile(UserProfile{Subject: "alice", Email: "alice@example.com"}); err != nil {
		t.Fatalf("store A upsert profile: %v", err)
	}
	if err := storeB.SetTOTP("alice", "SECRET"); err != nil {
		t.Fatalf("store B set totp: %v", err)
	}

	user, ok := storeA.GetUser("alice")
	if !ok {
		t.Fatal("shared user was not found")
	}
	if user.Email != "alice@example.com" || user.TOTPSecretBase32 != "SECRET" {
		t.Fatalf("shared user = %#v, want email and totp from both stores", user)
	}
}

func TestSharedStorePersistsWebAuthnLoginChallenges(t *testing.T) {
	path := filepath.Join(t.TempDir(), defaultDataFile)
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if _, err := store.UpsertProfile(UserProfile{Subject: "alice"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	brokerA := mustNewDurableBrokerWithStore(t, store)
	brokerB := mustNewDurableBroker(t, path)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/webauthn/login/begin", strings.NewReader(`{"username":"alice"}`))
	brokerA.handleWebAuthnLoginBegin(recorder, req)
	if recorder.Code != 200 {
		t.Fatalf("webauthn login begin status = %d, want 200", recorder.Code)
	}
	state := store.RuntimeState()
	if len(state.WebAuthnLog) != 1 {
		t.Fatalf("shared webauthn login challenges = %d, want 1", len(state.WebAuthnLog))
	}

	brokerB.sweepExpired(time.Now().Add(10 * time.Minute))
	state = store.RuntimeState()
	if len(state.WebAuthnLog) != 0 {
		t.Fatalf("expired shared webauthn login challenges = %d, want 0", len(state.WebAuthnLog))
	}
}

func mustNewDurableBroker(t *testing.T, path string) *Broker {
	t.Helper()
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	return mustNewDurableBrokerWithStore(t, store)
}

func mustNewDurableBrokerWithStore(t *testing.T, store *Store) *Broker {
	t.Helper()
	broker, err := NewBroker(Config{
		Issuer:        "http://broker.example",
		KeyID:         "test-key",
		SigningKeyPEM: mustGeneratedKeyPEM(t),
	}, store)
	if err != nil {
		t.Fatalf("create broker: %v", err)
	}
	return broker
}

func tokenRequest(t *testing.T, code string) *http.Request {
	t.Helper()
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader("code="+code+"&redirect_uri=http%3A%2F%2Fapp.example%2Fcallback"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("parse token form: %v", err)
	}
	return req
}
