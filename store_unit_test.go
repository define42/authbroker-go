package main

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), defaultDataFile))
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestStoreRejectsEmptyPath(t *testing.T) {
	if _, err := NewStore(""); err == nil {
		t.Fatal("NewStore must reject empty path")
	}
}

func TestStoreSetTOTP(t *testing.T) {
	store := newTestStore(t)
	if err := store.SetTOTP("alice", "ABC123"); err != nil {
		t.Fatalf("SetTOTP new user: %v", err)
	}
	user, ok := store.GetUser("alice")
	if !ok || user.TOTPSecretBase32 != "ABC123" {
		t.Fatalf("after SetTOTP: user=%#v ok=%v", user, ok)
	}
	if err := store.SetTOTP("alice", "XYZ456"); err != nil {
		t.Fatalf("SetTOTP overwrite: %v", err)
	}
	user, _ = store.GetUser("alice")
	if user.TOTPSecretBase32 != "XYZ456" {
		t.Fatalf("TOTP overwrite = %q", user.TOTPSecretBase32)
	}
}

//nolint:gocognit,cyclop // Test exercises the full lifecycle in one function on purpose.
func TestStorePendingTOTPLifecycle(t *testing.T) {
	store := newTestStore(t)
	if err := store.SetPendingTOTP("alice", "PENDING1"); err != nil {
		t.Fatalf("SetPendingTOTP: %v", err)
	}
	user, _ := store.GetUser("alice")
	if user.PendingTOTPSecretBase32 != "PENDING1" {
		t.Fatalf("pending = %q", user.PendingTOTPSecretBase32)
	}
	if user.TOTPSecretBase32 != "" {
		t.Fatalf("active should be empty, got %q", user.TOTPSecretBase32)
	}
	if err := store.CommitPendingTOTP("alice"); err != nil {
		t.Fatalf("CommitPendingTOTP: %v", err)
	}
	user, _ = store.GetUser("alice")
	if user.TOTPSecretBase32 != "PENDING1" {
		t.Fatalf("active after commit = %q", user.TOTPSecretBase32)
	}
	if user.PendingTOTPSecretBase32 != "" {
		t.Fatalf("pending should be cleared, got %q", user.PendingTOTPSecretBase32)
	}
	if err := store.CommitPendingTOTP("alice"); err == nil {
		t.Fatal("CommitPendingTOTP without pending must fail")
	}

	if err := store.SetPendingTOTP("alice", "PENDING2"); err != nil {
		t.Fatalf("SetPendingTOTP again: %v", err)
	}
	if err := store.ClearPendingTOTP("alice"); err != nil {
		t.Fatalf("ClearPendingTOTP: %v", err)
	}
	user, _ = store.GetUser("alice")
	if user.PendingTOTPSecretBase32 != "" {
		t.Fatal("pending should be cleared after ClearPendingTOTP")
	}
	if user.TOTPSecretBase32 != "PENDING1" {
		t.Fatalf("active should be preserved, got %q", user.TOTPSecretBase32)
	}
	if err := store.SetTOTP("alice", "FINAL"); err != nil {
		t.Fatalf("SetTOTP after lifecycle: %v", err)
	}
	if err := store.SetPendingTOTP("alice", "DANGLE"); err != nil {
		t.Fatalf("seed dangling pending: %v", err)
	}
	if err := store.SetTOTP("alice", "FINAL2"); err != nil {
		t.Fatalf("SetTOTP must clear dangling pending: %v", err)
	}
	user, _ = store.GetUser("alice")
	if user.PendingTOTPSecretBase32 != "" {
		t.Fatalf("SetTOTP should clear pending, got %q", user.PendingTOTPSecretBase32)
	}
	if user.TOTPSecretBase32 != "FINAL2" {
		t.Fatalf("active = %q", user.TOTPSecretBase32)
	}
}

func TestStoreAddWebAuthnCredential(t *testing.T) {
	store := newTestStore(t)
	cred := WebAuthnCredential{IDBase64URL: "cred-1", Alg: "ES256"}
	if err := store.AddWebAuthnCredential("bob", cred); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := store.AddWebAuthnCredential("bob", cred); err == nil {
		t.Fatal("duplicate add should fail")
	}
	if err := store.AddWebAuthnCredential("bob", WebAuthnCredential{IDBase64URL: "cred-2"}); err != nil {
		t.Fatalf("second cred add: %v", err)
	}
	user, _ := store.GetUser("bob")
	if len(user.WebAuthnCredentials) != 2 {
		t.Fatalf("got %d creds", len(user.WebAuthnCredentials))
	}
}

func TestStoreUpdateWebAuthnSignCount(t *testing.T) {
	store := newTestStore(t)
	if err := store.UpdateWebAuthnSignCount("ghost", "id", 1); err == nil {
		t.Fatal("missing user should error")
	}
	cred := WebAuthnCredential{IDBase64URL: "cred-1", Alg: "ES256", SignCount: 5}
	if err := store.AddWebAuthnCredential("carol", cred); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := store.UpdateWebAuthnSignCount("carol", "missing", 9); err == nil {
		t.Fatal("missing credential should error")
	}
	if err := store.UpdateWebAuthnSignCount("carol", "cred-1", 9); err != nil {
		t.Fatalf("update: %v", err)
	}
	user, _ := store.GetUser("carol")
	if user.WebAuthnCredentials[0].SignCount != 9 {
		t.Fatalf("sign count = %d", user.WebAuthnCredentials[0].SignCount)
	}
}

func TestStoreRefreshTokenRoundTrip(t *testing.T) {
	store := newTestStore(t)
	rt := RefreshToken{UserID: "u", ClientID: "c", Scope: "openid", ExpiresAt: time.Now().Add(time.Hour)}
	if err := store.PutRefreshToken("k", rt); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, ok, err := store.GetRefreshToken("k")
	if err != nil || !ok || got.UserID != "u" {
		t.Fatalf("get: %#v ok=%v err=%v", got, ok, err)
	}
	deleted, err := store.DeleteRefreshToken("k")
	if err != nil || !deleted {
		t.Fatalf("delete: deleted=%v err=%v", deleted, err)
	}
	deleted, err = store.DeleteRefreshToken("k")
	if err != nil || deleted {
		t.Fatalf("second delete: deleted=%v err=%v", deleted, err)
	}
	if _, ok, _ := store.GetRefreshToken("missing"); ok {
		t.Fatal("missing key should return ok=false")
	}
}

func TestStoreRevokedJTI(t *testing.T) {
	store := newTestStore(t)
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if err := store.PutRevokedJTI("jti", exp); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, ok, err := store.GetRevokedJTI("jti")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if !got.Equal(exp) {
		t.Fatalf("got %v want %v", got, exp)
	}
	if err := store.DeleteRevokedJTI("jti"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok, _ := store.GetRevokedJTI("jti"); ok {
		t.Fatal("entry should be gone")
	}
}

func TestStoreWebAuthnChallenges(t *testing.T) {
	store := newTestStore(t)
	rec := ChallengeRecord{UserID: "u", Challenge: "abc", ExpiresAt: time.Now().Add(time.Minute)}
	if err := store.PutWebAuthnRegistration("abc", rec); err != nil {
		t.Fatalf("put reg: %v", err)
	}
	got, ok, err := store.ConsumeWebAuthnRegistration("abc")
	if err != nil || !ok || got.UserID != "u" {
		t.Fatalf("consume reg: got=%#v ok=%v err=%v", got, ok, err)
	}
	// Idempotent consume returns ok=false.
	if _, ok, _ := store.ConsumeWebAuthnRegistration("abc"); ok {
		t.Fatal("second consume should return ok=false")
	}

	if err := store.PutWebAuthnLogin("login-1", rec); err != nil {
		t.Fatalf("put login: %v", err)
	}
	got, ok, err = store.ConsumeWebAuthnLogin("login-1")
	if err != nil || !ok || got.UserID != "u" {
		t.Fatalf("consume login: got=%#v ok=%v err=%v", got, ok, err)
	}
}

func TestStoreSweepExpiredAcrossBuckets(t *testing.T) {
	store := newTestStore(t)
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	if err := store.PutSession("expired", Session{UserID: "u", ExpiresAt: past}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if err := store.PutSession("active", Session{UserID: "u", ExpiresAt: future}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if err := store.PutRefreshToken("expired", RefreshToken{ExpiresAt: past}); err != nil {
		t.Fatalf("seed refresh: %v", err)
	}
	if err := store.PutRevokedJTI("expired", past); err != nil {
		t.Fatalf("seed jti: %v", err)
	}
	if err := store.PutWebAuthnLogin("expired", ChallengeRecord{ExpiresAt: past}); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}

	removed, err := store.SweepExpired(time.Now())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if removed < 4 {
		t.Fatalf("removed = %d, want >=4", removed)
	}
	snap := store.RuntimeSnapshot()
	if _, ok := snap.Sessions["expired"]; ok {
		t.Fatal("expired session survived sweep")
	}
	if _, ok := snap.Sessions["active"]; !ok {
		t.Fatal("active session was swept")
	}
}

func TestHashSecretStable(t *testing.T) {
	a := hashSecret("token-1")
	b := hashSecret("token-1")
	if a != b || len(a) != 64 {
		t.Fatalf("hashSecret unstable or wrong len: %q %q", a, b)
	}
	if hashSecret("token-1") == hashSecret("token-2") {
		t.Fatal("distinct inputs collided")
	}
}

func TestCloseHandlesNil(t *testing.T) {
	var s *Store
	if err := s.Close(); err != nil {
		t.Fatalf("nil close returned %v", err)
	}
}

func TestStoreUpsertProfileRefreshesDirectoryFields(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.UpsertProfile(UserProfile{Subject: "p", Email: "p@e", Name: "P", Groups: []string{"old"}}); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if err := store.SetTOTP("p", "SECRET"); err != nil {
		t.Fatalf("set totp: %v", err)
	}
	if _, err := store.UpsertProfile(UserProfile{Subject: "p"}); err != nil {
		t.Fatalf("merge upsert: %v", err)
	}
	user, _ := store.GetUser("p")
	if user.Email != "" || user.Name != "" || len(user.Groups) != 0 {
		t.Fatalf("directory fields were not refreshed: %#v", user)
	}
	if user.TOTPSecretBase32 != "SECRET" {
		t.Fatalf("totp secret should be preserved, got %#v", user)
	}
}
