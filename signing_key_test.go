package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrepareSigningKeysCreatesAndReusesKeySet(t *testing.T) {
	dataDir := t.TempDir()
	store := newStoreInDir(t, dataDir)
	cfg := Config{}

	if err := prepareSigningKeys(&cfg, store, dataDir, false); err != nil {
		t.Fatalf("prepare signing keys: %v", err)
	}
	if cfg.SigningKeyPEM != "" {
		t.Fatal("SigningKeyPEM should not be populated for managed key sets")
	}
	if len(cfg.SigningKeys) != 1 || !cfg.SigningKeys[0].Active {
		t.Fatalf("managed signing keys = %#v, want one active key", cfg.SigningKeys)
	}
	if cfg.KeyID != cfg.SigningKeys[0].KeyID {
		t.Fatalf("cfg.KeyID = %q, want active key %q", cfg.KeyID, cfg.SigningKeys[0].KeyID)
	}
	keySet := readStoredKeySet(t, store)
	if keySet.ActiveKeyID != cfg.KeyID || len(keySet.Keys) != 1 {
		t.Fatalf("generated key set = %#v, want one active key", keySet)
	}
	requireRSAKeyBits(t, cfg.SigningKeys[0].SigningKeyPEM, 2048)
	requireNoLegacyKeyFile(t, dataDir)

	reloadedCfg := Config{}
	if err := prepareSigningKeys(&reloadedCfg, store, dataDir, false); err != nil {
		t.Fatalf("prepare signing keys again: %v", err)
	}
	if len(reloadedCfg.SigningKeys) != 1 || reloadedCfg.SigningKeys[0].SigningKeyPEM != cfg.SigningKeys[0].SigningKeyPEM {
		t.Fatal("prepareSigningKeys did not reuse the existing key set")
	}
}

func readStoredKeySet(t *testing.T, store *Store) managedSigningKeySet {
	t.Helper()
	keySet, ok, err := store.GetSigningKeySet()
	if err != nil {
		t.Fatalf("read stored key set: %v", err)
	}
	if !ok {
		t.Fatal("expected a signing key set in store, got none")
	}
	return keySet
}

func requireRSAKeyBits(t *testing.T, keyPEM string, bits int) {
	t.Helper()
	key, err := parseRSAPrivateKeyPEM([]byte(keyPEM))
	if err != nil {
		t.Fatalf("parse generated key: %v", err)
	}
	if got := key.N.BitLen(); got != bits {
		t.Fatalf("generated key bits = %d, want %d", got, bits)
	}
}

func requireNoLegacyKeyFile(t *testing.T, dataDir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dataDir, defaultKeysPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy signing-keys.json should not exist after store-backed run: %v", err)
	}
}

func TestPrepareSigningKeysLeavesConfiguredKeyAlone(t *testing.T) {
	dataDir := t.TempDir()
	store := newStoreInDir(t, dataDir)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate configured key: %v", err)
	}
	keyPEM, err := marshalRSAPrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("marshal configured key: %v", err)
	}
	cfg := Config{SigningKeyPEM: string(keyPEM)}

	if err := prepareSigningKeys(&cfg, store, dataDir, false); err != nil {
		t.Fatalf("prepare signing keys: %v", err)
	}
	if cfg.SigningKeyPEM != string(keyPEM) {
		t.Fatal("configured signing key was changed")
	}
	if _, ok, err := store.GetSigningKeySet(); err != nil {
		t.Fatalf("get stored key set: %v", err)
	} else if ok {
		t.Fatal("store should be empty when an operator-configured key is in use")
	}
}

func TestPrepareSigningKeysMigratesLegacyFile(t *testing.T) {
	dataDir := t.TempDir()
	store := newStoreInDir(t, dataDir)

	legacyKey, err := newManagedSigningKey("legacy", time.Now())
	if err != nil {
		t.Fatalf("create legacy key: %v", err)
	}
	legacySet := managedSigningKeySet{ActiveKeyID: legacyKey.KeyID, Keys: []managedSigningKey{legacyKey}}
	legacyPath := filepath.Join(dataDir, defaultKeysPath)
	legacyBytes, err := json.MarshalIndent(legacySet, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy set: %v", err)
	}
	if err := os.WriteFile(legacyPath, legacyBytes, 0o600); err != nil {
		t.Fatalf("write legacy file: %v", err)
	}

	cfg := Config{}
	if err := prepareSigningKeys(&cfg, store, dataDir, false); err != nil {
		t.Fatalf("prepare signing keys: %v", err)
	}

	if cfg.KeyID != legacyKey.KeyID {
		t.Fatalf("cfg.KeyID = %q, want migrated key %q", cfg.KeyID, legacyKey.KeyID)
	}
	stored := readStoredKeySet(t, store)
	if stored.ActiveKeyID != legacyKey.KeyID || len(stored.Keys) != 1 {
		t.Fatalf("stored key set after migration = %#v, want migrated single key", stored)
	}
	if stored.Keys[0].SigningKeyPEM != legacyKey.SigningKeyPEM {
		t.Fatal("migrated PEM does not match original legacy PEM")
	}
	if _, err := os.Stat(legacyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy file should be renamed after migration: %v", err)
	}
	if _, err := os.Stat(legacyPath + ".migrated"); err != nil {
		t.Fatalf("expected renamed legacy file at %s.migrated: %v", legacyPath, err)
	}
}

func TestPrepareSigningKeysRejectsCorruptLegacyFile(t *testing.T) {
	dataDir := t.TempDir()
	store := newStoreInDir(t, dataDir)

	legacyPath := filepath.Join(dataDir, defaultKeysPath)
	if err := os.WriteFile(legacyPath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write corrupt legacy file: %v", err)
	}

	err := prepareSigningKeys(&Config{}, store, dataDir, false)
	if err == nil {
		t.Fatal("prepareSigningKeys accepted a corrupt legacy file")
	}
	if !strings.Contains(err.Error(), defaultKeysPath) {
		t.Fatalf("error %q should mention the legacy file path", err)
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatalf("corrupt legacy file should be left in place for inspection: %v", err)
	}
	if _, ok, err := store.GetSigningKeySet(); err != nil {
		t.Fatalf("get stored key set: %v", err)
	} else if ok {
		t.Fatal("store should remain empty when migration fails")
	}
}

func TestBuildSigningKeySetActiveFlagOverridesKeyID(t *testing.T) {
	oldPEM := mustGeneratedKeyPEM(t)
	newPEM := mustGeneratedKeyPEM(t)

	active, _, _, err := buildSigningKeySet(Config{
		KeyID: "old-key",
		SigningKeys: []SigningKeyConfig{
			{KeyID: "old-key", SigningKeyPEM: oldPEM},
			{KeyID: "new-key", SigningKeyPEM: newPEM, Active: true},
		},
	})
	if err != nil {
		t.Fatalf("build signing key set: %v", err)
	}
	if active.keyID != "new-key" {
		t.Fatalf("active key = %q, want new-key", active.keyID)
	}
}

func TestPrepareSigningKeysRotatesAndKeepsOldJWKSKey(t *testing.T) {
	now := time.Now()
	dataDir := t.TempDir()
	store := newStoreInDir(t, dataDir)
	oldKey, oldToken := seedOldSigningKeySet(t, store, now)

	cfg := Config{
		Issuer:                  "http://broker.example",
		KeyID:                   "test-key",
		SigningKeyRotationDays:  1,
		SigningKeyRetentionDays: 30,
	}
	if err := prepareSigningKeys(&cfg, store, dataDir, false); err != nil {
		t.Fatalf("prepare signing keys: %v", err)
	}
	requireRotatedSigningKeyConfig(t, cfg, oldKey.KeyID)

	broker, err := NewBroker(cfg, mustNewStore(t))
	if err != nil {
		t.Fatalf("create broker: %v", err)
	}
	if _, err := broker.verifyJWT(oldToken); err != nil {
		t.Fatalf("rotated broker should verify old token: %v", err)
	}
	newToken, err := broker.signJWT(map[string]any{
		"iss": "http://broker.example",
		"sub": "johndoe",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	})
	if err != nil {
		t.Fatalf("sign new token: %v", err)
	}
	if kid := jwtHeaderKid(t, newToken); kid != cfg.KeyID {
		t.Fatalf("new token kid = %q, want active key %q", kid, cfg.KeyID)
	}
	if len(broker.publicJWKs) != 2 {
		t.Fatalf("JWKS key count = %d, want 2", len(broker.publicJWKs))
	}
}

func seedOldSigningKeySet(t *testing.T, store *Store, now time.Time) (managedSigningKey, string) {
	t.Helper()
	oldKey, err := newManagedSigningKey("test-key", now.AddDate(0, 0, -2))
	if err != nil {
		t.Fatalf("create old key: %v", err)
	}
	oldSet := managedSigningKeySet{ActiveKeyID: oldKey.KeyID, Keys: []managedSigningKey{oldKey}}
	if err := store.PutSigningKeySet(oldSet); err != nil {
		t.Fatalf("seed old key set: %v", err)
	}
	oldToken := signTestToken(t, oldKey, now)
	return oldKey, oldToken
}

func signTestToken(t *testing.T, key managedSigningKey, now time.Time) string {
	t.Helper()
	broker, err := NewBroker(Config{
		Issuer: "http://broker.example",
		KeyID:  key.KeyID,
		SigningKeys: []SigningKeyConfig{{
			KeyID:         key.KeyID,
			SigningKeyPEM: key.SigningKeyPEM,
			Active:        true,
		}},
	}, mustNewStore(t))
	if err != nil {
		t.Fatalf("create broker: %v", err)
	}
	token, err := broker.signJWT(map[string]any{
		"iss": "http://broker.example",
		"sub": "johndoe",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	})
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

func requireRotatedSigningKeyConfig(t *testing.T, cfg Config, oldKeyID string) {
	t.Helper()
	if len(cfg.SigningKeys) != 2 {
		t.Fatalf("signing keys after rotation = %d, want 2", len(cfg.SigningKeys))
	}
	if cfg.KeyID == oldKeyID {
		t.Fatal("active key was not rotated")
	}
}

func TestResolveDataDirAcceptsDirectory(t *testing.T) {
	dataDir := t.TempDir()
	got, err := resolveDataDir(dataDir)
	if err != nil {
		t.Fatalf("resolve data dir: %v", err)
	}
	if got != dataDir {
		t.Fatalf("data dir = %q, want %q", got, dataDir)
	}
}

func TestResolveDataDirAcceptsMissingDirectory(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "authbroker-data")
	got, err := resolveDataDir(dataDir)
	if err != nil {
		t.Fatalf("resolve data dir: %v", err)
	}
	if got != dataDir {
		t.Fatalf("data dir = %q, want %q", got, dataDir)
	}
}

func TestResolveDataDirRejectsFile(t *testing.T) {
	dataPath := filepath.Join(t.TempDir(), "data.json")
	if err := os.WriteFile(dataPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write data file: %v", err)
	}
	if _, err := resolveDataDir(dataPath); err == nil {
		t.Fatal("resolveDataDir accepted a file path")
	}
}

func mustNewStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), defaultDataFile)
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func newStoreInDir(t *testing.T, dataDir string) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(dataDir, defaultDataFile))
	if err != nil {
		t.Fatalf("create store in %s: %v", dataDir, err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func mustGeneratedKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPEM, err := marshalRSAPrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return string(keyPEM)
}

func jwtHeaderKid(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed jwt %q", token)
	}
	headerBytes, err := decodeB64URL(parts[0])
	if err != nil {
		t.Fatalf("decode jwt header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("parse jwt header: %v", err)
	}
	kid, _ := header["kid"].(string)
	return kid
}
