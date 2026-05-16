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
	cfg := Config{}

	if err := prepareSigningKeys(&cfg, dataDir, false); err != nil {
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
	keySetPath := filepath.Join(dataDir, defaultKeysPath)
	keySetBytes, err := os.ReadFile(keySetPath)
	if err != nil {
		t.Fatalf("read generated key set: %v", err)
	}
	var keySet managedSigningKeySet
	if err := json.Unmarshal(keySetBytes, &keySet); err != nil {
		t.Fatalf("decode generated key set: %v", err)
	}
	if keySet.ActiveKeyID != cfg.KeyID || len(keySet.Keys) != 1 {
		t.Fatalf("generated key set = %#v, want one active key", keySet)
	}
	key, err := parseRSAPrivateKeyPEM([]byte(cfg.SigningKeys[0].SigningKeyPEM))
	if err != nil {
		t.Fatalf("parse generated key: %v", err)
	}
	if got := key.N.BitLen(); got != 2048 {
		t.Fatalf("generated key bits = %d, want 2048", got)
	}
	info, err := os.Stat(keySetPath)
	if err != nil {
		t.Fatalf("stat generated key set: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("generated key set permissions = %v, want no group/world access", mode)
	}

	reloadedCfg := Config{}
	if err := prepareSigningKeys(&reloadedCfg, dataDir, false); err != nil {
		t.Fatalf("prepare signing keys again: %v", err)
	}
	if len(reloadedCfg.SigningKeys) != 1 || reloadedCfg.SigningKeys[0].SigningKeyPEM != cfg.SigningKeys[0].SigningKeyPEM {
		t.Fatal("prepareSigningKeys did not reuse the existing key set")
	}
}

func TestPrepareSigningKeysLeavesConfiguredKeyAlone(t *testing.T) {
	dataDir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate configured key: %v", err)
	}
	keyPEM, err := marshalRSAPrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("marshal configured key: %v", err)
	}
	cfg := Config{SigningKeyPEM: string(keyPEM)}

	if err := prepareSigningKeys(&cfg, dataDir, false); err != nil {
		t.Fatalf("prepare signing keys: %v", err)
	}
	if cfg.SigningKeyPEM != string(keyPEM) {
		t.Fatal("configured signing key was changed")
	}
	if _, err := os.Stat(filepath.Join(dataDir, defaultKeysPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("generated key set exists for configured key: %v", err)
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
	oldKey, err := newManagedSigningKey("test-key", now.AddDate(0, 0, -2))
	if err != nil {
		t.Fatalf("create old key: %v", err)
	}
	oldSet := managedSigningKeySet{ActiveKeyID: oldKey.KeyID, Keys: []managedSigningKey{oldKey}}
	if err := saveManagedSigningKeySet(filepath.Join(dataDir, defaultKeysPath), oldSet); err != nil {
		t.Fatalf("save old key set: %v", err)
	}
	oldBroker, err := NewBroker(Config{
		Issuer: "http://broker.example",
		KeyID:  oldKey.KeyID,
		SigningKeys: []SigningKeyConfig{{
			KeyID:         oldKey.KeyID,
			SigningKeyPEM: oldKey.SigningKeyPEM,
			Active:        true,
		}},
	}, mustNewStore(t))
	if err != nil {
		t.Fatalf("create old broker: %v", err)
	}
	oldToken, err := oldBroker.signJWT(map[string]any{
		"iss": "http://broker.example",
		"sub": "johndoe",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	})
	if err != nil {
		t.Fatalf("sign old token: %v", err)
	}

	cfg := Config{
		Issuer:                  "http://broker.example",
		KeyID:                   "test-key",
		SigningKeyRotationDays:  1,
		SigningKeyRetentionDays: 30,
	}
	if err := prepareSigningKeys(&cfg, dataDir, false); err != nil {
		t.Fatalf("prepare signing keys: %v", err)
	}
	if len(cfg.SigningKeys) != 2 {
		t.Fatalf("signing keys after rotation = %d, want 2", len(cfg.SigningKeys))
	}
	if cfg.KeyID == oldKey.KeyID {
		t.Fatal("active key was not rotated")
	}

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
	store, err := NewStore("")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
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
