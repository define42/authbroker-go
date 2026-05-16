package main

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareSigningKeyPEMCreatesAndReusesKey(t *testing.T) {
	dataDir := t.TempDir()
	cfg := Config{}

	if err := prepareSigningKeyPEM(&cfg, dataDir); err != nil {
		t.Fatalf("prepare signing key: %v", err)
	}
	if cfg.SigningKeyPEM == "" {
		t.Fatal("SigningKeyPEM is empty")
	}

	keyPath := filepath.Join(dataDir, defaultKeyPath)
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read generated key: %v", err)
	}
	if cfg.SigningKeyPEM != string(keyPEM) {
		t.Fatal("config signing key does not match generated key file")
	}
	key, err := parseRSAPrivateKeyPEM(keyPEM)
	if err != nil {
		t.Fatalf("parse generated key: %v", err)
	}
	if got := key.N.BitLen(); got != 2048 {
		t.Fatalf("generated key bits = %d, want 2048", got)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat generated key: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("generated key permissions = %v, want no group/world access", mode)
	}

	reloadedCfg := Config{}
	if err := prepareSigningKeyPEM(&reloadedCfg, dataDir); err != nil {
		t.Fatalf("prepare signing key again: %v", err)
	}
	if reloadedCfg.SigningKeyPEM != cfg.SigningKeyPEM {
		t.Fatal("prepareSigningKeyPEM did not reuse the existing key")
	}
}

func TestPrepareSigningKeyPEMLeavesConfiguredKeyAlone(t *testing.T) {
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

	if err := prepareSigningKeyPEM(&cfg, dataDir); err != nil {
		t.Fatalf("prepare signing key: %v", err)
	}
	if cfg.SigningKeyPEM != string(keyPEM) {
		t.Fatal("configured signing key was changed")
	}
	if _, err := os.Stat(filepath.Join(dataDir, defaultKeyPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("generated key file exists for configured key: %v", err)
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
