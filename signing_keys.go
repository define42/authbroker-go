package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type signingKey struct {
	keyID      string
	privateKey *rsa.PrivateKey
	publicJWK  map[string]any
}

func buildSigningKeySet(cfg Config) (signingKey, map[string]*rsa.PublicKey, []any, error) {
	keyConfigs := effectiveSigningKeyConfigs(cfg)
	if len(keyConfigs) == 0 {
		return signingKey{}, nil, nil, nil
	}

	verifyKeys := make(map[string]*rsa.PublicKey, len(keyConfigs))
	publicJWKs := make([]any, 0, len(keyConfigs))
	var active signingKey
	activeCount := 0
	activeFlags := countActiveSigningKeyConfigs(keyConfigs)
	for i, keyCfg := range keyConfigs {
		keyID, key, publicJWK, err := parseSigningKeyConfig(keyCfg, i)
		if err != nil {
			return signingKey{}, nil, nil, err
		}
		if _, exists := verifyKeys[keyID]; exists {
			return signingKey{}, nil, nil, fmt.Errorf("duplicate signing key id %q", keyID)
		}
		verifyKeys[keyID] = &key.PublicKey
		publicJWKs = append(publicJWKs, publicJWK)
		if signingKeyConfigIsActive(keyCfg, activeFlags, len(keyConfigs), cfg.KeyID, keyID) {
			activeCount++
			active = signingKey{keyID: keyID, privateKey: key, publicJWK: publicJWK}
		}
	}
	if activeCount != 1 {
		return signingKey{}, nil, nil, fmt.Errorf("exactly one signing key must be active")
	}
	return active, verifyKeys, publicJWKs, nil
}

func effectiveSigningKeyConfigs(cfg Config) []SigningKeyConfig {
	if len(cfg.SigningKeys) > 0 || strings.TrimSpace(cfg.SigningKeyPEM) == "" {
		return cfg.SigningKeys
	}
	return []SigningKeyConfig{{
		KeyID:         cfg.KeyID,
		SigningKeyPEM: cfg.SigningKeyPEM,
		Active:        true,
	}}
}

func countActiveSigningKeyConfigs(keyConfigs []SigningKeyConfig) int {
	count := 0
	for _, keyCfg := range keyConfigs {
		if keyCfg.Active {
			count++
		}
	}
	return count
}

func parseSigningKeyConfig(keyCfg SigningKeyConfig, index int) (string, *rsa.PrivateKey, map[string]any, error) {
	keyID := strings.TrimSpace(keyCfg.KeyID)
	if keyID == "" {
		return "", nil, nil, fmt.Errorf("signing_keys[%d].key_id is required", index)
	}
	keyPEM := strings.TrimSpace(keyCfg.SigningKeyPEM)
	if keyPEM == "" {
		return "", nil, nil, fmt.Errorf("signing key %q: signing_key_pem is required", keyID)
	}
	key, err := parseRSAPrivateKeyPEM([]byte(keyPEM))
	if err != nil {
		return "", nil, nil, fmt.Errorf("parse signing key %q: %w", keyID, err)
	}
	return keyID, key, makePublicJWK(keyID, &key.PublicKey), nil
}

func signingKeyConfigIsActive(keyCfg SigningKeyConfig, activeFlags, keyCount int, cfgKeyID, keyID string) bool {
	if activeFlags > 0 {
		return keyCfg.Active
	}
	return keyCount == 1 || (cfgKeyID != "" && keyID == cfgKeyID)
}

func parseRSAPrivateKeyPEM(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no pem block found")
	}
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}
	return rsaKey, nil
}

func marshalRSAPrivateKeyPEM(key *rsa.PrivateKey) ([]byte, error) {
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type managedSigningKeySet struct {
	ActiveKeyID string              `json:"active_key_id"`
	Keys        []managedSigningKey `json:"keys"`
}

type managedSigningKey struct {
	KeyID         string `json:"key_id"`
	SigningKeyPEM string `json:"signing_key_pem"`
	CreatedAt     int64  `json:"created_at"`
	RetiredAt     int64  `json:"retired_at,omitempty"`
}

// signingKeySetSource records where the in-memory managedSigningKeySet came
// from on this boot. It drives both the startup log line and the decision of
// whether to persist the set even when rotate/prune did not change it (a
// freshly-generated or just-migrated set must always be written back).
type signingKeySetSource int

const (
	sourceGenerated signingKeySetSource = iota
	sourceMigrated
	sourceStore
)

func prepareSigningKeys(cfg *Config, store *Store, dataDir string, forceRotate bool) error {
	if strings.TrimSpace(cfg.SigningKeyPEM) != "" || len(cfg.SigningKeys) > 0 || store == nil {
		return nil
	}

	keySet, source, changed, err := prepareManagedSigningKeySet(store, dataDir, cfg, forceRotate, time.Now())
	if err != nil {
		return err
	}
	cfg.SigningKeys = keySet.signingKeyConfigs()
	cfg.KeyID = keySet.ActiveKeyID
	logManagedSigningKeySet(source, changed)
	return nil
}

func prepareManagedSigningKeySet(store *Store, dataDir string, cfg *Config, forceRotate bool, now time.Time) (managedSigningKeySet, signingKeySetSource, bool, error) {
	keySet, loaded, err := store.GetSigningKeySet()
	if err != nil {
		return managedSigningKeySet{}, sourceGenerated, false, err
	}
	source := sourceStore
	if !loaded {
		migrated, hasFile, err := migrateLegacySigningKeyFile(dataDir)
		if err != nil {
			return managedSigningKeySet{}, sourceGenerated, false, err
		}
		switch {
		case hasFile:
			keySet = migrated
			source = sourceMigrated
		default:
			keySet, err = initialManagedSigningKeySet(cfg.KeyID, now)
			if err != nil {
				return managedSigningKeySet{}, sourceGenerated, false, err
			}
			source = sourceGenerated
		}
	}
	// forceRotate only applies to a pre-existing set — rotating a key we just
	// generated this boot would be pointless churn.
	changed, err := keySet.rotateAndPrune(cfg.KeyID, cfg.SigningKeyRotationDays, cfg.SigningKeyRetentionDays, forceRotate && source != sourceGenerated, now)
	if err != nil {
		return managedSigningKeySet{}, source, false, err
	}
	if source != sourceStore || changed {
		if err := store.PutSigningKeySet(keySet); err != nil {
			return managedSigningKeySet{}, source, false, err
		}
	}
	return keySet, source, changed, nil
}

func logManagedSigningKeySet(source signingKeySetSource, changed bool) {
	switch source {
	case sourceGenerated:
		log.Printf("generated RSA signing key set in store")
	case sourceMigrated:
		log.Printf("migrated RSA signing key set from %s into store", defaultKeysPath)
	case sourceStore:
		if changed {
			log.Printf("updated RSA signing key set in store")
		} else {
			log.Printf("loaded RSA signing key set from store")
		}
	}
}

// migrateLegacySigningKeyFile imports a pre-bbolt signing-keys.json into the
// store on first boot after the switch. The file is renamed (not deleted) so
// an operator who needs to roll back has the original PEMs on disk.
func migrateLegacySigningKeyFile(dataDir string) (managedSigningKeySet, bool, error) {
	if dataDir == "" {
		return managedSigningKeySet{}, false, nil
	}
	path := filepath.Join(dataDir, defaultKeysPath)
	b, err := os.ReadFile(path) //nolint:gosec // key path is derived from operator-supplied data directory.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return managedSigningKeySet{}, false, nil
		}
		return managedSigningKeySet{}, false, err
	}
	var keySet managedSigningKeySet
	if err := json.Unmarshal(b, &keySet); err != nil {
		return managedSigningKeySet{}, false, fmt.Errorf("migrate %s: %w", path, err)
	}
	if err := os.Rename(path, path+".migrated"); err != nil {
		return managedSigningKeySet{}, false, fmt.Errorf("rename migrated key file %s: %w", path, err)
	}
	return keySet, true, nil
}

func initialManagedSigningKeySet(keyIDPrefix string, now time.Time) (managedSigningKeySet, error) {
	key, err := newManagedSigningKey(keyIDPrefix, now)
	if err != nil {
		return managedSigningKeySet{}, err
	}
	return managedSigningKeySet{ActiveKeyID: key.KeyID, Keys: []managedSigningKey{key}}, nil
}

func (s *managedSigningKeySet) rotateAndPrune(keyIDPrefix string, rotationDays, retentionDays int, forceRotate bool, now time.Time) (bool, error) {
	changed := false
	createdInitial := false
	if len(s.Keys) == 0 {
		key, err := newManagedSigningKey(keyIDPrefix, now)
		if err != nil {
			return false, err
		}
		s.ActiveKeyID = key.KeyID
		s.Keys = []managedSigningKey{key}
		changed = true
		createdInitial = true
	}
	if err := s.validate(); err != nil {
		return false, err
	}
	activeIndex := s.activeIndex()
	if activeIndex < 0 {
		return false, fmt.Errorf("active signing key %q not found", s.ActiveKeyID)
	}
	if !createdInitial && shouldRotateSigningKey(s.Keys[activeIndex], rotationDays, forceRotate, now) {
		s.Keys[activeIndex].RetiredAt = now.Unix()
		key, err := newManagedSigningKey(keyIDPrefix, now)
		if err != nil {
			return false, err
		}
		s.ActiveKeyID = key.KeyID
		s.Keys = append(s.Keys, key)
		changed = true
	}
	if s.prune(retentionDays, now) {
		changed = true
	}
	return changed, s.validate()
}

func (s *managedSigningKeySet) validate() error {
	if strings.TrimSpace(s.ActiveKeyID) == "" {
		return fmt.Errorf("active signing key id is required")
	}
	seen := map[string]bool{}
	activeSeen := false
	for i, key := range s.Keys {
		if err := validateManagedSigningKey(key, i, seen); err != nil {
			return err
		}
		if key.KeyID == s.ActiveKeyID {
			activeSeen = true
			if key.RetiredAt != 0 {
				return fmt.Errorf("active signing key %q is retired", key.KeyID)
			}
		}
	}
	if !activeSeen {
		return fmt.Errorf("active signing key %q not found", s.ActiveKeyID)
	}
	return nil
}

func validateManagedSigningKey(key managedSigningKey, index int, seen map[string]bool) error {
	if strings.TrimSpace(key.KeyID) == "" {
		return fmt.Errorf("signing key %d: key_id is required", index)
	}
	if seen[key.KeyID] {
		return fmt.Errorf("duplicate signing key id %q", key.KeyID)
	}
	seen[key.KeyID] = true
	if strings.TrimSpace(key.SigningKeyPEM) == "" {
		return fmt.Errorf("signing key %q: signing_key_pem is required", key.KeyID)
	}
	if _, err := parseRSAPrivateKeyPEM([]byte(key.SigningKeyPEM)); err != nil {
		return fmt.Errorf("parse signing key %q: %w", key.KeyID, err)
	}
	return nil
}

func (s *managedSigningKeySet) activeIndex() int {
	for i, key := range s.Keys {
		if key.KeyID == s.ActiveKeyID {
			return i
		}
	}
	return -1
}

func shouldRotateSigningKey(key managedSigningKey, rotationDays int, forceRotate bool, now time.Time) bool {
	if forceRotate {
		return true
	}
	if rotationDays <= 0 {
		return false
	}
	createdAt := time.Unix(key.CreatedAt, 0)
	return !createdAt.IsZero() && !now.Before(createdAt.AddDate(0, 0, rotationDays))
}

func (s *managedSigningKeySet) prune(retentionDays int, now time.Time) bool {
	if retentionDays < 0 {
		return false
	}
	cutoff := now.AddDate(0, 0, -retentionDays).Unix()
	keys := s.Keys[:0]
	changed := false
	for _, key := range s.Keys {
		if key.KeyID != s.ActiveKeyID && key.RetiredAt != 0 && key.RetiredAt < cutoff {
			changed = true
			continue
		}
		keys = append(keys, key)
	}
	s.Keys = keys
	return changed
}

func (s *managedSigningKeySet) signingKeyConfigs() []SigningKeyConfig {
	out := make([]SigningKeyConfig, 0, len(s.Keys))
	for _, key := range s.Keys {
		out = append(out, SigningKeyConfig{
			KeyID:         key.KeyID,
			SigningKeyPEM: key.SigningKeyPEM,
			Active:        key.KeyID == s.ActiveKeyID,
		})
	}
	return out
}

func newManagedSigningKey(keyIDPrefix string, now time.Time) (managedSigningKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return managedSigningKey{}, err
	}
	keyPEM, err := marshalRSAPrivateKeyPEM(key)
	if err != nil {
		return managedSigningKey{}, err
	}
	return managedSigningKey{
		KeyID:         newSigningKeyID(keyIDPrefix, now),
		SigningKeyPEM: string(keyPEM),
		CreatedAt:     now.Unix(),
	}, nil
}

func newSigningKeyID(prefix string, now time.Time) string {
	prefix = sanitizeKeyIDPrefix(prefix)
	if prefix == "" {
		prefix = "broker-key"
	}
	return prefix + "-" + now.UTC().Format("20060102T150405Z") + "-" + randomB64(6)
}

func sanitizeKeyIDPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	var b strings.Builder
	for _, r := range prefix {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		}
	}
	return strings.Trim(b.String(), "-_")
}
