package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type PersistentData struct {
	Users         map[string]*StoredUser          `json:"users"`
	Sessions      map[string]Session              `json:"sessions,omitempty"`
	AuthRequests  map[string]AuthorizationRequest `json:"auth_requests,omitempty"`
	AuthCodes     map[string]AuthCode             `json:"authorization_codes,omitempty"`
	RefreshTokens map[string]RefreshToken         `json:"refresh_tokens,omitempty"`
	RevokedJTIs   map[string]time.Time            `json:"revoked_jtis,omitempty"`
	WebAuthnReg   map[string]ChallengeRecord      `json:"webauthn_registration_challenges,omitempty"`
	WebAuthnLog   map[string]ChallengeRecord      `json:"webauthn_login_challenges,omitempty"`
}

type StoredUser struct {
	Username            string               `json:"username"`
	Email               string               `json:"email,omitempty"`
	Name                string               `json:"name,omitempty"`
	Groups              []string             `json:"groups,omitempty"`
	TOTPSecretBase32    string               `json:"totp_secret_base32,omitempty"`
	WebAuthnCredentials []WebAuthnCredential `json:"webauthn_credentials,omitempty"`
}

type WebAuthnCredential struct {
	IDBase64URL string `json:"id_base64url"`
	Alg         string `json:"alg"` // currently ES256
	XBase64URL  string `json:"x_base64url"`
	YBase64URL  string `json:"y_base64url"`
	SignCount   uint32 `json:"sign_count"`
	CreatedAt   int64  `json:"created_at"`
}

type Store struct {
	mu   sync.RWMutex
	path string
	data PersistentData
}

type StoredRuntimeState struct {
	Sessions      map[string]Session
	AuthRequests  map[string]AuthorizationRequest
	AuthCodes     map[string]AuthCode
	RefreshTokens map[string]RefreshToken
	RevokedJTIs   map[string]time.Time
	WebAuthnReg   map[string]ChallengeRecord
	WebAuthnLog   map[string]ChallengeRecord
}

func NewStore(path string) (*Store, error) {
	s := &Store{path: path, data: newPersistentData()}
	if path == "" {
		return s, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func newPersistentData() PersistentData {
	return PersistentData{
		Users:         map[string]*StoredUser{},
		Sessions:      map[string]Session{},
		AuthRequests:  map[string]AuthorizationRequest{},
		AuthCodes:     map[string]AuthCode{},
		RefreshTokens: map[string]RefreshToken{},
		RevokedJTIs:   map[string]time.Time{},
		WebAuthnReg:   map[string]ChallengeRecord{},
		WebAuthnLog:   map[string]ChallengeRecord{},
	}
}

func (s *Store) ensureMaps() {
	if s.data.Users == nil {
		s.data.Users = map[string]*StoredUser{}
	}
	if s.data.Sessions == nil {
		s.data.Sessions = map[string]Session{}
	}
	if s.data.AuthRequests == nil {
		s.data.AuthRequests = map[string]AuthorizationRequest{}
	}
	if s.data.AuthCodes == nil {
		s.data.AuthCodes = map[string]AuthCode{}
	}
	if s.data.RefreshTokens == nil {
		s.data.RefreshTokens = map[string]RefreshToken{}
	}
	if s.data.RevokedJTIs == nil {
		s.data.RevokedJTIs = map[string]time.Time{}
	}
	if s.data.WebAuthnReg == nil {
		s.data.WebAuthnReg = map[string]ChallengeRecord{}
	}
	if s.data.WebAuthnLog == nil {
		s.data.WebAuthnLog = map[string]ChallengeRecord{}
	}
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, b, 0o600)
}

func (s *Store) loadLocked() error {
	if s.path == "" {
		return nil
	}
	data := newPersistentData()
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.data = data
			return nil
		}
		return err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		s.data = data
		return nil
	}
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}
	s.data = data
	s.ensureMaps()
	return nil
}

func (s *Store) withLockedData(fn func() (bool, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if fn == nil {
		return nil
	}
	changed, err := fn()
	if err != nil || !changed {
		return err
	}
	return s.saveLocked()
}

func writeFileAtomic(path string, content []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	dirFile, err := os.Open(dir) //nolint:gosec // directory path is derived from operator-supplied data directory.
	if err != nil {
		return err
	}
	defer dirFile.Close()
	return dirFile.Sync()
}

func (s *Store) UpsertProfile(p UserProfile) (*StoredUser, error) {
	var out *StoredUser
	err := s.withLockedData(func() (bool, error) {
		u := s.data.Users[p.Subject]
		if u == nil {
			u = &StoredUser{Username: p.Subject}
			s.data.Users[p.Subject] = u
		}
		if p.Email != "" {
			u.Email = p.Email
		}
		if p.Name != "" {
			u.Name = p.Name
		}
		if p.Groups != nil {
			u.Groups = append([]string(nil), p.Groups...)
		}
		out = cloneStoredUser(u)
		return true, nil
	})
	return out, err
}

func (s *Store) GetUser(username string) (*StoredUser, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.data.Users[username]
	if !ok || u == nil {
		return nil, false
	}
	return cloneStoredUser(u), true
}

func (s *Store) SetTOTP(username, secret string) error {
	return s.withLockedData(func() (bool, error) {
		u := s.data.Users[username]
		if u == nil {
			u = &StoredUser{Username: username}
			s.data.Users[username] = u
		}
		u.TOTPSecretBase32 = secret
		return true, nil
	})
}

func (s *Store) AddWebAuthnCredential(username string, cred WebAuthnCredential) error {
	return s.withLockedData(func() (bool, error) {
		u := s.data.Users[username]
		if u == nil {
			u = &StoredUser{Username: username}
			s.data.Users[username] = u
		}
		for _, existing := range u.WebAuthnCredentials {
			if existing.IDBase64URL == cred.IDBase64URL {
				return false, fmt.Errorf("credential already registered")
			}
		}
		u.WebAuthnCredentials = append(u.WebAuthnCredentials, cred)
		return true, nil
	})
}

func (s *Store) UpdateWebAuthnSignCount(username, credID string, signCount uint32) error {
	return s.withLockedData(func() (bool, error) {
		u := s.data.Users[username]
		if u == nil {
			return false, fmt.Errorf("user not found")
		}
		for i := range u.WebAuthnCredentials {
			if u.WebAuthnCredentials[i].IDBase64URL == credID {
				u.WebAuthnCredentials[i].SignCount = signCount
				return true, nil
			}
		}
		return false, fmt.Errorf("credential not found")
	})
}

func (s *Store) RuntimeState() StoredRuntimeState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.runtimeStateLocked()
}

func (s *Store) runtimeStateLocked() StoredRuntimeState {
	return StoredRuntimeState{
		Sessions:      cloneSessionMap(s.data.Sessions),
		AuthRequests:  cloneAuthorizationRequestMap(s.data.AuthRequests),
		AuthCodes:     cloneAuthCodeMap(s.data.AuthCodes),
		RefreshTokens: cloneRefreshTokenMap(s.data.RefreshTokens),
		RevokedJTIs:   cloneRevokedJTIMap(s.data.RevokedJTIs),
		WebAuthnReg:   cloneChallengeRecordMap(s.data.WebAuthnReg),
		WebAuthnLog:   cloneChallengeRecordMap(s.data.WebAuthnLog),
	}
}

func (s *Store) ReplaceRuntimeState(state StoredRuntimeState) error {
	return s.withLockedData(func() (bool, error) {
		s.replaceRuntimeStateLocked(state)
		return true, nil
	})
}

func (s *Store) UpdateRuntimeState(fn func(*StoredRuntimeState) (bool, error)) (StoredRuntimeState, error) {
	var state StoredRuntimeState
	err := s.withLockedData(func() (bool, error) {
		state = s.runtimeStateLocked()
		changed, err := fn(&state)
		if err != nil {
			return false, err
		}
		if changed {
			s.replaceRuntimeStateLocked(state)
		}
		return changed, nil
	})
	return state, err
}

func (s *Store) replaceRuntimeStateLocked(state StoredRuntimeState) {
	s.data.Sessions = cloneSessionMap(state.Sessions)
	s.data.AuthRequests = cloneAuthorizationRequestMap(state.AuthRequests)
	s.data.AuthCodes = cloneAuthCodeMap(state.AuthCodes)
	s.data.RefreshTokens = cloneRefreshTokenMap(state.RefreshTokens)
	s.data.RevokedJTIs = cloneRevokedJTIMap(state.RevokedJTIs)
	s.data.WebAuthnReg = cloneChallengeRecordMap(state.WebAuthnReg)
	s.data.WebAuthnLog = cloneChallengeRecordMap(state.WebAuthnLog)
}

func cloneStoredUser(u *StoredUser) *StoredUser {
	if u == nil {
		return nil
	}
	c := *u
	if u.Groups != nil {
		c.Groups = append([]string(nil), u.Groups...)
	}
	if u.WebAuthnCredentials != nil {
		c.WebAuthnCredentials = append([]WebAuthnCredential(nil), u.WebAuthnCredentials...)
	}
	return &c
}

func cloneSessionMap(in map[string]Session) map[string]Session {
	out := make(map[string]Session, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneAuthorizationRequestMap(in map[string]AuthorizationRequest) map[string]AuthorizationRequest {
	out := make(map[string]AuthorizationRequest, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneAuthCodeMap(in map[string]AuthCode) map[string]AuthCode {
	out := make(map[string]AuthCode, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneRefreshTokenMap(in map[string]RefreshToken) map[string]RefreshToken {
	out := make(map[string]RefreshToken, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneRevokedJTIMap(in map[string]time.Time) map[string]time.Time {
	out := make(map[string]time.Time, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneChallengeRecordMap(in map[string]ChallengeRecord) map[string]ChallengeRecord {
	out := make(map[string]ChallengeRecord, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// hashSecret returns the hex SHA-256 of an opaque random secret. We key the
// in-memory and on-disk AuthCode and RefreshToken maps by this hash so a
// stolen data.json or backup does not expose live tokens — the wire format
// (opaque base64url random) is unchanged for clients.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
