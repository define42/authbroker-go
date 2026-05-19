package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Store is a bbolt-backed persistence layer. Each logical map lives in its
// own bucket; values are JSON-encoded. All operations execute inside a
// single bbolt transaction, which gives atomic get-and-mutate semantics
// without an in-memory mirror.
type Store struct {
	db *bolt.DB
}

type StoredUser struct {
	Username                string               `json:"username"`
	Email                   string               `json:"email,omitempty"`
	Name                    string               `json:"name,omitempty"`
	Groups                  []string             `json:"groups,omitempty"`
	TOTPSecretBase32        string               `json:"totp_secret_base32,omitempty"`
	PendingTOTPSecretBase32 string               `json:"pending_totp_secret_base32,omitempty"`
	WebAuthnCredentials     []WebAuthnCredential `json:"webauthn_credentials,omitempty"`
}

type WebAuthnCredential struct {
	IDBase64URL string `json:"id_base64url"`
	Alg         string `json:"alg"`
	XBase64URL  string `json:"x_base64url"`
	YBase64URL  string `json:"y_base64url"`
	SignCount   uint32 `json:"sign_count"`
	CreatedAt   int64  `json:"created_at"`
}

// StoredRuntimeState is a snapshot of all runtime buckets, used by tests
// that need to assert presence/absence of entries.
type StoredRuntimeState struct {
	Sessions              map[string]Session
	AuthRequests          map[string]AuthorizationRequest
	AuthCodes             map[string]AuthCode
	RefreshTokens         map[string]RefreshToken
	ConsumedRefreshTokens map[string]ConsumedRefreshToken
	RevokedJTIs           map[string]time.Time
	WebAuthnReg           map[string]ChallengeRecord
	WebAuthnLog           map[string]ChallengeRecord
}

const (
	bucketUsers                 = "users"
	bucketSessions              = "sessions"
	bucketAuthRequests          = "auth_requests"
	bucketAuthCodes             = "auth_codes"
	bucketRefreshTokens         = "refresh_tokens"
	bucketConsumedRefreshTokens = "consumed_refresh_tokens"
	bucketRevokedJTIs           = "revoked_jtis"
	bucketWebAuthnReg           = "webauthn_registration_challenges"
	bucketWebAuthnLog           = "webauthn_login_challenges"
	bucketSigningKeys           = "signing_keys"
	bucketClients               = "clients"
	bucketAppTokens             = "app_tokens"
	bucketConsents              = "consents"
)

// signingKeySetKey is the single bbolt key under bucketSigningKeys that holds
// the managed signing key set. The bucket has only one entry; using a fixed
// key keeps the schema explicit.
const signingKeySetKey = "managed"

func allBuckets() []string {
	return []string{
		bucketUsers,
		bucketSessions,
		bucketAuthRequests,
		bucketAuthCodes,
		bucketRefreshTokens,
		bucketConsumedRefreshTokens,
		bucketRevokedJTIs,
		bucketWebAuthnReg,
		bucketWebAuthnLog,
		bucketSigningKeys,
		bucketClients,
		bucketAppTokens,
		bucketConsents,
	}
}

// NewStore opens (or creates) the bbolt database at path. Passing an empty
// path is rejected — tests should pass a temp-dir file.
func NewStore(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("store: path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("store: create data dir: %w", err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range allBuckets() {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases the bbolt file lock. Safe to call multiple times.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Ready() error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store is not open")
	}
	return s.db.View(func(tx *bolt.Tx) error {
		if bucket(tx, bucketUsers) == nil || bucket(tx, bucketSigningKeys) == nil {
			return fmt.Errorf("store buckets are not initialized")
		}
		return nil
	})
}

// -- Users -----------------------------------------------------------------

func (s *Store) UpsertProfile(p UserProfile) (*StoredUser, error) {
	var out *StoredUser
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketUsers)
		u, err := getUserTx(b, p.Subject)
		if err != nil {
			return err
		}
		if u == nil {
			u = &StoredUser{Username: p.Subject}
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
		if err := putJSON(b, []byte(p.Subject), u); err != nil {
			return err
		}
		out = cloneStoredUser(u)
		return nil
	})
	return out, err
}

func (s *Store) GetUser(username string) (*StoredUser, bool) {
	var u *StoredUser
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		u, err = getUserTx(bucket(tx, bucketUsers), username)
		return err
	})
	if err != nil || u == nil {
		return nil, false
	}
	return cloneStoredUser(u), true
}

func (s *Store) SetTOTP(username, secret string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketUsers)
		u, err := getUserTx(b, username)
		if err != nil {
			return err
		}
		if u == nil {
			u = &StoredUser{Username: username}
		}
		u.TOTPSecretBase32 = secret
		u.PendingTOTPSecretBase32 = ""
		return putJSON(b, []byte(username), u)
	})
}

// SetPendingTOTP stages a freshly generated TOTP secret on the user without
// touching the active TOTPSecretBase32. The pending secret is only committed
// (via CommitPendingTOTP) after the user proves they can produce a valid
// code, so an abandoned QR scan does not lock the user out at next login.
func (s *Store) SetPendingTOTP(username, secret string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketUsers)
		u, err := getUserTx(b, username)
		if err != nil {
			return err
		}
		if u == nil {
			u = &StoredUser{Username: username}
		}
		u.PendingTOTPSecretBase32 = secret
		return putJSON(b, []byte(username), u)
	})
}

// CommitPendingTOTP promotes the user's pending TOTP secret to the active
// TOTPSecretBase32 slot in a single transaction. Returns an error if there
// is no pending secret to commit.
func (s *Store) CommitPendingTOTP(username string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketUsers)
		u, err := getUserTx(b, username)
		if err != nil {
			return err
		}
		if u == nil || u.PendingTOTPSecretBase32 == "" {
			return fmt.Errorf("no pending totp secret")
		}
		u.TOTPSecretBase32 = u.PendingTOTPSecretBase32
		u.PendingTOTPSecretBase32 = ""
		return putJSON(b, []byte(username), u)
	})
}

// ClearPendingTOTP discards a staged-but-uncommitted pending TOTP secret.
func (s *Store) ClearPendingTOTP(username string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketUsers)
		u, err := getUserTx(b, username)
		if err != nil {
			return err
		}
		if u == nil || u.PendingTOTPSecretBase32 == "" {
			return nil
		}
		u.PendingTOTPSecretBase32 = ""
		return putJSON(b, []byte(username), u)
	})
}

func (s *Store) AddWebAuthnCredential(username string, cred WebAuthnCredential) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketUsers)
		u, err := getUserTx(b, username)
		if err != nil {
			return err
		}
		if u == nil {
			u = &StoredUser{Username: username}
		}
		for _, existing := range u.WebAuthnCredentials {
			if existing.IDBase64URL == cred.IDBase64URL {
				return fmt.Errorf("credential already registered")
			}
		}
		u.WebAuthnCredentials = append(u.WebAuthnCredentials, cred)
		return putJSON(b, []byte(username), u)
	})
}

func (s *Store) UpdateWebAuthnSignCount(username, credID string, signCount uint32) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketUsers)
		u, err := getUserTx(b, username)
		if err != nil {
			return err
		}
		if u == nil {
			return fmt.Errorf("user not found")
		}
		for i := range u.WebAuthnCredentials {
			if u.WebAuthnCredentials[i].IDBase64URL == credID {
				u.WebAuthnCredentials[i].SignCount = signCount
				return putJSON(b, []byte(username), u)
			}
		}
		return fmt.Errorf("credential not found")
	})
}

// -- Sessions --------------------------------------------------------------

func (s *Store) GetSession(sid string) (Session, bool, error) {
	var sess Session
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := bucket(tx, bucketSessions).Get([]byte(sid))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &sess)
	})
	return sess, found, err
}

func (s *Store) PutSession(sid string, sess Session) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(bucket(tx, bucketSessions), []byte(sid), sess)
	})
}

// EnsureSessionCSRF lazily backfills a CSRF token on legacy sessions that were
// persisted before createSession started populating CSRFToken. The read-modify-
// write happens inside a single bbolt transaction so two concurrent callers on
// the same session cannot race to install different tokens — the second tx
// observes the value the first committed and returns it unchanged.
func (s *Store) EnsureSessionCSRF(sid string, generate func() string) (Session, bool, error) {
	var sess Session
	var found bool
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketSessions)
		v := b.Get([]byte(sid))
		if v == nil {
			return nil
		}
		if err := json.Unmarshal(v, &sess); err != nil {
			return err
		}
		found = true
		if sess.CSRFToken != "" {
			return nil
		}
		sess.CSRFToken = generate()
		return putJSON(b, []byte(sid), sess)
	})
	return sess, found, err
}

func (s *Store) DeleteSession(sid string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return bucket(tx, bucketSessions).Delete([]byte(sid))
	})
}

// -- AuthRequests ----------------------------------------------------------

func (s *Store) GetAuthRequest(id string) (AuthorizationRequest, bool, error) {
	var ar AuthorizationRequest
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := bucket(tx, bucketAuthRequests).Get([]byte(id))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &ar)
	})
	return ar, found, err
}

func (s *Store) PutAuthRequest(ar AuthorizationRequest) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(bucket(tx, bucketAuthRequests), []byte(ar.ID), ar)
	})
}

// ConsumeAuthRequest reads and deletes the request in one transaction.
func (s *Store) ConsumeAuthRequest(id string) (AuthorizationRequest, bool, error) {
	var ar AuthorizationRequest
	var found bool
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketAuthRequests)
		v := b.Get([]byte(id))
		if v == nil {
			return nil
		}
		if err := json.Unmarshal(v, &ar); err != nil {
			return err
		}
		found = true
		return b.Delete([]byte(id))
	})
	return ar, found, err
}

// -- AuthCodes -------------------------------------------------------------

func (s *Store) PutAuthCode(key string, ac AuthCode) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(bucket(tx, bucketAuthCodes), []byte(key), ac)
	})
}

func (s *Store) ConsumeAuthCode(key string) (AuthCode, bool, error) {
	var ac AuthCode
	var found bool
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketAuthCodes)
		v := b.Get([]byte(key))
		if v == nil {
			return nil
		}
		if err := json.Unmarshal(v, &ac); err != nil {
			return err
		}
		found = true
		return b.Delete([]byte(key))
	})
	return ac, found, err
}

// -- RefreshTokens ---------------------------------------------------------

func (s *Store) GetRefreshToken(key string) (RefreshToken, bool, error) {
	var rt RefreshToken
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := bucket(tx, bucketRefreshTokens).Get([]byte(key))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &rt)
	})
	return rt, found, err
}

func (s *Store) PutRefreshToken(key string, rt RefreshToken) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(bucket(tx, bucketRefreshTokens), []byte(key), rt)
	})
}

// DeleteRefreshToken removes the token and reports whether it existed. The
// boolean lets callers implement single-use rotation: a concurrent request
// that loses the CAS receives deleted=false and must reject the grant.
func (s *Store) DeleteRefreshToken(key string) (bool, error) {
	deleted := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketRefreshTokens)
		if v := b.Get([]byte(key)); v != nil {
			deleted = true
			return b.Delete([]byte(key))
		}
		return nil
	})
	return deleted, err
}

func (s *Store) GetConsumedRefreshToken(key string) (ConsumedRefreshToken, bool, error) {
	var rec ConsumedRefreshToken
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := bucket(tx, bucketConsumedRefreshTokens).Get([]byte(key))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &rec)
	})
	return rec, found, err
}

// RotateRefreshToken consumes oldKey and writes both the new active refresh
// token and a tombstone for oldKey in one bbolt transaction. The returned
// boolean is false when oldKey was already consumed by a concurrent request.
func (s *Store) RotateRefreshToken(oldKey, newKey string, next RefreshToken, consumed ConsumedRefreshToken) (bool, error) {
	rotated := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		active := bucket(tx, bucketRefreshTokens)
		if active.Get([]byte(oldKey)) == nil {
			return nil
		}
		if err := active.Delete([]byte(oldKey)); err != nil {
			return err
		}
		if err := putJSON(bucket(tx, bucketConsumedRefreshTokens), []byte(oldKey), consumed); err != nil {
			return err
		}
		if err := putJSON(active, []byte(newKey), next); err != nil {
			return err
		}
		rotated = true
		return nil
	})
	return rotated, err
}

func (s *Store) RevokeRefreshTokenFamily(familyID string) error {
	if familyID == "" {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketRefreshTokens)
		var stale [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var rt RefreshToken
			if err := json.Unmarshal(v, &rt); err != nil {
				return err
			}
			if rt.FamilyID == familyID {
				stale = append(stale, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, key := range stale {
			if err := b.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
}

// -- RevokedJTIs -----------------------------------------------------------

func (s *Store) GetRevokedJTI(jti string) (time.Time, bool, error) {
	var exp time.Time
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := bucket(tx, bucketRevokedJTIs).Get([]byte(jti))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &exp)
	})
	return exp, found, err
}

func (s *Store) PutRevokedJTI(jti string, exp time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(bucket(tx, bucketRevokedJTIs), []byte(jti), exp)
	})
}

func (s *Store) DeleteRevokedJTI(jti string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return bucket(tx, bucketRevokedJTIs).Delete([]byte(jti))
	})
}

// -- WebAuthn challenges ---------------------------------------------------

func (s *Store) PutWebAuthnRegistration(challenge string, rec ChallengeRecord) error {
	return putChallenge(s.db, bucketWebAuthnReg, challenge, rec)
}

func (s *Store) ConsumeWebAuthnRegistration(challenge string) (ChallengeRecord, bool, error) {
	return consumeChallenge(s.db, bucketWebAuthnReg, challenge)
}

func (s *Store) PutWebAuthnLogin(challenge string, rec ChallengeRecord) error {
	return putChallenge(s.db, bucketWebAuthnLog, challenge, rec)
}

func (s *Store) ConsumeWebAuthnLogin(challenge string) (ChallengeRecord, bool, error) {
	return consumeChallenge(s.db, bucketWebAuthnLog, challenge)
}

func putChallenge(db *bolt.DB, name, challenge string, rec ChallengeRecord) error {
	return db.Update(func(tx *bolt.Tx) error {
		return putJSON(bucket(tx, name), []byte(challenge), rec)
	})
}

func consumeChallenge(db *bolt.DB, name, challenge string) (ChallengeRecord, bool, error) {
	var rec ChallengeRecord
	var found bool
	err := db.Update(func(tx *bolt.Tx) error {
		b := bucket(tx, name)
		v := b.Get([]byte(challenge))
		if v == nil {
			return nil
		}
		if err := json.Unmarshal(v, &rec); err != nil {
			return err
		}
		found = true
		return b.Delete([]byte(challenge))
	})
	return rec, found, err
}

// -- SigningKeys -----------------------------------------------------------

// GetSigningKeySet loads the managed signing key set from the store. Returns
// (zero, false, nil) when the bucket is empty, which is the boot-time signal
// for "generate a fresh key" or "migrate from signing-keys.json".
func (s *Store) GetSigningKeySet() (managedSigningKeySet, bool, error) {
	var keySet managedSigningKeySet
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := bucket(tx, bucketSigningKeys).Get([]byte(signingKeySetKey))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &keySet)
	})
	return keySet, found, err
}

func (s *Store) PutSigningKeySet(keySet managedSigningKeySet) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(bucket(tx, bucketSigningKeys), []byte(signingKeySetKey), keySet)
	})
}

// -- Sweep -----------------------------------------------------------------

// SweepExpired removes entries whose expiry is before now across every
// runtime bucket. Runs in a single transaction.
func (s *Store) SweepExpired(now time.Time) (int, error) {
	total := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		removed, err := sweepBucketTx[Session](tx, bucketSessions, func(v Session) time.Time { return v.ExpiresAt }, now)
		total += removed
		if err != nil {
			return err
		}
		removed, err = sweepBucketTx[AuthorizationRequest](tx, bucketAuthRequests, func(v AuthorizationRequest) time.Time { return v.ExpiresAt }, now)
		total += removed
		if err != nil {
			return err
		}
		removed, err = sweepBucketTx[AuthCode](tx, bucketAuthCodes, func(v AuthCode) time.Time { return v.ExpiresAt }, now)
		total += removed
		if err != nil {
			return err
		}
		removed, err = sweepBucketTx[RefreshToken](tx, bucketRefreshTokens, func(v RefreshToken) time.Time { return v.ExpiresAt }, now)
		total += removed
		if err != nil {
			return err
		}
		removed, err = sweepBucketTx[ConsumedRefreshToken](tx, bucketConsumedRefreshTokens, func(v ConsumedRefreshToken) time.Time { return v.ExpiresAt }, now)
		total += removed
		if err != nil {
			return err
		}
		removed, err = sweepBucketTx[time.Time](tx, bucketRevokedJTIs, func(v time.Time) time.Time { return v }, now)
		total += removed
		if err != nil {
			return err
		}
		removed, err = sweepBucketTx[ChallengeRecord](tx, bucketWebAuthnReg, func(v ChallengeRecord) time.Time { return v.ExpiresAt }, now)
		total += removed
		if err != nil {
			return err
		}
		removed, err = sweepBucketTx[ChallengeRecord](tx, bucketWebAuthnLog, func(v ChallengeRecord) time.Time { return v.ExpiresAt }, now)
		total += removed
		return err
	})
	return total, err
}

func sweepBucketTx[T any](tx *bolt.Tx, name string, expiresAt func(T) time.Time, now time.Time) (int, error) {
	b := bucket(tx, name)
	if b == nil {
		return 0, nil
	}
	var stale [][]byte
	if err := b.ForEach(func(k, v []byte) error {
		var val T
		if err := json.Unmarshal(v, &val); err != nil {
			return err
		}
		if now.After(expiresAt(val)) {
			stale = append(stale, append([]byte(nil), k...))
		}
		return nil
	}); err != nil {
		return 0, err
	}
	for _, k := range stale {
		if err := b.Delete(k); err != nil {
			return 0, err
		}
	}
	return len(stale), nil
}

// -- Test helpers ----------------------------------------------------------

// RuntimeSnapshot loads every runtime bucket into memory. Intended for
// tests that need to assert presence/count of entries; not used in any
// hot request path.
func (s *Store) RuntimeSnapshot() StoredRuntimeState {
	state := StoredRuntimeState{
		Sessions:              map[string]Session{},
		AuthRequests:          map[string]AuthorizationRequest{},
		AuthCodes:             map[string]AuthCode{},
		RefreshTokens:         map[string]RefreshToken{},
		ConsumedRefreshTokens: map[string]ConsumedRefreshToken{},
		RevokedJTIs:           map[string]time.Time{},
		WebAuthnReg:           map[string]ChallengeRecord{},
		WebAuthnLog:           map[string]ChallengeRecord{},
	}
	_ = s.db.View(func(tx *bolt.Tx) error {
		loadBucketView(tx, bucketSessions, state.Sessions)
		loadBucketView(tx, bucketAuthRequests, state.AuthRequests)
		loadBucketView(tx, bucketAuthCodes, state.AuthCodes)
		loadBucketView(tx, bucketRefreshTokens, state.RefreshTokens)
		loadBucketView(tx, bucketConsumedRefreshTokens, state.ConsumedRefreshTokens)
		loadBucketView(tx, bucketRevokedJTIs, state.RevokedJTIs)
		loadBucketView(tx, bucketWebAuthnReg, state.WebAuthnReg)
		loadBucketView(tx, bucketWebAuthnLog, state.WebAuthnLog)
		return nil
	})
	return state
}

// SeedRuntimeState replaces the runtime buckets with the given state.
// Test-only helper.
func (s *Store) SeedRuntimeState(state StoredRuntimeState) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := seedBucketTx(tx, bucketSessions, state.Sessions); err != nil {
			return err
		}
		if err := seedBucketTx(tx, bucketAuthRequests, state.AuthRequests); err != nil {
			return err
		}
		if err := seedBucketTx(tx, bucketAuthCodes, state.AuthCodes); err != nil {
			return err
		}
		if err := seedBucketTx(tx, bucketRefreshTokens, state.RefreshTokens); err != nil {
			return err
		}
		if err := seedBucketTx(tx, bucketConsumedRefreshTokens, state.ConsumedRefreshTokens); err != nil {
			return err
		}
		if err := seedBucketTx(tx, bucketRevokedJTIs, state.RevokedJTIs); err != nil {
			return err
		}
		if err := seedBucketTx(tx, bucketWebAuthnReg, state.WebAuthnReg); err != nil {
			return err
		}
		return seedBucketTx(tx, bucketWebAuthnLog, state.WebAuthnLog)
	})
}

func loadBucketView[T any](tx *bolt.Tx, name string, out map[string]T) {
	b := bucket(tx, name)
	if b == nil {
		return
	}
	_ = b.ForEach(func(k, v []byte) error {
		var val T
		if err := json.Unmarshal(v, &val); err != nil {
			return nil
		}
		out[string(k)] = val
		return nil
	})
}

func seedBucketTx[T any](tx *bolt.Tx, name string, in map[string]T) error {
	b := bucket(tx, name)
	if b == nil {
		return nil
	}
	for k, v := range in {
		if err := putJSON(b, []byte(k), v); err != nil {
			return err
		}
	}
	return nil
}

// -- Stored clients --------------------------------------------------------

// ListStoredClients returns all admin-managed clients persisted in the store,
// sorted by client_id.
func (s *Store) ListStoredClients() ([]Client, error) {
	clients := []Client{}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketClients)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var c Client
			if err := json.Unmarshal(v, &c); err != nil {
				return err
			}
			clients = append(clients, c)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sortClientsByID(clients)
	return clients, nil
}

// PutStoredClient persists a client. Caller is responsible for validating /
// normalizing the value beforehand.
func (s *Store) PutStoredClient(c Client) error {
	if c.ClientID == "" {
		return fmt.Errorf("store: client_id is required")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(bucket(tx, bucketClients), []byte(c.ClientID), c)
	})
}

// DeleteStoredClient removes a stored client by id. Missing keys are a no-op
// so the admin "delete" action is idempotent.
func (s *Store) DeleteStoredClient(clientID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return bucket(tx, bucketClients).Delete([]byte(clientID))
	})
}

// -- Stored app tokens -----------------------------------------------------

func (s *Store) ListStoredAppTokens() ([]AppTokenConfig, error) {
	tokens := []AppTokenConfig{}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketAppTokens)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var t AppTokenConfig
			if err := json.Unmarshal(v, &t); err != nil {
				return err
			}
			tokens = append(tokens, t)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sortAppTokensByID(tokens)
	return tokens, nil
}

func (s *Store) PutStoredAppToken(t AppTokenConfig) error {
	if t.ID == "" {
		return fmt.Errorf("store: app token id is required")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(bucket(tx, bucketAppTokens), []byte(t.ID), t)
	})
}

func (s *Store) DeleteStoredAppToken(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return bucket(tx, bucketAppTokens).Delete([]byte(id))
	})
}

// -- Consent records -------------------------------------------------------

// ConsentRecord captures that a user has approved a client for a set of
// requested scopes. The granted-scope set lets us re-prompt when a later
// authorize asks for additional scopes the user has not yet seen.
type ConsentRecord struct {
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes,omitempty"`
	GrantedAt time.Time `json:"granted_at"`
}

func consentKey(userID, clientID string) string {
	return userID + "|" + clientID
}

func (s *Store) GetConsent(userID, clientID string) (ConsentRecord, bool, error) {
	var rec ConsentRecord
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := bucket(tx, bucketConsents).Get([]byte(consentKey(userID, clientID)))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &rec)
	})
	return rec, found, err
}

func (s *Store) PutConsent(rec ConsentRecord) error {
	if rec.UserID == "" || rec.ClientID == "" {
		return fmt.Errorf("store: consent requires user_id and client_id")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(bucket(tx, bucketConsents), []byte(consentKey(rec.UserID, rec.ClientID)), rec)
	})
}

// DeleteConsentsForClient removes every consent record naming the given
// client. Called when a stored client is deleted so future re-creates with the
// same id do not silently inherit old approvals.
func (s *Store) DeleteConsentsForClient(clientID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketConsents)
		if b == nil {
			return nil
		}
		var stale [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var rec ConsentRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return nil
			}
			if rec.ClientID == clientID {
				stale = append(stale, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range stale {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

func sortClientsByID(clients []Client) {
	sort.Slice(clients, func(i, j int) bool { return clients[i].ClientID < clients[j].ClientID })
}

func sortAppTokensByID(tokens []AppTokenConfig) {
	sort.Slice(tokens, func(i, j int) bool { return tokens[i].ID < tokens[j].ID })
}

// -- Internal helpers ------------------------------------------------------

func bucket(tx *bolt.Tx, name string) *bolt.Bucket {
	return tx.Bucket([]byte(name))
}

// getUserTx loads a user inside a bbolt transaction. Returns (nil, nil) when
// the username is not present — callers must check for u == nil before
// dereferencing.
func getUserTx(b *bolt.Bucket, username string) (*StoredUser, error) {
	v := b.Get([]byte(username))
	if v == nil {
		return nil, nil
	}
	var u StoredUser
	if err := json.Unmarshal(v, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

func putJSON(b *bolt.Bucket, key []byte, v any) error {
	encoded, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put(key, encoded)
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

// hashSecret returns the hex SHA-256 of an opaque random secret. We key the
// AuthCode and RefreshToken buckets by this hash so a stolen data file does
// not expose live tokens — the wire format (opaque base64url random) is
// unchanged for clients.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
