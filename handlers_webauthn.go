package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"
)

func (b *Broker) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.validSession(r)
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxWebAuthnBodyBytes)
	// Re-auth required: a stolen session must not be able to silently add a
	// new passkey to the account.
	if !b.requireRecentReAuth(w, sess) {
		return
	}
	b.maybeExtendSession(w, r)
	user, _ := b.store.GetUser(sess.UserID)
	if user == nil {
		user = &StoredUser{Username: sess.UserID}
	}
	challenge := randomB64(32)
	// Key by challenge (not user ID) so parallel registration attempts from
	// the same account don't overwrite one another's challenge state.
	if err := b.store.PutWebAuthnRegistration(challenge, ChallengeRecord{UserID: sess.UserID, Challenge: challenge, ExpiresAt: time.Now().Add(5 * time.Minute)}); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}

	creds := make([]map[string]string, 0, len(user.WebAuthnCredentials))
	for _, c := range user.WebAuthnCredentials {
		creds = append(creds, map[string]string{"type": "public-key", "id": c.IDBase64URL})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"publicKey": map[string]any{
			"challenge": challenge,
			"rp": map[string]string{
				"name": b.cfg.WebAuthn.RPDisplayName,
				"id":   b.cfg.WebAuthn.RPID,
			},
			"user": map[string]string{
				"id":          base64RawURL([]byte(sess.UserID)),
				"name":        sess.UserID,
				"displayName": displayName(user),
			},
			"pubKeyCredParams":   []map[string]any{{"type": "public-key", "alg": -7}}, // ES256
			"timeout":            60000,
			"attestation":        "none",
			"excludeCredentials": creds,
			"authenticatorSelection": map[string]any{
				"userVerification": "preferred",
			},
		},
	})
}

func (b *Broker) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.validSession(r)
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxWebAuthnBodyBytes)
	if !b.requireRecentReAuth(w, sess) {
		return
	}
	b.maybeExtendSession(w, r)
	var req webauthnAttestationResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	clientDataBytes, err := decodeB64URL(req.Response.ClientDataJSON)
	if err != nil {
		http.Error(w, "bad clientDataJSON", http.StatusBadRequest)
		return
	}
	var cd webauthnClientData
	if err := json.Unmarshal(clientDataBytes, &cd); err != nil {
		http.Error(w, "bad client data", http.StatusBadRequest)
		return
	}
	challenge := normalizeChallenge(cd.Challenge)

	ch, found, persistErr := b.store.ConsumeWebAuthnRegistration(challenge)
	if persistErr != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if !found || time.Now().After(ch.ExpiresAt) || ch.UserID != sess.UserID {
		http.Error(w, "registration challenge expired", http.StatusBadRequest)
		return
	}

	cred, err := b.verifyWebAuthnAttestation(req, ch.Challenge)
	if err != nil {
		b.auditEvent(r, auditEventWebAuthnRegister, auditOutcomeFailure,
			slog.String("user_id", sess.UserID),
			slog.String("reason", "invalid_attestation"))
		http.Error(w, "invalid attestation: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := b.store.AddWebAuthnCredential(sess.UserID, cred); err != nil {
		b.auditEvent(r, auditEventWebAuthnRegister, auditOutcomeFailure,
			slog.String("user_id", sess.UserID),
			slog.String("reason", "store_error"))
		http.Error(w, "store error: "+err.Error(), http.StatusBadRequest)
		return
	}
	b.auditEvent(r, auditEventWebAuthnRegister, auditOutcomeSuccess,
		slog.String("user_id", sess.UserID),
		slog.String("credential_id", cred.IDBase64URL))
	writeJSON(w, http.StatusOK, map[string]string{"status": "registered"})
}

func (b *Broker) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxWebAuthnBodyBytes)
	var req struct {
		Username string `json:"username"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	// Match handleLoginPost: normalize case so users registered as "alice"
	// can sign in as "Alice" without missing the store lookup.
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	if req.Username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}
	// Always return a valid challenge with an allowCredentials list, even
	// when the user does not exist or has no passkeys enrolled. This keeps
	// /webauthn/login/begin from leaking whether an account is registered.
	// The browser handles an empty allowCredentials by surfacing the
	// standard "no credential" dialog; /webauthn/login/finish rejects the
	// flow when the challenge is bound to no user.
	var creds []WebAuthnCredential
	userID := ""
	if user, ok := b.store.GetUser(req.Username); ok {
		creds = user.WebAuthnCredentials
		userID = user.Username
	}
	challenge := randomB64(32)
	if err := b.store.PutWebAuthnLogin(challenge, ChallengeRecord{UserID: userID, Challenge: challenge, ExpiresAt: time.Now().Add(5 * time.Minute)}); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	allow := make([]map[string]string, 0, len(creds))
	for _, c := range creds {
		allow = append(allow, map[string]string{"type": "public-key", "id": c.IDBase64URL})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"publicKey": map[string]any{
			"challenge":        challenge,
			"timeout":          60000,
			"rpId":             b.cfg.WebAuthn.RPID,
			"allowCredentials": allow,
			"userVerification": "preferred",
		},
	})
}

func (b *Broker) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxWebAuthnBodyBytes)
	var req webauthnAssertionResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	clientDataBytes, err := decodeB64URL(req.Response.ClientDataJSON)
	if err != nil {
		http.Error(w, "bad clientDataJSON", http.StatusBadRequest)
		return
	}
	var cd webauthnClientData
	if err := json.Unmarshal(clientDataBytes, &cd); err != nil {
		http.Error(w, "bad client data", http.StatusBadRequest)
		return
	}
	challenge := normalizeChallenge(cd.Challenge)

	ch, ok, persistErr := b.store.ConsumeWebAuthnLogin(challenge)
	if persistErr != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	// Rate-limit before the empty-UserID early exit so an attacker cannot
	// time-distinguish "user exists" (runs the assertion verify) from "user
	// doesn't exist" (short-circuits here) by spraying usernames at
	// /webauthn/login/begin and submitting the resulting challenges.
	rateKey := b.loginRateKey(r, ch.UserID)
	if allowed, retry := b.loginLimiter.allow(rateKey); !allowed {
		writeRetryAfter(w, retry)
		b.auditEvent(r, auditEventWebAuthnLogin, auditOutcomeFailure,
			slog.String("user_id", ch.UserID),
			slog.String("reason", "rate_limited"))
		http.Error(w, "too many login attempts; try again later", http.StatusTooManyRequests)
		return
	}
	if !ok || time.Now().After(ch.ExpiresAt) || ch.UserID == "" {
		b.loginLimiter.recordFailure(rateKey)
		b.auditEvent(r, auditEventWebAuthnLogin, auditOutcomeFailure,
			slog.String("user_id", ch.UserID),
			slog.String("reason", "challenge_expired"))
		http.Error(w, "login challenge expired", http.StatusBadRequest)
		return
	}
	if err := b.verifyWebAuthnAssertion(req, ch.UserID, ch.Challenge, clientDataBytes, cd); err != nil {
		b.loginLimiter.recordFailure(rateKey)
		b.auditEvent(r, auditEventWebAuthnLogin, auditOutcomeFailure,
			slog.String("user_id", ch.UserID),
			slog.String("reason", "invalid_assertion"))
		http.Error(w, "invalid assertion: "+err.Error(), http.StatusBadRequest)
		return
	}
	b.loginLimiter.recordSuccess(rateKey)
	if _, err := b.createSession(w, ch.UserID, true, []string{amrWebAuthn}); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	b.auditEvent(r, auditEventWebAuthnLogin, auditOutcomeSuccess,
		slog.String("user_id", ch.UserID))
	writeJSON(w, http.StatusOK, map[string]string{"status": "authenticated"})
}

//nolint:gocognit,cyclop // WebAuthn validation is kept linear to match the protocol checks.
func (b *Broker) verifyWebAuthnAttestation(req webauthnAttestationResponse, expectedChallenge string) (WebAuthnCredential, error) {
	rawID, err := decodeB64URL(req.RawID)
	if err != nil || len(rawID) == 0 {
		return WebAuthnCredential{}, fmt.Errorf("bad rawId")
	}
	clientDataBytes, err := decodeB64URL(req.Response.ClientDataJSON)
	if err != nil {
		return WebAuthnCredential{}, fmt.Errorf("bad clientDataJSON")
	}
	var cd webauthnClientData
	if err := json.Unmarshal(clientDataBytes, &cd); err != nil {
		return WebAuthnCredential{}, fmt.Errorf("bad client data")
	}
	if cd.Type != "webauthn.create" {
		return WebAuthnCredential{}, fmt.Errorf("wrong clientData type")
	}
	if normalizeChallenge(cd.Challenge) != expectedChallenge {
		return WebAuthnCredential{}, fmt.Errorf("challenge mismatch")
	}
	if !b.allowedOrigin(cd.Origin) {
		return WebAuthnCredential{}, fmt.Errorf("origin not allowed")
	}

	attBytes, err := decodeB64URL(req.Response.AttestationObject)
	if err != nil {
		return WebAuthnCredential{}, fmt.Errorf("bad attestationObject")
	}
	val, rest, err := parseCBOR(attBytes)
	if err != nil || len(rest) != 0 {
		return WebAuthnCredential{}, fmt.Errorf("bad cbor attestation")
	}
	m := val.mapValue
	fmtVal, ok := cborGetString(m, "fmt")
	if !ok || fmtVal.strValue != "none" {
		return WebAuthnCredential{}, fmt.Errorf("only attestation fmt 'none' is accepted")
	}
	authDataVal, ok := cborGetString(m, "authData")
	if !ok || authDataVal.kind != cborBytes {
		return WebAuthnCredential{}, fmt.Errorf("missing authData")
	}
	parsed, err := parseAttestedAuthData(authDataVal.bytesValue, b.cfg.WebAuthn.RPID)
	if err != nil {
		return WebAuthnCredential{}, err
	}
	if !bytes.Equal(parsed.CredentialID, rawID) {
		return WebAuthnCredential{}, fmt.Errorf("credential id mismatch")
	}
	pub, err := parseCOSEES256PublicKey(parsed.COSEPublicKey)
	if err != nil {
		return WebAuthnCredential{}, err
	}
	return WebAuthnCredential{
		IDBase64URL: base64RawURL(rawID),
		Alg:         "ES256",
		XBase64URL:  base64RawURL(pub.X.Bytes()),
		YBase64URL:  base64RawURL(pub.Y.Bytes()),
		SignCount:   parsed.SignCount,
		CreatedAt:   time.Now().Unix(),
	}, nil
}

//nolint:gocognit,cyclop,funlen // WebAuthn assertion checks are intentionally explicit and ordered.
func (b *Broker) verifyWebAuthnAssertion(req webauthnAssertionResponse, username, expectedChallenge string, clientDataBytes []byte, cd webauthnClientData) error {
	if cd.Type != "webauthn.get" {
		return fmt.Errorf("wrong clientData type")
	}
	if normalizeChallenge(cd.Challenge) != expectedChallenge {
		return fmt.Errorf("challenge mismatch")
	}
	if !b.allowedOrigin(cd.Origin) {
		return fmt.Errorf("origin not allowed")
	}
	rawID, err := decodeB64URL(req.RawID)
	if err != nil || len(rawID) == 0 {
		return fmt.Errorf("bad rawId")
	}
	// Per WebAuthn §7.2 step 6, when the authenticator returns a userHandle
	// it MUST match the user the RP intended to authenticate. The current
	// flow already binds username via the challenge record, but discoverable
	// (passkey) credentials may surface a userHandle that the RP did not
	// originally supply — reject if it disagrees. We expect the handle to be
	// the b64url-encoded UTF-8 of the username (matching register/begin).
	if handle := strings.TrimSpace(req.Response.UserHandle); handle != "" {
		handleBytes, err := decodeB64URL(handle)
		if err != nil {
			return fmt.Errorf("bad userHandle")
		}
		if string(handleBytes) != username {
			return fmt.Errorf("userHandle does not match expected user")
		}
	}
	credID := base64RawURL(rawID)
	user, ok := b.store.GetUser(username)
	if !ok {
		return fmt.Errorf("user not found")
	}
	var cred *WebAuthnCredential
	for i := range user.WebAuthnCredentials {
		if user.WebAuthnCredentials[i].IDBase64URL == credID {
			cred = &user.WebAuthnCredentials[i]
			break
		}
	}
	if cred == nil {
		return fmt.Errorf("credential not registered")
	}
	authData, err := decodeB64URL(req.Response.AuthenticatorData)
	if err != nil {
		return fmt.Errorf("bad authenticatorData")
	}
	signCount, err := verifyAssertionAuthData(authData, b.cfg.WebAuthn.RPID)
	if err != nil {
		return err
	}
	// Once the authenticator has ever reported a non-zero signCount, every
	// subsequent assertion must strictly increase it. A regression to 0 (or to
	// any earlier value) is treated as a possible cloning indicator. The
	// "always-zero" authenticator class is still accepted because stored
	// SignCount stays 0 across all assertions.
	if cred.SignCount > 0 && signCount <= cred.SignCount {
		return fmt.Errorf("signature counter did not increase")
	}
	signature, err := decodeB64URL(req.Response.Signature)
	if err != nil {
		return fmt.Errorf("bad signature")
	}
	pub, err := publicKeyFromStored(*cred)
	if err != nil {
		return err
	}
	clientHash := sha256.Sum256(clientDataBytes)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(pub, digest[:], signature) {
		return fmt.Errorf("signature verification failed")
	}
	return b.store.UpdateWebAuthnSignCount(username, credID, signCount)
}

func (b *Broker) allowedOrigin(origin string) bool {
	for _, allowed := range b.cfg.WebAuthn.Origins {
		if strings.TrimRight(origin, "/") == strings.TrimRight(allowed, "/") {
			return true
		}
	}
	return false
}

type webauthnClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}

type webauthnAttestationResponse struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AttestationObject string `json:"attestationObject"`
	} `json:"response"`
}

type webauthnAssertionResponse struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle,omitempty"`
	} `json:"response"`
}

type parsedAttestationData struct {
	SignCount     uint32
	CredentialID  []byte
	COSEPublicKey []byte
}

func parseAttestedAuthData(data []byte, rpID string) (parsedAttestationData, error) {
	if len(data) < 37 {
		return parsedAttestationData{}, fmt.Errorf("authData too short")
	}
	rpHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(data[:32], rpHash[:]) {
		return parsedAttestationData{}, fmt.Errorf("rpId hash mismatch")
	}
	flags := data[32]
	if flags&0x01 == 0 {
		return parsedAttestationData{}, fmt.Errorf("user presence flag missing")
	}
	if flags&0x40 == 0 {
		return parsedAttestationData{}, fmt.Errorf("attested credential data flag missing")
	}
	signCount := binary.BigEndian.Uint32(data[33:37])
	off := 37 + 16 // skip AAGUID
	if len(data) < off+2 {
		return parsedAttestationData{}, fmt.Errorf("missing credential id length")
	}
	credLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if len(data) < off+credLen {
		return parsedAttestationData{}, fmt.Errorf("credential id truncated")
	}
	credID := append([]byte{}, data[off:off+credLen]...)
	off += credLen
	if len(data) <= off {
		return parsedAttestationData{}, fmt.Errorf("missing credential public key")
	}
	return parsedAttestationData{SignCount: signCount, CredentialID: credID, COSEPublicKey: append([]byte{}, data[off:]...)}, nil
}

func verifyAssertionAuthData(data []byte, rpID string) (uint32, error) {
	if len(data) < 37 {
		return 0, fmt.Errorf("authenticatorData too short")
	}
	rpHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(data[:32], rpHash[:]) {
		return 0, fmt.Errorf("rpId hash mismatch")
	}
	flags := data[32]
	if flags&0x01 == 0 {
		return 0, fmt.Errorf("user presence flag missing")
	}
	return binary.BigEndian.Uint32(data[33:37]), nil
}

func parseCOSEES256PublicKey(data []byte) (*ecdsa.PublicKey, error) {
	val, rest, err := parseCBOR(data)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("bad COSE key")
	}
	if val.kind != cborMap {
		return nil, fmt.Errorf("COSE key is not a map")
	}
	m := val.mapValue
	kty, ok := cborGetInt(m, 1)
	if !ok || kty.intValue != 2 {
		return nil, fmt.Errorf("COSE kty is not EC2")
	}
	alg, ok := cborGetInt(m, 3)
	if !ok || alg.intValue != -7 {
		return nil, fmt.Errorf("COSE alg is not ES256")
	}
	crv, ok := cborGetInt(m, -1)
	if !ok || crv.intValue != 1 {
		return nil, fmt.Errorf("COSE curve is not P-256")
	}
	xVal, ok := cborGetInt(m, -2)
	if !ok || xVal.kind != cborBytes {
		return nil, fmt.Errorf("missing x coordinate")
	}
	yVal, ok := cborGetInt(m, -3)
	if !ok || yVal.kind != cborBytes {
		return nil, fmt.Errorf("missing y coordinate")
	}
	x := new(big.Int).SetBytes(xVal.bytesValue)
	y := new(big.Int).SetBytes(yVal.bytesValue)
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, fmt.Errorf("public key point is not on P-256")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func publicKeyFromStored(c WebAuthnCredential) (*ecdsa.PublicKey, error) {
	if c.Alg != "ES256" {
		return nil, fmt.Errorf("unsupported credential alg")
	}
	xBytes, err := decodeB64URL(c.XBase64URL)
	if err != nil {
		return nil, fmt.Errorf("bad x coordinate")
	}
	yBytes, err := decodeB64URL(c.YBase64URL)
	if err != nil {
		return nil, fmt.Errorf("bad y coordinate")
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, fmt.Errorf("stored public key is not on P-256")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}
