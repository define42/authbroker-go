package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

func makePublicJWK(keyID string, pub *rsa.PublicKey) map[string]any {
	n := base64RawURL(pub.N.Bytes())
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"kid": keyID,
		"alg": "RS256",
		"n":   n,
		"e":   base64RawURL(eBytes),
	}
}

func (b *Broker) signJWT(claims map[string]any) (string, error) {
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": b.activeKey.keyID}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := base64RawURL(hb) + "." + base64RawURL(cb)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, b.activeKey.privateKey, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64RawURL(sig), nil
}

// jwtVerifyOptions tunes verifyJWT. Use ignoreExpiry only for id_token_hint on
// /oauth2/logout per OIDC RP-Initiated Logout 1.0 §3.
type jwtVerifyOptions struct {
	ignoreExpiry bool
}

func (b *Broker) verifyJWT(token string) (map[string]any, error) {
	return b.verifyJWTWithOptions(token, jwtVerifyOptions{})
}

func (b *Broker) verifyJWTWithOptions(token string, opts jwtVerifyOptions) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed jwt")
	}
	header, err := decodeJWTHeader(parts[0])
	if err != nil {
		return nil, err
	}
	verifyKey, err := b.jwtVerifyKey(header)
	if err != nil {
		return nil, err
	}
	if err := verifyJWTSignature(parts[0], parts[1], parts[2], verifyKey); err != nil {
		return nil, err
	}
	claims, err := decodeJWTClaims(parts[1])
	if err != nil {
		return nil, err
	}
	if err := b.validateJWTClaims(claims, opts); err != nil {
		return nil, err
	}
	return claims, nil
}

func decodeJWTHeader(encoded string) (map[string]any, error) {
	headerBytes, err := decodeB64URL(encoded)
	if err != nil {
		return nil, err
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}
	return header, nil
}

func (b *Broker) jwtVerifyKey(header map[string]any) (*rsa.PublicKey, error) {
	kid, _ := header["kid"].(string)
	verifyKey, ok := b.verifyKeys[kid]
	if header["alg"] != "RS256" || kid == "" || !ok {
		return nil, fmt.Errorf("bad header")
	}
	return verifyKey, nil
}

func verifyJWTSignature(encodedHeader, encodedClaims, encodedSignature string, verifyKey *rsa.PublicKey) error {
	sig, err := decodeB64URL(encodedSignature)
	if err != nil {
		return err
	}
	signingInput := encodedHeader + "." + encodedClaims
	h := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(verifyKey, crypto.SHA256, h[:], sig)
}

func decodeJWTClaims(encoded string) (map[string]any, error) {
	claimsBytes, err := decodeB64URL(encoded)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(claimsBytes))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (b *Broker) validateJWTClaims(claims map[string]any, opts jwtVerifyOptions) error {
	if iss, _ := claims["iss"].(string); iss != b.cfg.Issuer {
		return fmt.Errorf("bad issuer")
	}
	now := time.Now()
	if !opts.ignoreExpiry && jwtExpired(claims, now) {
		return fmt.Errorf("token expired")
	}
	if jwtNotActive(claims, now) {
		return fmt.Errorf("token not active")
	}
	return b.verifyTokenNotRevoked(claims)
}

func jwtExpired(claims map[string]any, now time.Time) bool {
	exp, ok := numberClaim(claims["exp"])
	return ok && now.After(time.Unix(exp, 0))
}

func jwtNotActive(claims map[string]any, now time.Time) bool {
	nbf, ok := numberClaim(claims["nbf"])
	return ok && now.Before(time.Unix(nbf, 0).Add(-30*time.Second))
}

func (b *Broker) verifyTokenNotRevoked(claims map[string]any) error {
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil
	}
	b.mu.Lock()
	var revoked bool
	err := b.updateRuntimeStateLocked(func(state *StoredRuntimeState) (bool, error) {
		exp, found := state.RevokedJTIs[jti]
		revoked = found
		if found && time.Now().After(exp) {
			delete(state.RevokedJTIs, jti)
			revoked = false
			return true, nil
		}
		return false, nil
	})
	b.mu.Unlock()
	if err != nil {
		return err
	}
	if revoked {
		return fmt.Errorf("token revoked")
	}
	return nil
}

func numberClaim(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	case float64:
		return int64(x), true
	case int64:
		return x, true
	case int:
		return int64(x), true
	default:
		return 0, false
	}
}
