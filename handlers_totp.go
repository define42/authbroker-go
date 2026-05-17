package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TOTP RFC 6238 uses HMAC-SHA1.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (b *Broker) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.validSession(r)
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTOTPEnrollBodyBytes)
	// Re-auth required: a stolen session must not be able to silently swap
	// the TOTP secret.
	if !b.requireRecentReAuth(w, sess) {
		return
	}
	b.maybeExtendSession(w, r)
	secretBytes := make([]byte, 20)
	if _, err := rand.Read(secretBytes); err != nil {
		http.Error(w, "random error", http.StatusInternalServerError)
		return
	}
	secret := strings.TrimRight(base32.StdEncoding.EncodeToString(secretBytes), "=")
	if err := b.store.SetTOTP(sess.UserID, secret); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	issuerName := strings.TrimSpace(b.cfg.DisplayName)
	if issuerName == "" {
		issuerName = "Authbroker"
	}
	label := url.QueryEscape(issuerName + ":" + sess.UserID)
	issuer := url.QueryEscape(issuerName)
	otpauth := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", label, secret, issuer)
	writeJSON(w, http.StatusOK, map[string]string{"secret_base32": secret, "otpauth_uri": otpauth})
}

// TOTP, RFC 6238 style, HMAC-SHA1/6 digits/30 sec.
func verifyTOTP(secretBase32, code string, now time.Time, window int) bool {
	if len(code) != 6 {
		return false
	}
	code = strings.TrimSpace(code)
	step := now.Unix() / 30
	for i := -window; i <= window; i++ {
		if subtle.ConstantTimeCompare([]byte(totpCode(secretBase32, step+int64(i))), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func totpCode(secretBase32 string, counter int64) string {
	if counter < 0 {
		return "000000"
	}
	secretBase32 = strings.ToUpper(strings.TrimSpace(secretBase32))
	pad := len(secretBase32) % 8
	if pad != 0 {
		secretBase32 += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(secretBase32)
	if err != nil {
		return "000000"
	}
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(counter))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 | (uint32(sum[offset+1])&0xff)<<16 | (uint32(sum[offset+2])&0xff)<<8 | (uint32(sum[offset+3]) & 0xff)
	otp := bin % 1000000
	return fmt.Sprintf("%06d", otp)
}
