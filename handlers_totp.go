package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TOTP RFC 6238 uses HMAC-SHA1.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// handleTOTPEnroll stages a freshly generated TOTP secret on the user as
// PendingTOTPSecretBase32 and returns it (plus the otpauth:// URI) so the
// client can render a QR code. The user must then prove possession of the
// shared secret by POSTing a valid code to /mfa/totp/verify, which is what
// actually commits the secret as their active TOTPSecretBase32. Until that
// verify call succeeds, the user's existing TOTP (if any) keeps working —
// abandoning the enrollment does not lock anyone out.
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
		b.auditEvent(r, auditEventTOTPEnroll, auditOutcomeFailure,
			slog.String("user_id", sess.UserID),
			slog.String("reason", "random_error"))
		http.Error(w, "random error", http.StatusInternalServerError)
		return
	}
	secret := strings.TrimRight(base32.StdEncoding.EncodeToString(secretBytes), "=")
	if err := b.store.SetPendingTOTP(sess.UserID, secret); err != nil {
		b.auditEvent(r, auditEventTOTPEnroll, auditOutcomeFailure,
			slog.String("user_id", sess.UserID),
			slog.String("reason", "store_error"))
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	b.auditEvent(r, auditEventTOTPEnroll, auditOutcomeSuccess,
		slog.String("user_id", sess.UserID))
	issuerName := strings.TrimSpace(b.cfg.DisplayName)
	if issuerName == "" {
		issuerName = "Authbroker"
	}
	label := url.QueryEscape(issuerName + ":" + sess.UserID)
	issuer := url.QueryEscape(issuerName)
	otpauth := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", label, secret, issuer)
	writeJSON(w, http.StatusOK, map[string]string{"secret_base32": secret, "otpauth_uri": otpauth})
}

// handleTOTPEnrollVerify commits the user's pending TOTP secret only after
// they prove they can produce a valid code from it. Accepts either an
// application/x-www-form-urlencoded body (otp=...) or a JSON body
// ({"otp":"..."}). A 410 Gone is returned if no pending secret is staged.
func (b *Broker) handleTOTPEnrollVerify(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.validSession(r)
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTOTPVerifyBodyBytes)
	if !b.requireRecentReAuth(w, sess) {
		return
	}
	b.maybeExtendSession(w, r)
	rateKey := b.loginRateKey(r, sess.UserID+"/totp_enroll_verify")
	if allowed, retry := b.loginLimiter.allow(rateKey); !allowed {
		writeRetryAfter(w, retry)
		b.auditEvent(r, auditEventTOTPEnrollVerify, auditOutcomeFailure,
			slog.String("user_id", sess.UserID),
			slog.String("reason", "rate_limited"))
		http.Error(w, "too many verification attempts; try again later", http.StatusTooManyRequests)
		return
	}

	code, err := readTOTPVerifyCode(r)
	if err != nil {
		b.loginLimiter.recordFailure(rateKey)
		b.auditEvent(r, auditEventTOTPEnrollVerify, auditOutcomeFailure,
			slog.String("user_id", sess.UserID),
			slog.String("reason", "bad_request"))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, found := b.store.GetUser(sess.UserID)
	if !found || user.PendingTOTPSecretBase32 == "" {
		b.loginLimiter.recordFailure(rateKey)
		b.auditEvent(r, auditEventTOTPEnrollVerify, auditOutcomeFailure,
			slog.String("user_id", sess.UserID),
			slog.String("reason", "no_pending_enrollment"))
		http.Error(w, "no pending totp enrollment", http.StatusGone)
		return
	}
	if !verifyTOTP(user.PendingTOTPSecretBase32, code, time.Now(), 1) {
		b.loginLimiter.recordFailure(rateKey)
		b.auditEvent(r, auditEventTOTPEnrollVerify, auditOutcomeFailure,
			slog.String("user_id", sess.UserID),
			slog.String("reason", "invalid_code"))
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}
	if err := b.store.CommitPendingTOTP(sess.UserID); err != nil {
		b.loginLimiter.recordFailure(rateKey)
		b.auditEvent(r, auditEventTOTPEnrollVerify, auditOutcomeFailure,
			slog.String("user_id", sess.UserID),
			slog.String("reason", "store_error"))
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	b.loginLimiter.recordSuccess(rateKey)
	b.auditEvent(r, auditEventTOTPEnrollVerify, auditOutcomeSuccess,
		slog.String("user_id", sess.UserID))
	w.WriteHeader(http.StatusNoContent)
}

func readTOTPVerifyCode(r *http.Request) (string, error) {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(ct)
	if ct == "application/json" {
		var body struct {
			OTP string `json:"otp"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return "", fmt.Errorf("bad json")
		}
		code := strings.TrimSpace(body.OTP)
		if code == "" {
			return "", fmt.Errorf("missing otp")
		}
		return code, nil
	}
	if err := r.ParseForm(); err != nil {
		return "", fmt.Errorf("bad form")
	}
	code := strings.TrimSpace(r.Form.Get("otp"))
	if code == "" {
		return "", fmt.Errorf("missing otp")
	}
	return code, nil
}

// TOTP, RFC 6238 style, HMAC-SHA1/6 digits/30 sec.
//
// The inner comparison is constant-time, but the early return on first match
// makes total runtime depend on which window slot matched. With a window of 1
// (the only caller, both at login and at enroll-verify) this leaks at most
// log2(3) ≈ 1.6 bits per probe, which is harmless across a network and
// dominated by HTTP/TLS jitter. If the window is ever widened materially,
// change this to scan the full window and `subtle.ConstantTimeSelect` the
// match result.
func verifyTOTP(secretBase32, code string, now time.Time, window int) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
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
