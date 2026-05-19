package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
)

// Audit event names form a stable taxonomy that log consumers can filter on
// without parsing free-form messages. Keep this list small; prefer reusing
// an existing event with a more specific reason= attribute over adding a
// new event name.
const (
	auditEventLogin            = "login"
	auditEventReAuth           = "reauth"
	auditEventLogout           = "logout"
	auditEventTOTPEnroll       = "totp_enroll"
	auditEventTOTPEnrollVerify = "totp_enroll_verify"
	auditEventWebAuthnRegister = "webauthn_register"
	auditEventWebAuthnLogin    = "webauthn_login"
	auditEventTokenIssue       = "token_issue"
	auditEventRefreshReuse     = "refresh_token_reuse"
	auditEventTokenRevoke      = "token_revoke"
	auditEventTokenIntrospect  = "token_introspect"
	auditEventAppTokenIssue    = "app_token_issue" //nolint:gosec // event name, not a credential.
	auditEventConsent          = "consent"
	auditEventAdminMutation    = "admin_mutation"
)

const (
	auditOutcomeSuccess = "success"
	auditOutcomeFailure = "failure"
)

// newAuditLogger returns a structured JSON logger for audit events. Output is
// written to stderr alongside the rest of the broker's logs so a single log
// shipper can collect both streams.
func newAuditLogger(out io.Writer) *slog.Logger {
	if out == nil {
		out = os.Stderr
	}
	return slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// auditEvent emits one structured audit record. event and outcome are required
// and should be values from the audit* constants. Extra context (user_id,
// client_id, reason, grant_type, …) is passed as slog attributes.
func (b *Broker) auditEvent(r *http.Request, event, outcome string, attrs ...slog.Attr) {
	if b == nil || b.audit == nil {
		return
	}
	base := make([]slog.Attr, 0, len(attrs)+3)
	base = append(base, slog.String("event", event), slog.String("outcome", outcome))
	ctx := context.Background()
	if r != nil {
		base = append(base, slog.String("client_ip", b.clientIP(r)))
		if requestID := requestIDFromContext(r.Context()); requestID != "" {
			base = append(base, slog.String("request_id", requestID))
		}
		ctx = r.Context()
	}
	base = append(base, attrs...)
	b.audit.LogAttrs(ctx, slog.LevelInfo, "audit", base...)
}
