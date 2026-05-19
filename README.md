# Go authentication broker: OAuth2/OIDC + LDAP/AD + JWT/JWKS + PKCE + TOTP + WebAuthn

[![codecov](https://codecov.io/gh/define42/authbroker-go/graph/badge.svg?token=0M6XMNZDTR)](https://codecov.io/gh/define42/authbroker-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/define42/authbroker-go)](https://goreportcard.com/report/github.com/define42/authbroker-go)
[![Build Status](https://github.com/define42/authbroker-go/actions/workflows/test.yml/badge.svg)](https://github.com/define42/authbroker-go/actions/)


This is a runnable starter implementation of an authentication broker in Go.

It provides modern application-facing protocols and security mechanisms:

- OAuth2 authorization-code flow
- OpenID Connect discovery, ID tokens, and UserInfo
- JWT access tokens signed with RS256
- JWKS endpoint
- PKCE S256
- Refresh-token rotation
- Token revocation endpoint
- TOTP MFA enrollment and validation
- Minimal WebAuthn/passkey registration and login support for ES256 credentials
- LDAP/AD simple-bind backend with optional profile lookup

The broker is intentionally small enough to study and extend. LDAP connectivity uses `github.com/go-ldap/ldap/v3`.

## Run

```bash
go run . -config config.example.json -data data
```

The same paths can be supplied through environment variables:

```bash
AUTHBROKER_CONFIG=config.example.json AUTHBROKER_DATA=data go run .
```

`AUTHBROKER_DATA` points at a data directory. The broker stores users, MFA secrets, WebAuthn credentials and challenge state, sessions, OAuth authorization state, refresh tokens, revoked token IDs, and managed RSA signing keys in `data.db`, a [bbolt](https://github.com/etcd-io/bbolt) (BoltDB) embedded key-value store. Back up `data.db` to preserve signing-key continuity across restarts. The broker is single-instance: only one process should run against a given `AUTHBROKER_DATA` directory at a time — bbolt holds an exclusive file lock on `data.db` and will refuse to open it from a second process.

Browser pages serve first-party CSS/JS under a strict Content-Security-Policy. Login uses a double-submit CSRF cookie, and authenticated browser forms such as logout and app-token generation use the session CSRF token.

Open the OIDC discovery document:

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

Open the broker's own login/logout page:

```text
http://localhost:8080/
```

JWKS:

```bash
curl http://localhost:8080/oauth2/jwks
```

## ACME / Let's Encrypt

The broker can terminate TLS itself via [certmagic](https://github.com/caddyserver/certmagic) and obtain certificates from Let's Encrypt (or any ACME CA). When the ACME block is enabled, `listen` is ignored: the broker binds `:443` for HTTPS and `:80` for the HTTP-01 challenge plus a 301 redirect to HTTPS.

```json
"acme": {
  "enabled": true,
  "domains": ["auth.example.com"],
  "email": "ops@example.com",
  "agreed_tos": true,
  "ca_directory": "https://acme-v02.api.letsencrypt.org/directory",
  "ca_cert_path": "",
  "storage_path": "",
  "http_addr": ":80",
  "https_addr": ":443"
}
```

- `agreed_tos` must be `true` — this signifies acceptance of the CA's Subscriber Agreement.
- `ca_directory` defaults to Let's Encrypt production (`https://acme-v02.api.letsencrypt.org/directory`). Set it to `https://acme-staging-v02.api.letsencrypt.org/directory` while testing to avoid rate limits, or point it at any other ACME-compatible CA (e.g. ZeroSSL, Buypass, an internal step-ca).
- `ca_cert_path` points at a PEM file with one or more root certificates the broker should trust when reaching the ACME server. Use this for internal CAs whose roots aren't in the system trust store; leave empty to rely solely on the system pool.
- `storage_path` defaults to `<AUTHBROKER_DATA>/acme`. The account key, certificates, and locks live there — back this up alongside `data.db` (which also holds the managed signing keys).
- `http_addr` / `https_addr` only need overriding for non-standard ports; ACME challenges still require `:80` / `:443` to reach the broker (port forwarding is fine).
- Set `issuer` to `https://<domain>` so OIDC discovery, redirects, and WebAuthn origins match the served scheme.
- The process needs permission to bind low ports — run as root, grant `CAP_NET_BIND_SERVICE`, or use a systemd `AmbientCapabilities=CAP_NET_BIND_SERVICE` unit.

Certificate management runs asynchronously, so the listener comes up immediately and certificates are obtained in the background on first start.

## Docker Compose demo

The compose stack starts:

- `glauth` as the LDAPS server, using the users in `testldap/default-config.cfg`
- `authbroker` on <http://localhost:8080>
- `test-web-ui` on <http://localhost:8090>
- `passkey-demo` on <http://localhost:8091>

```bash
docker compose up --build
```

Open <http://localhost:8090> and sign in through authbroker. Useful test users:

```text
ingestuser / dogood
johndoe / dogood
serviceuser / mysecret
```

The authbroker page at <http://localhost:8080/> can also sign in or sign out of the central authbroker session directly. The compose broker config lives in `compose/authbroker.config.json`. The test UI uses `http://localhost:8080` for browser redirects and `http://authbroker:8080` for server-side token and UserInfo calls inside the Docker network, then displays the LDAP-backed profile and client-mapped groups. Sign out uses the broker's OIDC `end_session_endpoint`, so it clears both the demo app session and the central authbroker SSO session.
In the GLAUTH fixture, `johndoe` also has a Demo OU-style group membership, `CN=demo_reports,OU=Demo,DC=glauth,DC=com`, which the compose client maps to `demo_reports`.

Open <http://localhost:8091> for the passkey demo. Sign in with LDAP first, register a passkey for that account, sign out of the demo broker session, then use "Sign in with passkey". The passkey demo proxies `/webauthn/*` to authbroker so the browser sees a single WebAuthn origin, `http://localhost:8091`; that origin is listed in the compose `webauthn.origins`.

## App Tokens

Users who sign in directly at <http://localhost:8080/> can generate signed JWTs for configured applications and copy them from the page. Each app token profile has its own audience, client ID, TTL, scope, and group mapping. Tokens use the broker signing key and can be validated through the existing JWKS endpoint:

```text
http://localhost:8080/oauth2/jwks
```

Example config with two token profiles:

```json
"app_tokens": [
  {
    "id": "litellm",
    "display_name": "LiteLLM",
    "audience": "litellm",
    "client_id": "litellm",
    "scope": "openid profile email groups",
    "token_ttl_minutes": 480,
    "group_mappings": {
      "OU=Demo,DC=example,DC=com": "{cn}",
      "regex:(?i)^CN=app_gitlab_[^,]+,": "{cn}"
    }
  },
  {
    "id": "internal-api",
    "display_name": "Internal API",
    "audience": "internal-api",
    "scope": "openid profile email",
    "token_ttl_minutes": 120
  }
]
```

For LiteLLM, point JWT auth at the broker like this:

```yaml
general_settings:
  enable_jwt_auth: true
  litellm_jwtauth:
    user_id_jwt_field: "sub"
    user_email_jwt_field: "email"
    team_ids_jwt_field: "groups"
    user_id_upsert: true
```

```bash
export JWT_PUBLIC_KEY_URL="http://localhost:8080/oauth2/jwks"
export JWT_AUDIENCE="litellm"
```

App tokens include `sub`, `preferred_username`, `email`, `name`, `client_id`, `app_token_id`, `scope`, and mapped `groups` when the selected profile has `group_mappings` and the profile scope includes `groups`. LiteLLM's JWT auth docs are at <https://docs.litellm.ai/docs/proxy/token_auth>.

## Admin UI and consent screen

Members of any group listed in `admin_groups` (in config.json) gain access to `/admin` after signing in. The admin UI lets you create and delete OAuth clients and app-token profiles at runtime; config-defined entries are read-only and stay declarative. Created entities persist in `AUTHBROKER_DATA/data.db` and are merged with config-defined ones on each request.

```json
"admin_groups": ["administrators"]
```

When a client has `require_consent: true`, the broker prompts the user (`/consent`) before redirecting back with an authorization code. Approvals are stored per (user, client) and re-prompted only if the client later requests a scope the user has not yet approved. Admin-created clients default to consent-required; config-defined clients default to consent-skipped to preserve existing first-party behavior — set `require_consent: true` per client to opt in.

Clients can also restrict OAuth scopes. `allowed_scopes` defaults to `openid profile email groups`; unsupported scopes are rejected at `/oauth2/authorize`. Refresh tokens are only issued for `offline_access` when the client has `"allow_offline_access": true`. The `client_credentials` grant has its own `client_credentials_scopes` list and rejects any non-empty scope not listed there.

## Signing keys and rotation

When `signing_key_pem` and `signing_keys` are omitted, startup automatically manages RSA signing keys inside `AUTHBROKER_DATA/data.db` (bbolt bucket `signing_keys`). New JWTs are signed with the active key, and retained old keys remain in `/oauth2/jwks` so existing tokens can validate after rotation. A pre-existing `AUTHBROKER_DATA/signing-keys.json` from older versions is read once on first startup and renamed to `signing-keys.json.migrated`; afterwards the bbolt store is authoritative.

Managed keys rotate every `signing_key_rotation_days` days, defaulting to 90. Retired keys are kept for `signing_key_retention_days`, defaulting to 30. Set either value to `-1` to disable automatic rotation or pruning, and run with `-rotate-key` to force a managed-key rotation on startup.

You can still generate a config-managed key yourself:

```bash
go run . -generate-key > config-key.pem
```

Then paste the PEM content into `signing_key_pem` in your JSON config, escaping newlines as `\n`. For config-managed multi-key rotation, use `signing_keys` with exactly one entry marked `"active": true`.

## OAuth/OIDC authorization-code flow with PKCE

Create a verifier and challenge:

```bash
VERIFIER=$(openssl rand -base64 64 | tr '+/' '-_' | tr -d '=')
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | openssl base64 -A | tr '+/' '-_' | tr -d '=')
echo "$VERIFIER"
echo "$CHALLENGE"
```

Visit:

```text
http://localhost:8080/oauth2/authorize?response_type=code&client_id=demo-web&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid%20profile%20email%20groups&state=abc&nonce=n1&code_challenge=<CHALLENGE>&code_challenge_method=S256
```

Login with an LDAP/AD user configured in your directory:

```text
username: <directory user>
password: <directory password>
```

Exchange the returned code:

```bash
curl -u demo-web:demo-secret \
  -d grant_type=authorization_code \
  -d code='<CODE>' \
  -d redirect_uri='http://localhost:3000/callback' \
  -d code_verifier="$VERIFIER" \
  http://localhost:8080/oauth2/token
```

The server config stores confidential client secrets as SHA-256 hex, not plaintext:

```bash
printf '%s' 'demo-secret' | sha256sum
```

Use the resulting first field as `client_secret_sha256`. The client still sends the original secret (`demo-secret`) to `/oauth2/token`; the broker hashes it and compares it with the configured digest.

## Logout

The broker advertises an OIDC/Keycloak-style `end_session_endpoint` in discovery:

```text
http://localhost:8080/oauth2/logout
```

Clients should clear their own local session first, then redirect the browser to that endpoint with `id_token_hint`, `client_id`, `post_logout_redirect_uri`, and optional `state`. The broker clears the `broker_session` SSO cookie and redirects only to a URI registered in the client's `post_logout_redirect_uris`.

Groups are also configured per client. LDAP/AD may return a large `memberOf` list, but the broker only emits groups that the client maps:

```json
{
  "client_id": "demo-web",
  "client_secret_sha256": "cd577fe2561ebff23505db0bb006300c7cdecbd46bc0e03c449afafaca2c25bf",
  "redirect_uris": ["http://localhost:3000/callback"],
  "post_logout_redirect_uris": ["http://localhost:3000/"],
  "require_pkce": true,
  "allowed_scopes": ["openid", "profile", "email", "groups"],
  "client_credentials_scopes": ["service"],
  "allow_offline_access": false,
  "group_mappings": {
    "CN=Demo App Admins,OU=Groups,DC=example,DC=com": "demo-admin",
    "OU=Demo,DC=example,DC=com": "{cn}",
    "regex:(?i)^CN=app_gitlab_[^,]+,": "{cn}"
  }
}
```

Mapping keys can be raw LDAP DNs or normalized group names. A mapping whose key is a base DN and whose value contains `{cn}` forwards every group with a `CN` below that base, so `"OU=Demo,DC=example,DC=com": "{cn}"` forwards `CN=Reports,OU=Demo,DC=example,DC=com` as `Reports`. The wildcard spelling `"CN=*,OU=Demo,DC=example,DC=com": "{cn}"` is also accepted. Regex mappings use the `regex:` prefix and run against the raw LDAP group value, so `"regex:(?i)^CN=app_gitlab_[^,]+,": "{cn}"` forwards `CN=app_gitlab_admins,OU=Any,DC=example,DC=com` as `app_gitlab_admins`, regardless of OU. Regex targets may use `{match}`, `{0}`, numeric captures like `{1}`, named captures like `{role}`, and the normal `{cn}`, `{group}`, and `{dn}` placeholders. Only mapped groups are included in access tokens, ID tokens, and UserInfo, and only when the authorization request includes the `groups` scope.

## LDAP/AD backend

Configure LDAP/AD as the authentication backend.

For Active Directory UPN bind:

```json
"ldap": {
  "url": "ldaps://dc01.example.com:636",
  "domain_suffix": "@example.com",
  "base_dn": "dc=example,dc=com",
  "user_filter": "(userPrincipalName={login})",
  "email_attribute": "mail",
  "name_attribute": "displayName",
  "groups_attribute": "memberOf",
  "nested_groups": true,
  "group_search_base_dn": "dc=example,dc=com",
  "group_search_filter": "(objectClass=group)",
  "group_name_attribute": "cn",
  "timeout_seconds": 5
}
```

The broker will bind as:

```text
<username>@example.com
```

It then searches below `base_dn`, escapes the `{login}` value, and copies the configured LDAP attributes into the broker profile. OIDC `groups` claims are filtered through each client's `group_mappings`.

Group support:

- Direct LDAP groups from `groups_attribute`: yes
- Nested AD groups: yes, when `nested_groups` is `true`
- Nested OpenLDAP groups: no

Collected LDAP groups are stored on the broker-side profile and are not forwarded wholesale. Add `group_mappings` to each client that should receive group claims.

For OpenLDAP DN-template bind:

```json
"ldap": {
  "url": "ldaps://ldap.example.com:636",
  "user_dn_template": "uid={username},ou=people,dc=example,dc=com",
  "base_dn": "dc=example,dc=com",
  "user_filter": "(uid={username})",
  "email_attribute": "mail",
  "name_attribute": "cn",
  "groups_attribute": "memberOf",
  "timeout_seconds": 5
}
```

Profile lookup is optional. If `base_dn` and `user_filter` are omitted, the broker only performs the bind and falls back to the submitted username plus `domain_suffix` for profile claims. Use `"start_tls": true` only with `ldap://` URLs; `ldaps://` starts TLS during dial. Nested AD lookup searches groups with the recursive matching rule `member:1.2.840.113556.1.4.1941:=<userDN>` and merges those results with direct groups. This starter does not implement group sync, nested OpenLDAP group resolution, or Kerberos/SPNEGO. Add those as separate federation modules.

For TLS to an LDAP server backed by an internal CA, set `ca_cert_path` to a PEM file with the root certificate(s) the broker should trust. The system trust store is also included, so this only needs to contain the extra roots. Prefer this over `insecure_skip_verify`, which disables certificate validation entirely.

## TOTP MFA

After login, enroll TOTP using the session cookie:

```bash
curl -X POST -b cookies.txt -c cookies.txt http://localhost:8080/mfa/totp/enroll
```

The response contains an `otpauth_uri` that can be added to an authenticator app. Once a user has a TOTP secret, the login form requires a code.

## WebAuthn/passkeys

The Docker Compose passkey demo at <http://localhost:8091> is the easiest way to exercise this flow. WebAuthn is origin-bound, so any app hosting the browser ceremony must be included in `webauthn.origins`, and the configured `rp_id` must be registrable for that origin.

The server exposes JSON endpoints:

- `POST /webauthn/register/begin` — requires an existing broker session
- `POST /webauthn/register/finish`
- `POST /webauthn/login/begin` — body: `{ "username": "ingestuser" }`
- `POST /webauthn/login/finish` — sets the broker session cookie

Browser helper functions for base64url conversion:

```js
function b64urlToBuf(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

function bufToB64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
```

Registration outline:

```js
const opts = await fetch('/webauthn/register/begin', {method: 'POST'}).then(r => r.json());
opts.publicKey.challenge = b64urlToBuf(opts.publicKey.challenge);
opts.publicKey.user.id = b64urlToBuf(opts.publicKey.user.id);
opts.publicKey.excludeCredentials = (opts.publicKey.excludeCredentials || []).map(c => ({...c, id: b64urlToBuf(c.id)}));
const cred = await navigator.credentials.create(opts);
await fetch('/webauthn/register/finish', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64url(cred.response.clientDataJSON),
      attestationObject: bufToB64url(cred.response.attestationObject)
    }
  })
});
```

Login outline:

```js
const opts = await fetch('/webauthn/login/begin', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({username: 'ingestuser'})
}).then(r => r.json());
opts.publicKey.challenge = b64urlToBuf(opts.publicKey.challenge);
opts.publicKey.allowCredentials = opts.publicKey.allowCredentials.map(c => ({...c, id: b64urlToBuf(c.id)}));
const assertion = await navigator.credentials.get(opts);
await fetch('/webauthn/login/finish', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    id: assertion.id,
    rawId: bufToB64url(assertion.rawId),
    type: assertion.type,
    response: {
      clientDataJSON: bufToB64url(assertion.response.clientDataJSON),
      authenticatorData: bufToB64url(assertion.response.authenticatorData),
      signature: bufToB64url(assertion.response.signature),
      userHandle: assertion.response.userHandle ? bufToB64url(assertion.response.userHandle) : ''
    }
  })
});
```

## Production deployment

For an internal Kubernetes deployment, set `"production": true` and run one broker replica with a ReadWriteOnce volume for `AUTHBROKER_DATA`. Production mode fails startup when unsafe settings are present: non-HTTPS issuer, insecure cookies, localhost or non-HTTPS redirects/WebAuthn origins, LDAP without LDAPS/StartTLS, `ldap.insecure_skip_verify`, missing admin groups, optional TOTP, missing PKCE, unbounded token/session TTLs, duplicate client IDs, or duplicate app-token IDs.

The Kubernetes starter manifest in `deploy/kubernetes/authbroker.yaml` uses a single-replica StatefulSet, non-root container security context, read-only root filesystem, RWO PVC, Service, TLS Ingress, NetworkPolicy, PodDisruptionBudget, `/livez` liveness, and `/readyz` readiness. Replace the example Secret, hostnames, LDAP settings, client hashes, image tag, ingress class assumptions, storage class, and network policy selectors before applying it.

Operational release gates:

- `make lint`
- `make test`
- `go test -race ./...`
- `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`
- `docker build -t authbroker-go:verify .`
- `make validate-k8s` with either `kubeconform` or `kubectl` installed

`make verify` runs those gates together. The build is pinned to a patched Go toolchain so standard-library vulnerability scans do not pass by accident.

Production operations still need deployment-specific work outside this repository:

- encrypt Kubernetes Secrets, PVC snapshots, backups, and TLS trust material at the infrastructure layer
- back up and restore-drill the full `AUTHBROKER_DATA` directory, including `data.db` and managed signing keys
- forward and retain structured JSON request/audit logs; audit events include login, reauth, logout, TOTP enrollment, WebAuthn register/login, token issue/revoke/introspection, app-token issue, consent, admin mutations, and refresh-token reuse
- scrape `/metrics` only when `metrics.enabled` is true; labels avoid usernames, tokens, raw groups, and client secrets
- define app-token issuance policy, per-app TTLs, client-secret rotation, signing-key rotation, alerting, and incident-response runbooks
- validate directory-specific group mapping and lifecycle behavior before go-live
- run OIDC and WebAuthn conformance testing for the relying-party/browser mix you support
- add OIDC front-channel/back-channel logout notifications if relying parties require them

## Important limitations

Production v1 is intentionally single-replica because the broker uses bbolt for local durable state. Multi-replica HA requires a future external/shared data-store design. The broker supports only WebAuthn `fmt: none` and ES256 credentials. It does not implement SAML, SCIM, dynamic client registration, nested OpenLDAP group resolution, group lifecycle sync, or full enterprise lifecycle management.
