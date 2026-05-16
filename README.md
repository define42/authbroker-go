# Go authentication broker: OAuth2/OIDC + LDAP/AD + JWT/JWKS + PKCE + TOTP + WebAuthn

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
go run . -config config.example.json -data data.json
```

Open the OIDC discovery document:

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

JWKS:

```bash
curl http://localhost:8080/oauth2/jwks
```

## Docker Compose demo

The compose stack starts:

- `glauth` as the LDAPS server, using the users in `testldap/default-config.cfg`
- `authbroker` on <http://localhost:8080>
- `test-web-ui` on <http://localhost:8090>

```bash
docker compose up --build
```

Open <http://localhost:8090> and sign in through authbroker. Useful test users:

```text
ingestuser / dogood
johndoe / dogood
serviceuser / mysecret
```

The compose broker config lives in `compose/authbroker.config.json`. The test UI uses `http://localhost:8080` for browser redirects and `http://authbroker:8080` for server-side token and UserInfo calls inside the Docker network, then displays the LDAP-backed profile and groups.

## Generate a persistent signing key

By default the server generates an ephemeral RSA key on startup. For real use, generate a stable key:

```bash
go run . -generate-key > signing-key.pem
```

Then paste the PEM content into `signing_key_pem` in your JSON config, escaping newlines as `\n`, or extend `loadConfig` to read the key from a secret-mounted file.

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
  "timeout_seconds": 5
}
```

The broker will bind as:

```text
<username>@example.com
```

It then searches below `base_dn`, escapes the `{login}` value, and copies the configured LDAP attributes into OIDC `email`, `name`, and `groups` claims.

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

Profile lookup is optional. If `base_dn` and `user_filter` are omitted, the broker only performs the bind and falls back to the submitted username plus `domain_suffix` for profile claims. Use `"start_tls": true` only with `ldap://` URLs; `ldaps://` starts TLS during dial. This starter does not implement group sync, nested AD group resolution, or Kerberos/SPNEGO. Add those as separate federation modules.

## TOTP MFA

After login, enroll TOTP using the session cookie:

```bash
curl -X POST -b cookies.txt -c cookies.txt http://localhost:8080/mfa/totp/enroll
```

The response contains an `otpauth_uri` that can be added to an authenticator app. Once a user has a TOTP secret, the login form requires a code.

## WebAuthn/passkeys

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

## Production hardening checklist

Before production, add at least:

- TLS-only deployment behind a trusted ingress/proxy
- persistent database for sessions, authorization codes, refresh tokens, users, MFA and WebAuthn credentials
- encrypted secret storage for signing keys and LDAP bind secrets
- key rotation and multiple JWKS keys
- consent screens and client administration
- rate limiting and brute-force protection
- audit logs
- CSRF protection for browser form endpoints
- stricter Content-Security-Policy
- LDAP group mapping and nested AD group support
- OpenID Foundation conformance testing
- WebAuthn conformance testing and broader attestation support
- refresh-token reuse detection
- back-channel logout/front-channel logout if required

## Important limitations

This is a learning/reference implementation. It supports only WebAuthn `fmt: none` and ES256 credentials. It does not implement SAML, SCIM, dynamic client registration, token introspection, consent, or full enterprise lifecycle management.
