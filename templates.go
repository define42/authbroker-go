package main

import "html/template"

//nolint:gochecknoglobals // Parsed templates are immutable and shared by handlers.
var brokerHomeTemplate = template.Must(template.New("broker-home").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.DisplayName}}</title>
  <link rel="stylesheet" href="/assets/authbroker.css">
  <script defer src="/assets/authbroker.js"></script>
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark">AB</div>
        <div>
          <h1 class="brand-title">{{.DisplayName}}</h1>
          <div class="brand-subtitle">{{.Issuer}}</div>
        </div>
      </div>
      {{if .Authenticated}}<div class="status-pill">Signed in</div>{{else}}<div class="status-pill">Signed out</div>{{end}}
    </header>

    {{if .Authenticated}}
      <div class="layout">
        <section class="panel">
          <div class="panel-header">
            <div>
              <p class="section-kicker">Access</p>
              <h2 class="panel-title">App tokens</h2>
            </div>
          </div>
          {{if .AppTokens}}
            <div class="token-list">
              {{range .AppTokens}}
                <article class="token-row">
                  <div>
                    <h3 class="token-name">{{.DisplayName}}</h3>
                    <div class="meta-grid">
                      <div><span class="meta-label">Audience</span><code class="meta-value">{{.Audience}}</code></div>
                      <div><span class="meta-label">Client ID</span><code class="meta-value">{{.ClientID}}</code></div>
                      <div><span class="meta-label">Scope</span><code class="meta-value">{{.Scope}}</code></div>
                      <div><span class="meta-label">TTL</span><span class="meta-value">{{.TokenTTLLabel}}</span></div>
                    </div>
                  </div>
                  <form method="post" action="/app-tokens/{{.ID}}">
                    <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                    <button type="submit">Generate JWT</button>
                  </form>
                </article>
              {{end}}
            </div>
          {{else}}
            <p class="muted">No app token profiles are configured.</p>
          {{end}}

          {{with .IssuedAppToken}}
            <section class="issued-token">
              <p class="section-kicker">Issued token</p>
              <h2 class="panel-title">{{.DisplayName}} JWT</h2>
              <p class="muted">Expires in {{.TokenTTLLabel}}.</p>
              <textarea id="app-token-value" class="token-output" readonly spellcheck="false" autocomplete="off">{{.Token}}</textarea>
              <div class="actions">
                <button type="button" class="secondary" data-copy-target="app-token-value">Copy JWT</button>
                <span class="copy-status" data-copy-status></span>
              </div>
            </section>
          {{end}}
        </section>

        <aside class="side-stack">
          <section class="panel identity-block">
            <p class="section-kicker">Session</p>
            <p class="identity-line">Signed in as <strong>{{.UserID}}</strong>.</p>
            <p class="muted identity-line">Expires {{.ExpiresAt}}</p>
          </section>
          <section class="panel">
            <p class="section-kicker">Discovery</p>
            <p class="muted">JWKS</p>
            <code class="meta-value">{{.Issuer}}/oauth2/jwks</code>
          </section>
          <form method="get" action="/logout">
            <button type="submit" class="secondary">Sign out</button>
          </form>
        </aside>
      </div>
    {{else}}
      <section class="empty-state panel">
        <h2>You are not signed in</h2>
        <p class="muted">Use your directory account to continue.</p>
        <div class="actions">
          <a class="button" href="/login">Sign in</a>
        </div>
      </section>
    {{end}}
  </main>
</body>
</html>`))

//nolint:gochecknoglobals // Parsed templates are immutable and shared by handlers.
var brokerLogoutTemplate = template.Must(template.New("broker-logout").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign out</title>
  <link rel="stylesheet" href="/assets/authbroker.css">
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark">AB</div>
        <div>
          <h1 class="brand-title">{{.DisplayName}}</h1>
          <div class="brand-subtitle">Session control</div>
        </div>
      </div>
    </header>
    <section class="panel logout-panel">
      <p class="section-kicker">Sign out</p>
      <h2 class="panel-title">End this broker session?</h2>
      <p>Signed in as <strong>{{.UserID}}</strong>.</p>
      <form method="post" action="/logout" class="actions logout-actions">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <button type="submit" class="danger">Sign out of authbroker</button>
        <a class="button secondary" href="/">Cancel</a>
      </form>
    </section>
  </main>
</body>
</html>`))

//nolint:gochecknoglobals // Parsed templates are immutable and shared by handlers.
var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in</title>
  <link rel="stylesheet" href="/assets/authbroker.css">
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark">AB</div>
        <div>
          <h1 class="brand-title">{{.DisplayName}}</h1>
          <div class="brand-subtitle">Client: {{.ClientID}}</div>
        </div>
      </div>
      <div class="status-pill">Sign in</div>
    </header>
    <section class="login-panel">
      <p class="section-kicker">Directory login</p>
      <h1>Sign in</h1>
      <form method="post" action="/login" class="form-grid">
        <input type="hidden" name="request_id" value="{{.RequestID}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <label class="field">
          <span>Username</span>
          <input name="username" autocomplete="username" required>
        </label>
        <label class="field">
          <span>Password</span>
          <input name="password" type="password" autocomplete="current-password" required>
        </label>
        <label class="field">
          <span>TOTP code {{if not .TOTPHint}}(if enrolled){{end}}</span>
          <input name="otp" inputmode="numeric" autocomplete="one-time-code">
        </label>
        <div class="actions">
          <button type="submit">Continue</button>
        </div>
      </form>
    </section>
  </main>
</body>
</html>`))
