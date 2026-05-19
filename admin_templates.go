package main

import "html/template"

//nolint:gochecknoglobals // Parsed templates are immutable and shared by handlers.
var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize {{.ClientID}}</title>
  <link rel="stylesheet" href="/assets/authbroker.css">
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark">AB</div>
        <div>
          <h1 class="brand-title">{{.DisplayName}}</h1>
          <div class="brand-subtitle">Authorize {{.ClientID}}</div>
        </div>
      </div>
      <div class="status-pill">Consent</div>
    </header>
    <section class="panel consent-panel">
      <p class="section-kicker">Authorization request</p>
      <h2 class="panel-title">Allow <code>{{.ClientID}}</code> to access your account?</h2>
      <p class="muted">Signed in as <strong>{{.UserID}}</strong>.</p>
      {{if .Scopes}}
        <p>The application is requesting the following scopes:</p>
        <ul class="scope-list">
          {{range .Scopes}}<li><code>{{.}}</code></li>{{end}}
        </ul>
      {{else}}
        <p class="muted">No explicit scopes were requested.</p>
      {{end}}
      <form method="post" action="/consent" class="actions">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="request_id" value="{{.RequestID}}">
        <button type="submit" name="decision" value="approve">Allow</button>
        <button type="submit" name="decision" value="deny" class="secondary">Deny</button>
      </form>
    </section>
  </main>
</body>
</html>`))

//nolint:gochecknoglobals // Parsed templates are immutable and shared by handlers.
var adminHomeTemplate = template.Must(template.New("admin-home").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin · {{.DisplayName}}</title>
  <link rel="stylesheet" href="/assets/authbroker.css">
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark">AB</div>
        <div>
          <h1 class="brand-title">{{.DisplayName}}</h1>
          <div class="brand-subtitle">Administration</div>
        </div>
      </div>
      <div class="status-pill">Admin: {{.UserID}}</div>
    </header>
    {{if .Flash}}<div class="flash">{{.Flash}}</div>{{end}}
    <nav class="admin-breadcrumb"><a href="/">&larr; Home</a></nav>

    <section class="panel">
      <div class="panel-header">
        <div>
          <p class="section-kicker">OAuth</p>
          <h2 class="panel-title">Clients</h2>
        </div>
        <a class="button" href="/admin/clients/new">New client</a>
      </div>
      {{if .Clients}}
        <div class="token-list">
          {{range .Clients}}
            <article class="token-row">
              <div>
                <h3 class="token-name">{{.ClientID}} {{if .ReadOnly}}<span class="badge">config</span>{{end}}</h3>
                <div class="meta-grid">
                  <div><span class="meta-label">Public</span><span class="meta-value">{{if .Public}}yes{{else}}no{{end}}</span></div>
                  <div><span class="meta-label">PKCE</span><span class="meta-value">{{if .RequirePKCE}}required{{else}}optional{{end}}</span></div>
                  <div><span class="meta-label">Consent</span><span class="meta-value">{{if .RequireConsent}}required{{else}}skipped{{end}}</span></div>
                  <div><span class="meta-label">Scopes</span><span class="meta-value">{{range $i, $scope := .AllowedScopes}}{{if $i}} {{end}}{{$scope}}{{else}}none{{end}}</span></div>
                  <div><span class="meta-label">Offline access</span><span class="meta-value">{{if .AllowOfflineAccess}}allowed{{else}}disabled{{end}}</span></div>
                  <div><span class="meta-label">Client credentials scopes</span><span class="meta-value">{{range $i, $scope := .ClientCredentialsScopes}}{{if $i}} {{end}}{{$scope}}{{else}}none{{end}}</span></div>
                  <div>
                    <span class="meta-label">Redirect URIs</span>
                    {{range .RedirectURIs}}<code class="meta-value">{{.}}</code>{{end}}
                  </div>
                </div>
              </div>
              {{if not .ReadOnly}}
                <form method="post" action="/admin/clients/{{.ClientID}}/delete">
                  <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                  <button type="submit" class="danger">Delete</button>
                </form>
              {{end}}
            </article>
          {{end}}
        </div>
      {{else}}
        <p class="muted">No clients configured.</p>
      {{end}}
    </section>

    <section class="panel">
      <div class="panel-header">
        <div>
          <p class="section-kicker">Access</p>
          <h2 class="panel-title">App token profiles</h2>
        </div>
        <a class="button" href="/admin/app-tokens/new">New app token</a>
      </div>
      {{if .AppTokens}}
        <div class="token-list">
          {{range .AppTokens}}
            <article class="token-row">
              <div>
                <h3 class="token-name">{{.DisplayName}} {{if .ReadOnly}}<span class="badge">config</span>{{end}}</h3>
                <div class="meta-grid">
                  <div><span class="meta-label">ID</span><code class="meta-value">{{.ID}}</code></div>
                  <div><span class="meta-label">Audience</span><code class="meta-value">{{.Audience}}</code></div>
                  <div><span class="meta-label">Client ID</span><code class="meta-value">{{.ClientID}}</code></div>
                  <div><span class="meta-label">Scope</span><code class="meta-value">{{.Scope}}</code></div>
                  <div><span class="meta-label">TTL</span><span class="meta-value">{{.TTLLabel}}</span></div>
                </div>
              </div>
              {{if not .ReadOnly}}
                <form method="post" action="/admin/app-tokens/{{.ID}}/delete">
                  <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                  <button type="submit" class="danger">Delete</button>
                </form>
              {{end}}
            </article>
          {{end}}
        </div>
      {{else}}
        <p class="muted">No app token profiles configured.</p>
      {{end}}
    </section>
  </main>
</body>
</html>`))

//nolint:gochecknoglobals // Parsed templates are immutable and shared by handlers.
var adminClientFormTemplate = template.Must(template.New("admin-client-form").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>New client · {{.DisplayName}}</title>
  <link rel="stylesheet" href="/assets/authbroker.css">
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark">AB</div>
        <div>
          <h1 class="brand-title">{{.DisplayName}}</h1>
          <div class="brand-subtitle">New OAuth client</div>
        </div>
      </div>
      <div class="status-pill">Admin: {{.UserID}}</div>
    </header>
    <nav class="admin-breadcrumb"><a href="/admin">&larr; Admin home</a></nav>
    {{if .Error}}<div class="flash danger">{{.Error}}</div>{{end}}
    <section class="panel">
      <p class="section-kicker">OAuth</p>
      <h2 class="panel-title">Create client</h2>
      <form method="post" action="/admin/clients" class="form-grid">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <label class="field">
          <span>Client ID</span>
          <input name="client_id" required autocomplete="off">
        </label>
        <label class="field">
          <span>Redirect URIs (one per line)</span>
          <textarea name="redirect_uris" rows="3" class="token-output" required></textarea>
        </label>
        <label class="field">
          <span>Post-logout redirect URIs (optional, one per line)</span>
          <textarea name="post_logout_redirect_uris" rows="2" class="token-output"></textarea>
        </label>
        <label class="field">
          <span>Allowed authorization scopes</span>
          <input name="allowed_scopes" autocomplete="off" value="openid profile email groups">
        </label>
        <label class="field">
          <span>Client credentials scopes</span>
          <input name="client_credentials_scopes" autocomplete="off">
        </label>
        <label class="checkbox"><input type="checkbox" name="public"> Public client (no client_secret)</label>
        <label class="checkbox"><input type="checkbox" name="require_pkce" checked> Require PKCE</label>
        <label class="checkbox"><input type="checkbox" name="allow_offline_access"> Allow offline_access refresh tokens</label>
        <label class="checkbox"><input type="checkbox" name="require_consent" checked> Require consent screen</label>
        <div class="actions">
          <button type="submit">Create client</button>
          <a class="button secondary" href="/admin">Cancel</a>
        </div>
      </form>
    </section>
  </main>
</body>
</html>`))

//nolint:gochecknoglobals // Parsed templates are immutable and shared by handlers.
var adminClientCreatedTemplate = template.Must(template.New("admin-client-created").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Client created · {{.DisplayName}}</title>
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
          <div class="brand-subtitle">Client created</div>
        </div>
      </div>
      <div class="status-pill">Admin: {{.UserID}}</div>
    </header>
    <section class="panel">
      <p class="section-kicker">OAuth</p>
      <h2 class="panel-title">{{.ClientID}}</h2>
      {{if .Public}}
        <p class="muted">Public client — no client_secret was generated.</p>
      {{else}}
        <p>This is the only time the client secret will be shown. Copy it now.</p>
        <textarea id="client-secret-value" class="token-output" readonly spellcheck="false" autocomplete="off">{{.ClientSecret}}</textarea>
        <div class="actions">
          <button type="button" class="secondary" data-copy-target="client-secret-value">Copy secret</button>
          <span class="copy-status" data-copy-status></span>
        </div>
      {{end}}
      <div class="actions">
        <a class="button" href="/admin">Back to admin</a>
      </div>
    </section>
  </main>
</body>
</html>`))

//nolint:gochecknoglobals // Parsed templates are immutable and shared by handlers.
var adminAppTokenFormTemplate = template.Must(template.New("admin-app-token-form").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>New app token · {{.DisplayName}}</title>
  <link rel="stylesheet" href="/assets/authbroker.css">
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark">AB</div>
        <div>
          <h1 class="brand-title">{{.DisplayName}}</h1>
          <div class="brand-subtitle">New app token profile</div>
        </div>
      </div>
      <div class="status-pill">Admin: {{.UserID}}</div>
    </header>
    <nav class="admin-breadcrumb"><a href="/admin">&larr; Admin home</a></nav>
    {{if .Error}}<div class="flash danger">{{.Error}}</div>{{end}}
    <section class="panel">
      <p class="section-kicker">Access</p>
      <h2 class="panel-title">Create app token profile</h2>
      <form method="post" action="/admin/app-tokens" class="form-grid">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <label class="field">
          <span>ID</span>
          <input name="id" required autocomplete="off">
        </label>
        <label class="field">
          <span>Display name (optional, defaults to ID)</span>
          <input name="display_name" autocomplete="off">
        </label>
        <label class="field">
          <span>Audience (optional, defaults to ID)</span>
          <input name="audience" autocomplete="off">
          <small class="muted">A confidential OAuth client whose <code>client_id</code> equals this audience may call <code>/oauth2/introspect</code> on tokens minted from this profile, even if it never received the token directly. Pick the audience that names the intended resource server.</small>
        </label>
        <label class="field">
          <span>Client ID (optional, defaults to audience)</span>
          <input name="client_id" autocomplete="off">
        </label>
        <label class="field">
          <span>Scope (defaults to "openid profile email groups")</span>
          <input name="scope" autocomplete="off">
        </label>
        <label class="field">
          <span>Token TTL minutes (defaults to 480)</span>
          <input name="token_ttl_minutes" inputmode="numeric" autocomplete="off">
        </label>
        <div class="actions">
          <button type="submit">Create app token</button>
          <a class="button secondary" href="/admin">Cancel</a>
        </div>
      </form>
    </section>
  </main>
</body>
</html>`))
