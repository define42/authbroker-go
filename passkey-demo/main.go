package main

import (
	"bytes"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	brokerSessionCookieName = "broker_session"
	brokerCSRFCookieName    = "broker_csrf"
	csrfFormField           = "csrf_token"
)

type app struct {
	listen            string
	publicBaseURL     string
	brokerPublicURL   string
	brokerInternalURL string
	brokerInternal    *url.URL
}

type pageData struct {
	BrokerURL     string
	PublicBaseURL string
	SignedIn      bool
	UserID        string
	CSRFToken     string
	HasCookie     bool
	Error         string
}

func main() {
	internal := strings.TrimRight(env("AUTHBROKER_INTERNAL_URL", "http://localhost:8080"), "/")
	internalURL, err := url.Parse(internal)
	if err != nil {
		log.Fatal(err)
	}
	a := &app{
		listen:            env("PASSKEY_DEMO_LISTEN", ":8091"),
		publicBaseURL:     strings.TrimRight(env("PUBLIC_BASE_URL", "http://localhost:8091"), "/"),
		brokerPublicURL:   strings.TrimRight(env("AUTHBROKER_PUBLIC_URL", "http://localhost:8080"), "/"),
		brokerInternalURL: internal,
		brokerInternal:    internalURL,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.handleIndex)
	mux.HandleFunc("POST /password-login", a.handlePasswordLogin)
	mux.HandleFunc("POST /logout", a.handleLogout)
	mux.Handle("POST /webauthn/", a.webauthnProxy())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	srv := &http.Server{
		Addr:              a.listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("passkey demo listening on %s", a.listen)
	log.Fatal(srv.ListenAndServe())
}

func (a *app) handleIndex(w http.ResponseWriter, r *http.Request) {
	userID, csrfToken, signedIn := a.currentBrokerSession(r)
	_, hasCookie := brokerSessionCookie(r)
	data := pageData{
		BrokerURL:     a.brokerPublicURL,
		PublicBaseURL: a.publicBaseURL,
		SignedIn:      signedIn,
		UserID:        userID,
		CSRFToken:     csrfToken,
		HasCookie:     hasCookie,
		Error:         r.URL.Query().Get("error"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplate.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *app) handlePasswordLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	form := url.Values{
		"username": {r.Form.Get("username")},
		"password": {r.Form.Get("password")},
		"otp":      {r.Form.Get("otp")},
	}
	csrfToken, csrfCookie, err := a.loginCSRF(r)
	if err != nil {
		http.Redirect(w, r, "/?error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	form.Set(csrfFormField, csrfToken)
	resp, body, err := a.forwardForm(r, http.MethodPost, "/login", form, csrfCookie)
	if err != nil {
		http.Redirect(w, r, "/?error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	defer resp.Body.Close()
	copySetCookie(w, resp)
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		http.Redirect(w, r, "/?error="+url.QueryEscape(strings.TrimSpace(string(body))), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	resp, _, err := a.forwardForm(r, http.MethodPost, "/oauth2/logout", nil)
	if err != nil {
		clearBrokerCookie(w)
		http.Redirect(w, r, "/?error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	defer resp.Body.Close()
	copySetCookie(w, resp)
	clearBrokerCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *app) forwardForm(r *http.Request, method, path string, form url.Values, extraCookies ...*http.Cookie) (*http.Response, []byte, error) {
	body := bytes.NewBufferString("")
	if form != nil {
		body = bytes.NewBufferString(form.Encode())
	}
	req, err := http.NewRequestWithContext(r.Context(), method, a.brokerInternalURL+path, body)
	if err != nil {
		return nil, nil, err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie, ok := brokerSessionCookie(r); ok {
		req.AddCookie(cookie)
	}
	for _, cookie := range extraCookies {
		if cookie != nil {
			req.AddCookie(cookie)
		}
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return resp, nil, readErr
	}
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return resp, bodyBytes, nil
}

func (a *app) loginCSRF(r *http.Request) (string, *http.Cookie, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, a.brokerInternalURL+"/login", nil)
	if err != nil {
		return "", nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
		return "", nil, &brokerError{message: "load login csrf", status: resp.StatusCode, body: string(body)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", nil, err
	}
	token := csrfTokenFromHTML(body)
	cookie := responseCookie(resp, brokerCSRFCookieName)
	if token == "" || cookie == nil {
		return "", nil, &brokerError{message: "login csrf token missing", status: resp.StatusCode}
	}
	return token, cookie, nil
}

func (a *app) webauthnProxy() http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(a.brokerInternal)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = a.brokerInternal.Host
		req.URL.Scheme = a.brokerInternal.Scheme
		req.URL.Host = a.brokerInternal.Host
	}
	return proxy
}

func (a *app) currentBrokerSession(r *http.Request) (string, string, bool) {
	cookie, ok := brokerSessionCookie(r)
	if !ok {
		return "", "", false
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, a.brokerInternalURL+"/", nil)
	if err != nil {
		return "", "", false
	}
	req.AddCookie(cookie)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	matches := signedInPattern.FindSubmatch(body)
	if len(matches) != 2 {
		return "", "", false
	}
	return string(matches[1]), csrfTokenFromHTML(body), true
}

func brokerSessionCookie(r *http.Request) (*http.Cookie, bool) {
	cookie, err := r.Cookie(brokerSessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	return cookie, true
}

func responseCookie(resp *http.Response, name string) *http.Cookie {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func copySetCookie(w http.ResponseWriter, resp *http.Response) {
	for _, cookie := range resp.Header.Values("Set-Cookie") {
		w.Header().Add("Set-Cookie", cookie)
	}
}

func clearBrokerCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     brokerSessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func env(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

var signedInPattern = regexp.MustCompile(`Signed in as <strong>([^<]+)</strong>`)
var csrfTokenPattern = regexp.MustCompile(`<input[^>]*name="csrf_token"[^>]*value="([^"]*)"`)

func csrfTokenFromHTML(body []byte) string {
	matches := csrfTokenPattern.FindSubmatch(body)
	if len(matches) != 2 {
		return ""
	}
	return string(matches[1])
}

type brokerError struct {
	message string
	status  int
	body    string
}

func (e *brokerError) Error() string {
	body := strings.TrimSpace(e.body)
	if body == "" {
		return e.message
	}
	return e.message + ": status=" + http.StatusText(e.status) + " body=" + body
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {{if .CSRFToken}}<meta name="broker-csrf-token" content="{{.CSRFToken}}">{{end}}
  <title>Passkey Demo</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 0; background: #f5f7fb; color: #16202a; }
    main { max-width: 780px; margin: 48px auto; padding: 28px; background: #fff; border: 1px solid #d8dee8; border-radius: 8px; }
    h1 { margin: 0 0 8px; font-size: 28px; }
    h2 { margin-top: 28px; font-size: 18px; }
    p { line-height: 1.5; }
    label { display: block; margin: 12px 0; color: #334155; }
    input { width: 100%; box-sizing: border-box; margin-top: 4px; padding: 9px 10px; border: 1px solid #bcc7d6; border-radius: 6px; font: inherit; }
    button { border: 0; border-radius: 6px; background: #135e4f; color: #fff; padding: 10px 14px; font: inherit; cursor: pointer; }
    button.secondary { background: #185abc; }
    button.warn { background: #9f2d2d; }
    code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .muted { color: #64748b; }
    .status { padding: 12px 14px; background: #eef6f2; border: 1px solid #cfe8dc; border-radius: 6px; margin: 18px 0; }
    .error { padding: 12px 14px; background: #fff1f2; border: 1px solid #fecdd3; border-radius: 6px; margin: 18px 0; color: #9f1239; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
    @media (max-width: 760px) { .grid { grid-template-columns: 1fr; } main { margin: 0; min-height: 100vh; border: 0; border-radius: 0; } }
  </style>
</head>
<body>
  <main>
    <h1>Passkey Demo</h1>
    <p class="muted">Uses authbroker WebAuthn endpoints through this app origin: <span class="mono">{{.PublicBaseURL}}</span></p>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <div class="status">
      {{if .SignedIn}}
        Broker session: signed in as <strong>{{.UserID}}</strong>.
      {{else if .HasCookie}}
        Broker session cookie exists, but the session was not accepted by authbroker.
      {{else}}
        Broker session: not signed in.
      {{end}}
    </div>

    <div class="grid">
      <section>
        <h2>1. Password sign-in for enrollment</h2>
        <p class="muted">Sign in with LDAP first, then register a passkey for that account.</p>
        <form method="post" action="/password-login">
          <label>Username<input name="username" autocomplete="username" required value="johndoe"></label>
          <label>Password<input name="password" type="password" autocomplete="current-password" required value="dogood"></label>
          <label>TOTP code<input name="otp" inputmode="numeric" autocomplete="one-time-code"></label>
          <button type="submit">Password sign in</button>
        </form>
        <p><button class="secondary" id="register-passkey" type="button">Register passkey</button></p>
      </section>

      <section>
        <h2>2. Passkey sign-in</h2>
        <p class="muted">After registration, sign out and use the passkey for the same username.</p>
        <label>Username<input id="passkey-username" autocomplete="username webauthn" value="johndoe"></label>
        <p><button class="secondary" id="login-passkey" type="button">Sign in with passkey</button></p>
        <form method="post" action="/logout">
          <button class="warn" type="submit">Sign out demo broker session</button>
        </form>
      </section>
    </div>

    <p id="message" class="muted"></p>
  </main>
<script>
const message = document.getElementById('message');
const csrfMeta = document.querySelector('meta[name="broker-csrf-token"]');
const brokerCSRFToken = csrfMeta ? csrfMeta.content : '';
function setMessage(text) { message.textContent = text; }
function b64urlToBuf(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
async function postJSON(path, body) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (brokerCSRFToken) headers['X-CSRF-Token'] = brokerCSRFToken;
  const res = await fetch(path, {
    method: 'POST',
    headers,
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'same-origin'
  });
  const text = await res.text();
  if (!res.ok) throw new Error(text || res.statusText);
  return text ? JSON.parse(text) : {};
}
function credentialToJSON(cred) {
  const response = {};
  if (cred.response.clientDataJSON) response.clientDataJSON = bufToB64url(cred.response.clientDataJSON);
  if (cred.response.attestationObject) response.attestationObject = bufToB64url(cred.response.attestationObject);
  if (cred.response.authenticatorData) response.authenticatorData = bufToB64url(cred.response.authenticatorData);
  if (cred.response.signature) response.signature = bufToB64url(cred.response.signature);
  if (cred.response.userHandle) response.userHandle = bufToB64url(cred.response.userHandle);
  return {id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type, response};
}
document.getElementById('register-passkey').addEventListener('click', async () => {
  try {
    setMessage('Starting passkey registration...');
    const opts = await postJSON('/webauthn/register/begin');
    const publicKey = opts.publicKey;
    publicKey.challenge = b64urlToBuf(publicKey.challenge);
    publicKey.user.id = b64urlToBuf(publicKey.user.id);
    publicKey.excludeCredentials = (publicKey.excludeCredentials || []).map(c => ({...c, id: b64urlToBuf(c.id)}));
    const cred = await navigator.credentials.create({publicKey});
    await postJSON('/webauthn/register/finish', credentialToJSON(cred));
    setMessage('Passkey registered. You can sign out and use passkey sign-in.');
  } catch (err) {
    setMessage('Registration failed: ' + err.message);
  }
});
document.getElementById('login-passkey').addEventListener('click', async () => {
  try {
    const username = document.getElementById('passkey-username').value.trim();
    if (!username) throw new Error('username is required');
    setMessage('Starting passkey sign-in...');
    const opts = await postJSON('/webauthn/login/begin', {username});
    const publicKey = opts.publicKey;
    publicKey.challenge = b64urlToBuf(publicKey.challenge);
    publicKey.allowCredentials = (publicKey.allowCredentials || []).map(c => ({...c, id: b64urlToBuf(c.id)}));
    const cred = await navigator.credentials.get({publicKey});
    await postJSON('/webauthn/login/finish', credentialToJSON(cred));
    setMessage('Passkey sign-in succeeded.');
    window.location.reload();
  } catch (err) {
    setMessage('Passkey sign-in failed: ' + err.message);
  }
});
</script>
</body>
</html>`))
