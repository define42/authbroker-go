package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const sessionCookieName = "test_web_ui_session"

type app struct {
	listen            string
	publicBaseURL     string
	brokerPublicURL   string
	brokerInternalURL string
	clientID          string
	clientSecret      string

	mu       sync.Mutex
	logins   map[string]loginAttempt
	sessions map[string]profile
}

type loginAttempt struct {
	Verifier    string
	Nonce       string
	RedirectURI string
	ExpiresAt   time.Time
}

type profile struct {
	Subject           string
	PreferredUsername string
	Email             string
	Name              string
	Groups            []string
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

func main() {
	a := &app{
		listen:            env("WEB_UI_LISTEN", ":8090"),
		publicBaseURL:     strings.TrimRight(env("PUBLIC_BASE_URL", "http://localhost:8090"), "/"),
		brokerPublicURL:   strings.TrimRight(env("AUTHBROKER_PUBLIC_URL", "http://localhost:8080"), "/"),
		brokerInternalURL: strings.TrimRight(env("AUTHBROKER_INTERNAL_URL", "http://localhost:8080"), "/"),
		clientID:          env("OAUTH_CLIENT_ID", "test-web-ui"),
		clientSecret:      env("OAUTH_CLIENT_SECRET", "test-web-ui-secret"),
		logins:            map[string]loginAttempt{},
		sessions:          map[string]profile{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.handleIndex)
	mux.HandleFunc("GET /login", a.handleLogin)
	mux.HandleFunc("GET /callback", a.handleCallback)
	mux.HandleFunc("POST /logout", a.handleLogout)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	srv := &http.Server{
		Addr:              a.listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("test web ui listening on %s", a.listen)
	log.Fatal(srv.ListenAndServe())
}

func (a *app) handleIndex(w http.ResponseWriter, r *http.Request) {
	p, ok := a.currentProfile(r)
	data := map[string]any{
		"Authenticated": ok,
		"Profile":       p,
		"BrokerURL":     a.brokerPublicURL,
	}
	if err := pageTemplate.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := randomB64(32)
	nonce := randomB64(24)
	verifier := randomB64(48)
	challengeHash := sha256.Sum256([]byte(verifier))
	redirectURI := a.publicBaseURL + "/callback"

	a.mu.Lock()
	a.logins[state] = loginAttempt{
		Verifier:    verifier,
		Nonce:       nonce,
		RedirectURI: redirectURI,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}
	a.mu.Unlock()

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {a.clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile email groups"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challengeHash[:])},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, a.brokerPublicURL+"/oauth2/authorize?"+q.Encode(), http.StatusFound)
}

func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	if oauthErr := r.URL.Query().Get("error"); oauthErr != "" {
		http.Error(w, oauthErr+": "+r.URL.Query().Get("error_description"), http.StatusBadRequest)
		return
	}
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		http.Error(w, "callback missing state or code", http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	attempt, ok := a.logins[state]
	delete(a.logins, state)
	a.mu.Unlock()
	if !ok || time.Now().After(attempt.ExpiresAt) {
		http.Error(w, "login state expired", http.StatusBadRequest)
		return
	}

	tokens, err := a.exchangeCode(r.Context(), code, attempt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	idClaims, err := decodeJWTClaims(tokens.IDToken)
	if err != nil {
		http.Error(w, "decode id token: "+err.Error(), http.StatusBadGateway)
		return
	}
	if got, _ := idClaims["nonce"].(string); got != attempt.Nonce {
		http.Error(w, "id token nonce mismatch", http.StatusBadGateway)
		return
	}

	p, err := a.userInfo(r.Context(), tokens.AccessToken)
	if err != nil {
		p = profileFromClaims(idClaims)
	}
	sessionID := randomB64(32)
	a.mu.Lock()
	a.sessions[sessionID] = p
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(8 * time.Hour),
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		a.mu.Lock()
		delete(a.sessions, cookie.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *app) exchangeCode(ctx context.Context, code string, attempt loginAttempt) (tokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {attempt.RedirectURI},
		"code_verifier": {attempt.Verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.brokerInternalURL+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(a.clientID, a.clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tokenResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return tokenResponse{}, fmt.Errorf("token exchange failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tokens tokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return tokenResponse{}, err
	}
	if tokens.AccessToken == "" || tokens.IDToken == "" {
		return tokenResponse{}, fmt.Errorf("token response missing access_token or id_token")
	}
	return tokens, nil
}

func (a *app) userInfo(ctx context.Context, accessToken string) (profile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.brokerInternalURL+"/oauth2/userinfo", nil)
	if err != nil {
		return profile{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return profile{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return profile{}, fmt.Errorf("userinfo failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var claims map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return profile{}, err
	}
	return profileFromClaims(claims), nil
}

func (a *app) currentProfile(r *http.Request) (profile, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return profile{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.sessions[cookie.Value]
	return p, ok
}

func profileFromClaims(claims map[string]any) profile {
	sub, _ := claims["sub"].(string)
	username, _ := claims["preferred_username"].(string)
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	return profile{Subject: sub, PreferredUsername: username, Email: email, Name: name, Groups: stringSliceClaim(claims["groups"])}
}

func stringSliceClaim(value any) []string {
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func decodeJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("bad JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func randomB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authbroker Test UI</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 0; background: #f6f7f9; color: #17202a; }
    main { max-width: 680px; margin: 64px auto; padding: 32px; background: #fff; border: 1px solid #d9dee5; border-radius: 8px; }
    h1 { margin: 0 0 8px; font-size: 28px; }
    p { line-height: 1.5; }
    dl { display: grid; grid-template-columns: 170px 1fr; gap: 10px 16px; margin: 24px 0; }
    dt { color: #5a6675; }
    dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; }
    a.button, button { display: inline-block; border: 0; border-radius: 6px; background: #185abc; color: #fff; padding: 10px 14px; font: inherit; text-decoration: none; cursor: pointer; }
    form { margin-top: 20px; }
    .muted { color: #5a6675; }
  </style>
</head>
<body>
  <main>
    <h1>Authbroker Test UI</h1>
    {{if .Authenticated}}
      <p class="muted">Authenticated through {{.BrokerURL}}.</p>
      <dl>
        <dt>Subject</dt><dd>{{.Profile.Subject}}</dd>
        <dt>Username</dt><dd>{{.Profile.PreferredUsername}}</dd>
        <dt>Email</dt><dd>{{.Profile.Email}}</dd>
        <dt>Name</dt><dd>{{.Profile.Name}}</dd>
        <dt>Groups</dt><dd>{{range $i, $group := .Profile.Groups}}{{if $i}}, {{end}}{{$group}}{{else}}none{{end}}</dd>
      </dl>
      <form method="post" action="/logout"><button type="submit">Sign out</button></form>
    {{else}}
      <p class="muted">Start an OAuth2/OIDC authorization-code flow with PKCE against the local authbroker.</p>
      <p><a class="button" href="/login">Sign in with authbroker</a></p>
      <p class="muted">Try <strong>ingestuser</strong> / <strong>dogood</strong> from the bundled GLAUTH directory.</p>
    {{end}}
  </main>
</body>
</html>`))
