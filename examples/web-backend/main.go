package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	sso "github.com/forgeplex/sso-sdk"
)

const cookieName = "example_session"

type pendingLogin struct {
	request   sso.AuthorizationRequest
	createdAt time.Time
}

type store struct {
	mu       sync.Mutex
	pending  map[string]pendingLogin
	sessions map[string]sso.Session
}

type app struct {
	oidc          *sso.OIDCClient
	store         *store
	secureCookies bool
	postLogoutURL string
}

func main() {
	redirectURL := env("SSO_REDIRECT_URL", "http://localhost:3000/callback")
	postLogoutURL := env("SSO_POST_LOGOUT_REDIRECT_URL", "http://localhost:3000/")
	issuer := requiredEnv("SSO_ISSUER")
	clientID := requiredEnv("SSO_CLIENT_ID")
	clientSecret := requiredEnv("SSO_CLIENT_SECRET")

	oidcClient, err := sso.NewOIDC(context.Background(), sso.OIDCConfig{
		IssuerURL:               issuer,
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		RedirectURL:             redirectURL,
		TokenEndpointAuthMethod: env("SSO_TOKEN_AUTH_METHOD", "client_secret_post"),
	})
	if err != nil {
		log.Fatal(err)
	}

	a := &app{
		oidc: oidcClient,
		store: &store{
			pending:  make(map[string]pendingLogin),
			sessions: make(map[string]sso.Session),
		},
		secureCookies: strings.HasPrefix(redirectURL, "https://"),
		postLogoutURL: postLogoutURL,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.home)
	mux.HandleFunc("GET /login", a.login)
	mux.HandleFunc("GET /callback", a.callback)
	mux.HandleFunc("GET /me", a.me)
	mux.HandleFunc("POST /logout", a.logout)

	server := &http.Server{
		Addr:              env("LISTEN_ADDR", ":3000"),
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("示例已启动：http://localhost%s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func (a *app) home(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = homePage.Execute(w, nil)
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	request, err := a.oidc.BeginLogin(sso.AuthorizationOptions{
		Audience:     r.URL.Query().Get("audience"),
		Organization: r.URL.Query().Get("organization"),
		Connection:   r.URL.Query().Get("connection"),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sessionID, err := randomID()
	if err != nil {
		http.Error(w, "无法创建登录会话", http.StatusInternalServerError)
		return
	}
	a.store.mu.Lock()
	a.store.pending[sessionID] = pendingLogin{request: request, createdAt: time.Now()}
	a.store.mu.Unlock()
	a.setCookie(w, sessionID, 10*time.Minute)
	http.Redirect(w, r, request.URL, http.StatusFound)
}

func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	if providerError := r.URL.Query().Get("error"); providerError != "" {
		http.Error(w, "SSO 拒绝登录："+providerError, http.StatusUnauthorized)
		return
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "登录会话不存在", http.StatusBadRequest)
		return
	}
	a.store.mu.Lock()
	pending, ok := a.store.pending[cookie.Value]
	delete(a.store.pending, cookie.Value)
	a.store.mu.Unlock()
	if !ok || time.Since(pending.createdAt) > 10*time.Minute {
		http.Error(w, "登录会话已过期", http.StatusBadRequest)
		return
	}

	session, err := a.oidc.Exchange(r.Context(), r.URL.Query().Get("code"), r.URL.Query().Get("state"), pending.request)
	if err != nil {
		log.Printf("登录校验失败：%v", err)
		http.Error(w, "登录校验失败", http.StatusUnauthorized)
		return
	}

	// 登录成功后轮换 Session ID，避免固定会话攻击。
	newSessionID, err := randomID()
	if err != nil {
		http.Error(w, "无法创建用户会话", http.StatusInternalServerError)
		return
	}
	a.store.mu.Lock()
	a.store.sessions[newSessionID] = session
	a.store.mu.Unlock()
	a.setCookie(w, newSessionID, 8*time.Hour)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *app) me(w http.ResponseWriter, r *http.Request) {
	session, err := a.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not_authenticated"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subject": session.Subject,
		"claims":  session.Claims,
		"expiry":  session.Expiry,
	})
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	a.store.mu.Lock()
	session, ok := a.store.sessions[cookie.Value]
	delete(a.store.sessions, cookie.Value)
	a.store.mu.Unlock()
	a.clearCookie(w)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	logoutURL, err := a.oidc.LogoutURL(session.IDToken, a.postLogoutURL, "")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, logoutURL, http.StatusSeeOther)
}

func (a *app) session(r *http.Request) (sso.Session, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return sso.Session{}, err
	}
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	session, ok := a.store.sessions[cookie.Value]
	if !ok {
		return sso.Session{}, errors.New("session 不存在")
	}
	if !session.Expiry.IsZero() && time.Now().After(session.Expiry) {
		delete(a.store.sessions, cookie.Value)
		return sso.Session{}, errors.New("session 已过期")
	}
	return session, nil
}

func (a *app) setCookie(w http.ResponseWriter, value string, lifetime time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(lifetime.Seconds()),
		HttpOnly: true,
		Secure:   a.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *app) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func randomID() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func requiredEnv(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		log.Fatalf("缺少环境变量 %s", name)
	}
	return value
}

var homePage = template.Must(template.New("home").Parse(`<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Forgeplex SSO Go 示例</title></head>
<body style="font:16px system-ui;max-width:760px;margin:64px auto;padding:0 24px">
  <h1>Go 后端托管登录</h1>
  <p>OIDC Token 留在后端，浏览器仅持有 HttpOnly Session Cookie。</p>
  <p><a href="/login">登录</a></p>
  <form method="post" action="/logout"><button type="submit">退出</button></form>
  <h2>当前用户</h2><pre id="profile">正在读取 /me ...</pre>
  <script>fetch('/me').then(async r => ({ok:r.ok, body:await r.json()})).then(x => {
    document.querySelector('#profile').textContent = JSON.stringify(x.body, null, 2)
  }).catch(e => document.querySelector('#profile').textContent = String(e))</script>
</body></html>`))
