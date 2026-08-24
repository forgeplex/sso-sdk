package sso_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	sso "github.com/forgeplex/sso-sdk"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestOIDCAuthorizationCodePKCEFlow(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	var expectedNonce string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, w, map[string]any{
				"issuer":                                server.URL,
				"authorization_endpoint":                server.URL + "/authorize",
				"token_endpoint":                        server.URL + "/oauth/token",
				"userinfo_endpoint":                     server.URL + "/userinfo",
				"jwks_uri":                              server.URL + "/.well-known/jwks.json",
				"end_session_endpoint":                  server.URL + "/oidc/logout",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/.well-known/jwks.json":
			writeJSON(t, w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}}})
		case "/oauth/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("ParseForm: %v", err)
			}
			if r.Form.Get("code_verifier") == "" {
				t.Error("token request missing code_verifier")
			}
			if r.Form.Get("client_id") != "web-app" || r.Form.Get("client_secret") != "secret" {
				t.Errorf("client auth = %s/%s", r.Form.Get("client_id"), r.Form.Get("client_secret"))
			}
			now := time.Now()
			raw, signErr := jwt.Signed(signer).Claims(jwt.Claims{
				Issuer: server.URL, Subject: "user-123", Audience: jwt.Audience{"web-app"},
				IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Hour)),
			}).Claims(map[string]any{"nonce": expectedNonce, "email": "user@example.com"}).Serialize()
			if signErr != nil {
				t.Fatalf("sign id token: %v", signErr)
			}
			writeJSON(t, w, map[string]any{"access_token": "access-token", "token_type": "Bearer", "expires_in": 3600, "id_token": raw})
		case "/userinfo":
			if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
				t.Errorf("userinfo Authorization = %q", got)
			}
			writeJSON(t, w, map[string]any{"sub": "user-123", "email": "user@example.com"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := sso.NewOIDC(context.Background(), sso.OIDCConfig{
		IssuerURL: server.URL, ClientID: "web-app", ClientSecret: "secret",
		RedirectURL: "https://app.example.com/callback", TokenEndpointAuthMethod: "client_secret_post",
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.BeginLogin(sso.AuthorizationOptions{Audience: "https://api.example.com/", Organization: "org-1"})
	if err != nil {
		t.Fatal(err)
	}
	expectedNonce = request.Nonce
	authorizeURL, err := url.Parse(request.URL)
	if err != nil {
		t.Fatal(err)
	}
	query := authorizeURL.Query()
	for key, want := range map[string]string{"response_type": "code", "client_id": "web-app", "code_challenge_method": "S256", "nonce": request.Nonce, "state": request.State, "audience": "https://api.example.com/", "organization": "org-1"} {
		if got := query.Get(key); got != want {
			t.Errorf("authorize %s = %q, want %q", key, got, want)
		}
	}
	if query.Get("code_challenge") == "" || request.CodeVerifier == "" {
		t.Fatal("PKCE values are empty")
	}
	if _, err = client.Exchange(context.Background(), "code", "wrong-state", request); err == nil {
		t.Fatal("state mismatch accepted")
	}
	session, err := client.Exchange(context.Background(), "code", request.State, request)
	if err != nil {
		t.Fatal(err)
	}
	if session.Subject != "user-123" || session.AccessToken != "access-token" || session.Claims["email"] != "user@example.com" {
		t.Fatalf("session = %+v", session)
	}
	var userInfo struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
	}
	if err = client.UserInfo(context.Background(), session, &userInfo); err != nil {
		t.Fatal(err)
	}
	if userInfo.Subject != session.Subject || userInfo.Email != "user@example.com" {
		t.Fatalf("userinfo = %+v", userInfo)
	}
	logout, err := client.LogoutURL(session.IDToken, "https://app.example.com/signed-out", "logout-state")
	if err != nil {
		t.Fatal(err)
	}
	logoutURL, _ := url.Parse(logout)
	if logoutURL.Path != "/oidc/logout" || logoutURL.Query().Get("state") != "logout-state" {
		t.Fatalf("logout URL = %s", logout)
	}
}
