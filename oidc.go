package sso

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig configures an interactive OpenID Connect client.
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	// TokenEndpointAuthMethod accepts none, client_secret_post, or
	// client_secret_basic. It must match the application registration.
	TokenEndpointAuthMethod string
	HTTPClient              *http.Client
}

// OIDCClient implements Authorization Code flow with PKCE and ID token checks.
type OIDCClient struct {
	provider           *oidc.Provider
	verifier           *oidc.IDTokenVerifier
	oauth              oauth2.Config
	http               *http.Client
	endSessionEndpoint string
}

// AuthorizationOptions adds product-level parameters to an authorization
// request without weakening the generated state, nonce, or PKCE values.
type AuthorizationOptions struct {
	Audience     string
	Organization string
	Connection   string
	Prompt       string
}

// AuthorizationRequest must be stored in the application's server-side session
// until the callback. State, Nonce, and CodeVerifier are security secrets.
type AuthorizationRequest struct {
	URL          string
	State        string
	Nonce        string
	CodeVerifier string
}

// Session is a verified OIDC token response.
type Session struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	Expiry       time.Time
	IDToken      string
	Subject      string
	Claims       map[string]any
}

// NewOIDC discovers the Realm endpoints and constructs a login client.
func NewOIDC(ctx context.Context, cfg OIDCConfig) (*OIDCClient, error) {
	issuer, err := parseBaseURL("IssuerURL", cfg.IssuerURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("sso: ClientID 不能为空")
	}
	if strings.TrimSpace(cfg.RedirectURL) == "" {
		return nil, errors.New("sso: RedirectURL 不能为空")
	}
	if _, err = parseBaseURL("RedirectURL", cfg.RedirectURL); err != nil {
		return nil, err
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	discoveryCtx := oidc.ClientContext(ctx, httpClient)
	provider, err := oidc.NewProvider(discoveryCtx, strings.TrimRight(issuer.String(), "/"))
	if err != nil {
		return nil, fmt.Errorf("sso: 读取 OIDC Discovery: %w", err)
	}
	endpoint := provider.Endpoint()
	switch cfg.TokenEndpointAuthMethod {
	case "", "client_secret_basic":
		endpoint.AuthStyle = oauth2.AuthStyleInHeader
	case "none", "client_secret_post":
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	default:
		return nil, fmt.Errorf("sso: 不支持 token_endpoint_auth_method %q", cfg.TokenEndpointAuthMethod)
	}
	if cfg.TokenEndpointAuthMethod != "none" && strings.TrimSpace(cfg.ClientSecret) == "" {
		return nil, errors.New("sso: 机密客户端必须提供 ClientSecret")
	}
	scopes := append([]string(nil), cfg.Scopes...)
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	if !contains(scopes, oidc.ScopeOpenID) {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}
	var metadata struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err = provider.Claims(&metadata); err != nil {
		return nil, fmt.Errorf("sso: 读取 OIDC 元数据: %w", err)
	}
	client := &OIDCClient{
		provider:           provider,
		verifier:           provider.VerifierContext(discoveryCtx, &oidc.Config{ClientID: cfg.ClientID}),
		http:               httpClient,
		endSessionEndpoint: metadata.EndSessionEndpoint,
		oauth:              oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL, Scopes: scopes, Endpoint: endpoint},
	}
	return client, nil
}

// BeginLogin creates a fresh authorization URL. Store the returned request in
// a server-side session and never put CodeVerifier in a browser cookie or URL.
func (c *OIDCClient) BeginLogin(options AuthorizationOptions) (AuthorizationRequest, error) {
	state, err := randomURLString(32)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	nonce, err := randomURLString(32)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	verifier, err := randomURLString(48)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	authOptions := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce)}
	for key, value := range map[string]string{"audience": options.Audience, "organization": options.Organization, "connection": options.Connection, "prompt": options.Prompt} {
		if value != "" {
			authOptions = append(authOptions, oauth2.SetAuthURLParam(key, value))
		}
	}
	return AuthorizationRequest{URL: c.oauth.AuthCodeURL(state, authOptions...), State: state, Nonce: nonce, CodeVerifier: verifier}, nil
}

// Exchange validates callback state, exchanges the code with PKCE, verifies the
// ID token signature/issuer/audience/expiry/nonce, and checks at_hash if present.
func (c *OIDCClient) Exchange(ctx context.Context, code, returnedState string, request AuthorizationRequest) (Session, error) {
	if subtle.ConstantTimeCompare([]byte(returnedState), []byte(request.State)) != 1 {
		return Session{}, errors.New("sso: OIDC state 不匹配")
	}
	ctx = oidc.ClientContext(ctx, c.http)
	token, err := c.oauth.Exchange(ctx, code, oauth2.VerifierOption(request.CodeVerifier))
	if err != nil {
		return Session{}, fmt.Errorf("sso: 交换授权码: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Session{}, errors.New("sso: 令牌响应缺少 id_token")
	}
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Session{}, fmt.Errorf("sso: 验证 id_token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(request.Nonce)) != 1 {
		return Session{}, errors.New("sso: ID Token nonce 不匹配")
	}
	if idToken.AccessTokenHash != "" {
		if err = idToken.VerifyAccessToken(token.AccessToken); err != nil {
			return Session{}, fmt.Errorf("sso: 验证 access_token 绑定: %w", err)
		}
	}
	claims := make(map[string]any)
	if err = idToken.Claims(&claims); err != nil {
		return Session{}, fmt.Errorf("sso: 解码 ID Token claims: %w", err)
	}
	return Session{AccessToken: token.AccessToken, TokenType: token.TokenType, RefreshToken: token.RefreshToken, Expiry: token.Expiry, IDToken: rawIDToken, Subject: idToken.Subject, Claims: claims}, nil
}

// UserInfo fetches claims and verifies that their subject matches the ID token.
func (c *OIDCClient) UserInfo(ctx context.Context, session Session, out any) error {
	if session.AccessToken == "" || session.Subject == "" {
		return errors.New("sso: Session 缺少 AccessToken 或 Subject")
	}
	ctx = oidc.ClientContext(ctx, c.http)
	info, err := c.provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: session.AccessToken, TokenType: "Bearer"}))
	if err != nil {
		return fmt.Errorf("sso: 获取 UserInfo: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(info.Subject), []byte(session.Subject)) != 1 {
		return errors.New("sso: UserInfo subject 与 ID Token 不一致")
	}
	if out == nil {
		return nil
	}
	if err = info.Claims(out); err != nil {
		return fmt.Errorf("sso: 解码 UserInfo: %w", err)
	}
	return nil
}

// LogoutURL builds the standard RP-initiated logout URL advertised by Discovery.
func (c *OIDCClient) LogoutURL(idTokenHint, postLogoutRedirectURL, state string) (string, error) {
	if c.endSessionEndpoint == "" {
		return "", errors.New("sso: Provider 未声明 end_session_endpoint")
	}
	u, err := url.Parse(c.endSessionEndpoint)
	if err != nil {
		return "", fmt.Errorf("sso: end_session_endpoint 无效: %w", err)
	}
	query := u.Query()
	if idTokenHint != "" {
		query.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirectURL != "" {
		query.Set("post_logout_redirect_uri", postLogoutRedirectURL)
	}
	if state != "" {
		query.Set("state", state)
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func randomURLString(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sso: 生成随机值: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
