// Package sso provides OpenID Connect login and Management API clients for
// Forgeplex SSO.
//
// A Client is bound to one tenant by its client_credentials and, optionally,
// to one Realm by Config.RealmID. It obtains and caches Management API access
// tokens automatically.
package sso

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

const managementPath = "/api/v2"

// Config configures a Management API client.
type Config struct {
	// IssuerURL is the Realm issuer, for example https://customer.example.com/.
	IssuerURL string
	// ManagementURL is the origin serving /api/v2. It defaults to IssuerURL.
	// Set it when authd and mgmtd use different origins, as in local development.
	ManagementURL string
	// Audience identifies the tenant Management API. For a non-default Realm,
	// this remains the default Realm issuer plus /api/v2/ and therefore differs
	// from IssuerURL. It defaults to IssuerURL + /api/v2/.
	Audience string
	// RealmID scopes Realm resources. The server requires this value explicitly.
	RealmID      string
	ClientID     string
	ClientSecret string
	// Scopes optionally narrows the scopes requested at the token endpoint.
	Scopes     []string
	HTTPClient *http.Client
}

// Client is a tenant-bound Management API client.
type Client struct {
	issuer       *url.URL
	management   *url.URL
	audience     string
	realmID      string
	clientID     string
	clientSecret string
	scopes       []string
	http         *http.Client

	tokens tokenCache

	Applications ApplicationsService
	APIs         APIsService
	Connections  ConnectionsService
	Users        UsersService
	Roles        RolesService
	Realms       RealmsService
}

type tokenCache struct {
	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// New constructs a client. No network request is made until the first API call.
func New(cfg Config) (*Client, error) {
	issuer, err := parseBaseURL("IssuerURL", cfg.IssuerURL)
	if err != nil {
		return nil, err
	}
	managementRaw := cfg.ManagementURL
	if strings.TrimSpace(managementRaw) == "" {
		managementRaw = cfg.IssuerURL
	}
	management, err := parseBaseURL("ManagementURL", managementRaw)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("sso: ClientID 不能为空")
	}
	if strings.TrimSpace(cfg.ClientSecret) == "" {
		return nil, errors.New("sso: ClientSecret 不能为空")
	}
	audience := strings.TrimSpace(cfg.Audience)
	if audience == "" {
		audience = strings.TrimRight(issuer.String(), "/") + managementPath + "/"
	} else if parsedAudience, parseErr := url.Parse(audience); parseErr != nil || !parsedAudience.IsAbs() {
		return nil, errors.New("sso: Audience 必须是绝对 URL")
	}

	c := &Client{
		issuer:       issuer,
		management:   management,
		audience:     audience,
		realmID:      strings.TrimSpace(cfg.RealmID),
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		scopes:       append([]string(nil), cfg.Scopes...),
		http:         cfg.HTTPClient,
	}
	if c.http == nil {
		c.http = http.DefaultClient
	}
	c.Applications = ApplicationsService{client: c}
	c.APIs = APIsService{client: c}
	c.Connections = ConnectionsService{client: c}
	c.Users = UsersService{client: c}
	c.Roles = RolesService{client: c}
	c.Realms = RealmsService{client: c}
	return c, nil
}

func parseBaseURL(name, raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("sso: %s 必须是含 scheme 和 host 的绝对 URL", name)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("sso: %s 不能包含 query 或 fragment", name)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

// Describe reports which tenant, client and scopes the current token represents.
func (c *Client) Describe(ctx context.Context) (Describe, error) {
	var out Describe
	err := c.Do(ctx, http.MethodGet, "/", nil, &out)
	return out, err
}

// Do calls a relative Management API path. Typed services should be preferred;
// this method makes newly added endpoints usable before a new SDK release adds
// a dedicated method.
func (c *Client) Do(ctx context.Context, method, relativePath string, body, out any) error {
	if c == nil {
		return errors.New("sso: Client 为空")
	}
	if !strings.HasPrefix(relativePath, "/") || strings.HasPrefix(relativePath, "//") {
		return errors.New("sso: API path 必须是以单个 / 开头的相对路径")
	}
	payload, err := encodeBody(body)
	if err != nil {
		return err
	}
	var rejectedToken string
	for attempt := 0; attempt < 2; attempt++ {
		token, tokenErr := c.accessToken(ctx, rejectedToken)
		if tokenErr != nil {
			return tokenErr
		}
		err = c.doOnce(ctx, method, relativePath, payload, token, out)
		var apiErr *Error
		if attempt == 0 && errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized {
			rejectedToken = token
			continue
		}
		return err
	}
	return err
}

func encodeBody(body any) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("sso: 编码请求体: %w", err)
	}
	return b, nil
}

func (c *Client) doOnce(ctx context.Context, method, relativePath string, payload []byte, token string, out any) error {
	relative, err := url.Parse(relativePath)
	if err != nil || relative.IsAbs() || relative.Host != "" {
		return errors.New("sso: API path 不是合法的相对 URL")
	}
	u := *c.management
	u.Path = path.Join(c.management.Path, managementPath, relative.Path)
	// RawPath preserves escaped path segments such as a client_id containing '/'.
	u.RawPath = path.Join(c.management.EscapedPath(), managementPath, relative.EscapedPath())
	if strings.HasSuffix(relative.Path, "/") {
		u.Path += "/"
		u.RawPath += "/"
	}
	query := relative.Query()
	if c.realmID != "" && query.Get("realm_id") == "" {
		query.Set("realm_id", c.realmID)
	}
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("sso: 创建请求: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("sso: 调用 Management API: %w", err)
	}
	defer res.Body.Close()
	return decodeResponse(res, out)
}

func (c *Client) accessToken(ctx context.Context, rejectedToken string) (string, error) {
	c.tokens.mu.Lock()
	defer c.tokens.mu.Unlock()
	// If another goroutine already replaced the rejected token, reuse that fresh
	// value instead of serially refreshing once per concurrent 401 response.
	if c.tokens.accessToken != "" && c.tokens.accessToken != rejectedToken && time.Until(c.tokens.expiresAt) > 30*time.Second {
		return c.tokens.accessToken, nil
	}

	u := *c.issuer
	u.Path = path.Join(c.issuer.Path, "/oauth/token")
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"audience":      {c.audience},
	}
	if len(c.scopes) > 0 {
		form.Set("scope", strings.Join(c.scopes, " "))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("sso: 创建令牌请求: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("sso: 获取 Management API 令牌: %w", err)
	}
	defer res.Body.Close()
	var token tokenResponse
	if err = decodeResponse(res, &token); err != nil {
		return "", err
	}
	if token.AccessToken == "" || token.ExpiresIn <= 0 {
		return "", errors.New("sso: 令牌响应缺少 access_token 或 expires_in")
	}
	c.tokens.accessToken = token.AccessToken
	c.tokens.expiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	return token.AccessToken, nil
}

func decodeResponse(res *http.Response, out any) error {
	const maxBody = 4 << 20
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("sso: 读取响应: %w", err)
	}
	if len(body) > maxBody {
		return errors.New("sso: 响应超过 4 MiB")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		apiErr := &Error{StatusCode: res.StatusCode, RequestID: res.Header.Get("X-Request-ID")}
		_ = json.Unmarshal(body, apiErr)
		if apiErr.Code == "" {
			apiErr.Code = http.StatusText(res.StatusCode)
		}
		return apiErr
	}
	if out == nil || len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	if err = json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("sso: 解码响应: %w", err)
	}
	return nil
}

// Error is a non-2xx Management API or token endpoint response.
type Error struct {
	StatusCode  int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description"`
	RequestID   string `json:"request_id"`
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	message := e.Code
	if e.Description != "" {
		message += ": " + e.Description
	}
	if e.RequestID != "" {
		message += " (request_id=" + e.RequestID + ")"
	}
	return fmt.Sprintf("sso: HTTP %d %s", e.StatusCode, message)
}
