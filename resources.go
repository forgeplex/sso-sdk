package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type Describe struct {
	Audience string   `json:"audience"`
	Tenant   string   `json:"tenant"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

type ListOptions struct {
	Page    int
	PerPage int
	Query   string
}

type Page[T any] struct {
	Start  int `json:"start"`
	Limit  int `json:"limit"`
	Length int `json:"length"`
	Total  int `json:"total"`
	Items  []T `json:"-"`
}

func listResource[T any](ctx context.Context, c *Client, resource, key string, options ListOptions) (Page[T], error) {
	values := url.Values{
		"page":           {strconv.Itoa(max(options.Page, 0))},
		"per_page":       {strconv.Itoa(options.PerPage)},
		"include_totals": {"true"},
	}
	if options.PerPage <= 0 {
		values.Set("per_page", "50")
	}
	if options.Query != "" {
		values.Set("q", options.Query)
	}
	var raw struct {
		Start  int
		Limit  int
		Length int
		Total  int
	}
	var envelope map[string]json.RawMessage
	if err := c.Do(ctx, http.MethodGet, resource+"?"+values.Encode(), nil, &envelope); err != nil {
		return Page[T]{}, err
	}
	decode := func(name string, target any) error {
		if data := envelope[name]; len(data) > 0 {
			return json.Unmarshal(data, target)
		}
		return nil
	}
	if err := decode("start", &raw.Start); err != nil {
		return Page[T]{}, fmt.Errorf("sso: 解码 start: %w", err)
	}
	if err := decode("limit", &raw.Limit); err != nil {
		return Page[T]{}, fmt.Errorf("sso: 解码 limit: %w", err)
	}
	if err := decode("length", &raw.Length); err != nil {
		return Page[T]{}, fmt.Errorf("sso: 解码 length: %w", err)
	}
	if err := decode("total", &raw.Total); err != nil {
		return Page[T]{}, fmt.Errorf("sso: 解码 total: %w", err)
	}
	items := make([]T, 0)
	if err := decode(key, &items); err != nil {
		return Page[T]{}, fmt.Errorf("sso: 解码 %s: %w", key, err)
	}
	return Page[T]{Start: raw.Start, Limit: raw.Limit, Length: raw.Length, Total: raw.Total, Items: items}, nil
}

type Application struct {
	ClientID                string          `json:"client_id"`
	RealmID                 string          `json:"realm_id"`
	Name                    string          `json:"name"`
	Description             string          `json:"description"`
	LogoURI                 string          `json:"logo_uri"`
	AppType                 string          `json:"app_type"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method"`
	Callbacks               []string        `json:"callbacks"`
	AllowedLogoutURLs       []string        `json:"allowed_logout_urls"`
	WebOrigins              []string        `json:"web_origins"`
	GrantTypes              []string        `json:"grant_types"`
	IsFirstParty            bool            `json:"is_first_party"`
	RequirePKCE             bool            `json:"require_pkce"`
	OrganizationUsage       string          `json:"organization_usage"`
	TokenLifetime           json.RawMessage `json:"token_lifetime"`
	RefreshTokenPolicy      json.RawMessage `json:"refresh_token_policy"`
	ClientMetadata          json.RawMessage `json:"client_metadata"`
	HasClientSecret         bool            `json:"has_client_secret"`
	ClientSecret            string          `json:"client_secret,omitempty"`
	CreatedAt               time.Time       `json:"created_at"`
	UpdatedAt               time.Time       `json:"updated_at"`
}

type CreateApplicationInput struct {
	Name                    string   `json:"name,omitempty"`
	Description             string   `json:"description,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	AppType                 string   `json:"app_type,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Callbacks               []string `json:"callbacks,omitempty"`
	AllowedLogoutURLs       []string `json:"allowed_logout_urls,omitempty"`
	WebOrigins              []string `json:"web_origins,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	IsFirstParty            *bool    `json:"is_first_party,omitempty"`
	RequirePKCE             *bool    `json:"require_pkce,omitempty"`
	OrganizationUsage       string   `json:"organization_usage,omitempty"`
	TokenLifetime           any      `json:"token_lifetime,omitempty"`
	RefreshTokenPolicy      any      `json:"refresh_token_policy,omitempty"`
	ClientMetadata          any      `json:"client_metadata,omitempty"`
}

// UpdateApplicationInput uses pointers so callers can distinguish "unchanged"
// from an explicit zero value such as clearing all callback URLs.
type UpdateApplicationInput struct {
	Name               *string         `json:"name,omitempty"`
	Description        *string         `json:"description,omitempty"`
	LogoURI            *string         `json:"logo_uri,omitempty"`
	Callbacks          *[]string       `json:"callbacks,omitempty"`
	AllowedLogoutURLs  *[]string       `json:"allowed_logout_urls,omitempty"`
	WebOrigins         *[]string       `json:"web_origins,omitempty"`
	GrantTypes         *[]string       `json:"grant_types,omitempty"`
	IsFirstParty       *bool           `json:"is_first_party,omitempty"`
	RequirePKCE        *bool           `json:"require_pkce,omitempty"`
	OrganizationUsage  *string         `json:"organization_usage,omitempty"`
	TokenLifetime      json.RawMessage `json:"token_lifetime,omitempty"`
	RefreshTokenPolicy json.RawMessage `json:"refresh_token_policy,omitempty"`
	ClientMetadata     json.RawMessage `json:"client_metadata,omitempty"`
}

type ApplicationsService struct{ client *Client }

func (s ApplicationsService) List(ctx context.Context, o ListOptions) (Page[Application], error) {
	return listResource[Application](ctx, s.client, "/clients", "clients", o)
}
func (s ApplicationsService) Get(ctx context.Context, id string) (Application, error) {
	var out Application
	err := s.client.Do(ctx, http.MethodGet, "/clients/"+url.PathEscape(id), nil, &out)
	return out, err
}
func (s ApplicationsService) Create(ctx context.Context, in CreateApplicationInput) (Application, error) {
	var out Application
	err := s.client.Do(ctx, http.MethodPost, "/clients", in, &out)
	return out, err
}
func (s ApplicationsService) Update(ctx context.Context, id string, in UpdateApplicationInput) (Application, error) {
	var out Application
	err := s.client.Do(ctx, http.MethodPatch, "/clients/"+url.PathEscape(id), in, &out)
	return out, err
}
func (s ApplicationsService) Delete(ctx context.Context, id string) error {
	return s.client.Do(ctx, http.MethodDelete, "/clients/"+url.PathEscape(id), nil, nil)
}

type Scope struct {
	Value       string `json:"value"`
	Description string `json:"description"`
}
type API struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Identifier         string    `json:"identifier"`
	Scopes             []Scope   `json:"scopes"`
	SigningAlg         string    `json:"signing_alg"`
	TokenLifetime      int       `json:"token_lifetime"`
	AllowOfflineAccess bool      `json:"allow_offline_access"`
	EnforcePolicies    bool      `json:"enforce_policies"`
	TokenDialect       string    `json:"token_dialect"`
	IsSystem           bool      `json:"is_system"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}
type CreateAPIInput struct {
	Name               string  `json:"name,omitempty"`
	Identifier         string  `json:"identifier,omitempty"`
	Scopes             []Scope `json:"scopes,omitempty"`
	SigningAlg         string  `json:"signing_alg,omitempty"`
	TokenLifetime      int     `json:"token_lifetime,omitempty"`
	AllowOfflineAccess *bool   `json:"allow_offline_access,omitempty"`
	EnforcePolicies    *bool   `json:"enforce_policies,omitempty"`
	TokenDialect       string  `json:"token_dialect,omitempty"`
}

type UpdateAPIInput struct {
	Name               *string  `json:"name,omitempty"`
	Scopes             *[]Scope `json:"scopes,omitempty"`
	SigningAlg         *string  `json:"signing_alg,omitempty"`
	TokenLifetime      *int     `json:"token_lifetime,omitempty"`
	AllowOfflineAccess *bool    `json:"allow_offline_access,omitempty"`
	EnforcePolicies    *bool    `json:"enforce_policies,omitempty"`
	TokenDialect       *string  `json:"token_dialect,omitempty"`
}
type APIsService struct{ client *Client }

func (s APIsService) List(ctx context.Context, o ListOptions) (Page[API], error) {
	return listResource[API](ctx, s.client, "/resource-servers", "resource_servers", o)
}
func (s APIsService) Get(ctx context.Context, id string) (API, error) {
	var out API
	err := s.client.Do(ctx, http.MethodGet, "/resource-servers/"+url.PathEscape(id), nil, &out)
	return out, err
}
func (s APIsService) Create(ctx context.Context, in CreateAPIInput) (API, error) {
	var out API
	err := s.client.Do(ctx, http.MethodPost, "/resource-servers", in, &out)
	return out, err
}
func (s APIsService) Update(ctx context.Context, id string, in UpdateAPIInput) (API, error) {
	var out API
	err := s.client.Do(ctx, http.MethodPatch, "/resource-servers/"+url.PathEscape(id), in, &out)
	return out, err
}
func (s APIsService) Delete(ctx context.Context, id string) error {
	return s.client.Do(ctx, http.MethodDelete, "/resource-servers/"+url.PathEscape(id), nil, nil)
}

type Connection struct {
	ID                 string          `json:"id"`
	Name               string          `json:"name"`
	DisplayName        string          `json:"display_name"`
	Strategy           string          `json:"strategy"`
	Options            json.RawMessage `json:"options"`
	EnabledClients     []string        `json:"enabled_clients"`
	IsDomainConnection bool            `json:"is_domain_connection"`
	HasClientSecret    bool            `json:"has_client_secret"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}
type ConnectionsService struct{ client *Client }

func (s ConnectionsService) List(ctx context.Context, o ListOptions) (Page[Connection], error) {
	return listResource[Connection](ctx, s.client, "/connections", "connections", o)
}
func (s ConnectionsService) Get(ctx context.Context, id string) (Connection, error) {
	var out Connection
	err := s.client.Do(ctx, http.MethodGet, "/connections/"+url.PathEscape(id), nil, &out)
	return out, err
}

type User struct {
	UserID        string          `json:"user_id"`
	Email         *string         `json:"email,omitempty"`
	EmailVerified bool            `json:"email_verified"`
	Username      *string         `json:"username,omitempty"`
	PhoneNumber   *string         `json:"phone_number,omitempty"`
	PhoneVerified bool            `json:"phone_verified"`
	Name          string          `json:"name"`
	Blocked       bool            `json:"blocked"`
	LastLogin     *time.Time      `json:"last_login,omitempty"`
	LoginsCount   int64           `json:"logins_count"`
	AppMetadata   json.RawMessage `json:"app_metadata"`
	UserMetadata  json.RawMessage `json:"user_metadata"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}
type UsersService struct{ client *Client }

func (s UsersService) List(ctx context.Context, o ListOptions) (Page[User], error) {
	return listResource[User](ctx, s.client, "/users", "users", o)
}
func (s UsersService) Get(ctx context.Context, id string) (User, error) {
	var out User
	err := s.client.Do(ctx, http.MethodGet, "/users/"+url.PathEscape(id), nil, &out)
	return out, err
}

type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
type RolesService struct{ client *Client }

func (s RolesService) List(ctx context.Context, o ListOptions) (Page[Role], error) {
	return listResource[Role](ctx, s.client, "/roles", "roles", o)
}
func (s RolesService) Get(ctx context.Context, id string) (Role, error) {
	var out Role
	err := s.client.Do(ctx, http.MethodGet, "/roles/"+url.PathEscape(id), nil, &out)
	return out, err
}

type Realm struct {
	ID           string    `json:"id"`
	IsDefault    bool      `json:"is_default"`
	Slug         string    `json:"slug"`
	DisplayName  string    `json:"display_name"`
	Status       string    `json:"status"`
	Issuer       string    `json:"issuer"`
	DiscoveryURL string    `json:"discovery_url"`
	JWKSURL      string    `json:"jwks_url"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
type RealmInput struct {
	Slug        string `json:"slug,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Status      string `json:"status,omitempty"`
}
type RealmsService struct{ client *Client }

func (s RealmsService) List(ctx context.Context, o ListOptions) (Page[Realm], error) {
	return listResource[Realm](ctx, s.client, "/realms", "realms", o)
}
func (s RealmsService) Get(ctx context.Context, id string) (Realm, error) {
	var out Realm
	err := s.client.Do(ctx, http.MethodGet, "/realms/"+url.PathEscape(id), nil, &out)
	return out, err
}
func (s RealmsService) Create(ctx context.Context, in RealmInput) (Realm, error) {
	var out Realm
	err := s.client.Do(ctx, http.MethodPost, "/realms", in, &out)
	return out, err
}
func (s RealmsService) Update(ctx context.Context, id string, in RealmInput) (Realm, error) {
	var out Realm
	err := s.client.Do(ctx, http.MethodPatch, "/realms/"+url.PathEscape(id), in, &out)
	return out, err
}
func (s RealmsService) Delete(ctx context.Context, id string) error {
	return s.client.Do(ctx, http.MethodDelete, "/realms/"+url.PathEscape(id), nil, nil)
}
