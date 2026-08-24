package sso_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	sso "github.com/forgeplex/sso-sdk"
)

func TestClientGetsTokenScopesRealmAndCachesToken(t *testing.T) {
	t.Parallel()
	var tokenCalls atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenCalls.Add(1)
			if err := r.ParseForm(); err != nil {
				t.Errorf("ParseForm: %v", err)
			}
			wantForm := url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {"sdk-client"},
				"client_secret": {"sdk-secret"},
				"audience":      {server.URL + "/api/v2/"},
				"scope":         {"read:clients read:users"},
			}
			if r.Form.Encode() != wantForm.Encode() {
				t.Errorf("token form = %s, want %s", r.Form.Encode(), wantForm.Encode())
			}
			writeJSON(t, w, map[string]any{"access_token": "token-1", "token_type": "Bearer", "expires_in": 3600})
		case "/api/v2/clients":
			if got := r.Header.Get("Authorization"); got != "Bearer token-1" {
				t.Errorf("Authorization = %q", got)
			}
			if got := r.URL.Query().Get("realm_id"); got != "realm-123" {
				t.Errorf("realm_id = %q", got)
			}
			if got := r.URL.Query().Get("include_totals"); got != "true" {
				t.Errorf("include_totals = %q", got)
			}
			writeJSON(t, w, map[string]any{"start": 0, "limit": 50, "length": 1, "total": 1, "clients": []map[string]any{{"client_id": "app-1", "name": "订单后台"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := sso.New(sso.Config{IssuerURL: server.URL, ManagementURL: server.URL, RealmID: "realm-123", ClientID: "sdk-client", ClientSecret: "sdk-secret", Scopes: []string{"read:clients", "read:users"}})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		page, listErr := client.Applications.List(context.Background(), sso.ListOptions{})
		if listErr != nil {
			t.Fatal(listErr)
		}
		if page.Total != 1 || len(page.Items) != 1 || page.Items[0].Name != "订单后台" {
			t.Fatalf("page = %+v", page)
		}
	}
	if got := tokenCalls.Load(); got != 1 {
		t.Fatalf("token calls = %d, want 1", got)
	}
}

func TestClientRefreshesOnceAfterUnauthorized(t *testing.T) {
	t.Parallel()
	var tokenCalls atomic.Int32
	var apiCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			n := tokenCalls.Add(1)
			writeJSON(t, w, map[string]any{"access_token": "token-" + string(rune('0'+n)), "expires_in": 3600})
		case "/api/v2/":
			if apiCalls.Add(1) == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				writeJSON(t, w, map[string]any{"error": "invalid_token", "error_description": "expired"})
				return
			}
			if got := r.Header.Get("Authorization"); got != "Bearer token-2" {
				t.Errorf("retry Authorization = %q", got)
			}
			writeJSON(t, w, map[string]any{"tenant": "demo", "client_id": "sdk-client", "audience": "aud", "scopes": []string{"read:clients"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := sso.New(sso.Config{IssuerURL: server.URL, ClientID: "sdk-client", ClientSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Describe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Tenant != "demo" || tokenCalls.Load() != 2 || apiCalls.Load() != 2 {
		t.Fatalf("describe=%+v tokenCalls=%d apiCalls=%d", got, tokenCalls.Load(), apiCalls.Load())
	}
}

func TestAPIErrorKeepsRequestID(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeJSON(t, w, map[string]any{"access_token": "token", "expires_in": 3600})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		writeJSON(t, w, map[string]any{"error": "insufficient_scope", "error_description": "missing read:users", "request_id": "req-123"})
	}))
	defer server.Close()
	client, err := sso.New(sso.Config{IssuerURL: server.URL, ClientID: "id", ClientSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Users.List(context.Background(), sso.ListOptions{})
	var apiErr *sso.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %T %v", err, err)
	}
	if apiErr.StatusCode != 403 || apiErr.Code != "insufficient_scope" || apiErr.RequestID != "req-123" {
		t.Fatalf("api error = %+v", apiErr)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	t.Parallel()
	tests := []sso.Config{{}, {IssuerURL: "localhost:8081", ClientID: "id", ClientSecret: "secret"}, {IssuerURL: "https://example.com", ClientSecret: "secret"}, {IssuerURL: "https://example.com", ClientID: "id"}}
	for _, cfg := range tests {
		if _, err := sso.New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
}

func TestClientUsesExplicitManagementAudience(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realm-b/oauth/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("ParseForm: %v", err)
			}
			if got := r.Form.Get("audience"); got != "https://tenant.example.com/api/v2/" {
				t.Errorf("audience = %q", got)
			}
			writeJSON(t, w, map[string]any{"access_token": "token", "expires_in": 3600})
		case "/api/v2/":
			writeJSON(t, w, map[string]any{"tenant": "tenant", "client_id": "id", "audience": "https://tenant.example.com/api/v2/", "scopes": []string{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := sso.New(sso.Config{
		IssuerURL: server.URL + "/realm-b", ManagementURL: server.URL,
		Audience: "https://tenant.example.com/api/v2/", ClientID: "id", ClientSecret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Describe(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestApplicationUpdateCanClearSlices(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeJSON(t, w, map[string]any{"access_token": "token", "expires_in": 3600})
			return
		}
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v2/clients/app-1" {
			http.NotFound(w, r)
			return
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if got := string(body["callbacks"]); got != "[]" {
			t.Errorf("callbacks = %s, want []", got)
		}
		writeJSON(t, w, map[string]any{"client_id": "app-1", "name": "App", "callbacks": []string{}})
	}))
	defer server.Close()
	client, err := sso.New(sso.Config{IssuerURL: server.URL, ClientID: "id", ClientSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	empty := []string{}
	if _, err = client.Applications.Update(context.Background(), "app-1", sso.UpdateApplicationInput{Callbacks: &empty}); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode response: %v", err)
	}
}
