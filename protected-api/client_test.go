package protected_api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv("KEYCLOAK_ISSUER", "https://id.example.test/realms/demo/")
	t.Setenv("KEYCLOAK_CLIENT_ID", "protected-api")
	t.Setenv("KEYCLOAK_CLIENT_SECRET", "secret")
	t.Setenv("KEYCLOAK_REDIRECT_URL", "https://app.example.test/callback")
	t.Setenv("KEYCLOAK_IDP_HINT", "upstream")
	t.Setenv("PROTECTED_API_AUDIENCE", "protected-api")
	t.Setenv("PROTECTED_API_LISTEN_ADDR", ":3000")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv() error = %v", err)
	}
	if cfg.Issuer != "https://id.example.test/realms/demo" {
		t.Fatalf("Issuer = %q", cfg.Issuer)
	}
	if cfg.IDPHint != "upstream" {
		t.Fatalf("IDPHint = %q", cfg.IDPHint)
	}
}

func TestLoadConfigFromEnvRejectsMissingValue(t *testing.T) {
	for _, name := range []string{
		"KEYCLOAK_ISSUER",
		"KEYCLOAK_CLIENT_ID",
		"KEYCLOAK_CLIENT_SECRET",
		"KEYCLOAK_REDIRECT_URL",
		"PROTECTED_API_AUDIENCE",
		"PROTECTED_API_LISTEN_ADDR",
	} {
		t.Setenv(name, "")
	}

	_, err := LoadConfigFromEnv()
	if err == nil || !strings.Contains(err.Error(), "KEYCLOAK_ISSUER") {
		t.Fatalf("LoadConfigFromEnv() error = %v", err)
	}
}

func TestLoginCreatesServerSideFlowAndSecureCookie(t *testing.T) {
	api := testAPI()
	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	recorder := httptest.NewRecorder()

	api.Handler().ServeHTTP(recorder, request)

	response := recorder.Result()
	defer response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", response.StatusCode)
	}
	cookies := response.Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected cookies: %#v", cookies)
	}
	api.mu.RLock()
	flow, ok := api.flows[cookies[0].Value]
	api.mu.RUnlock()
	if !ok || flow.State == "" || flow.Nonce == "" || flow.CodeVerifier == "" {
		t.Fatalf("flow was not stored correctly: %#v", flow)
	}

	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	query := location.Query()
	if query.Get("state") != flow.State || query.Get("nonce") != flow.Nonce {
		t.Fatalf("authorization parameters do not match stored flow")
	}
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		t.Fatalf("PKCE parameters missing: %s", location.RawQuery)
	}
}

func TestSessionResponseNeverContainsTokens(t *testing.T) {
	api := testAPI()
	var user UserClaims
	user.Sub = "immutable-subject"
	user.Email = "person@example.test"
	user.PreferredUsername = "person"
	user.RealmAccess.Roles = []string{"reader"}
	api.sessions["session-id"] = session{
		AccessToken:  "access-secret",
		IDToken:      "id-secret",
		RefreshToken: "refresh-secret",
		User:         user,
		AuthFlowID:   "flow-id",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	request := httptest.NewRequest(http.MethodGet, "/session", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-id"})
	recorder := httptest.NewRecorder()

	api.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, token := range []string{"access-secret", "id-secret", "refresh-secret"} {
		if strings.Contains(body, token) {
			t.Fatalf("response leaked token %q", token)
		}
	}
	var result struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.User.ID != user.Sub {
		t.Fatalf("user ID = %q", result.User.ID)
	}
}

func TestLogoutDeletesSessionAndCookie(t *testing.T) {
	api := testAPI()
	api.sessions["session-id"] = session{ExpiresAt: time.Now().Add(time.Hour)}
	request := httptest.NewRequest(http.MethodPost, "/logout", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-id"})
	recorder := httptest.NewRecorder()

	api.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
	if _, ok := api.sessions["session-id"]; ok {
		t.Fatal("session was not deleted")
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != -1 || !cookies[0].HttpOnly {
		t.Fatalf("unexpected clearing cookie: %#v", cookies)
	}
}

func TestParseBearer(t *testing.T) {
	tests := []struct {
		header string
		want   string
		ok     bool
	}{
		{header: "Bearer aaa.bbb.ccc", want: "aaa.bbb.ccc", ok: true},
		{header: "bearer token", want: "token", ok: true},
		{header: "Bearer", ok: false},
		{header: "Basic token", ok: false},
		{header: "Bearer one two", ok: false},
		{header: "Bearer token\r\nInjected: yes", ok: false},
	}
	for _, test := range tests {
		t.Run(test.header, func(t *testing.T) {
			got, ok := parseBearer(test.header)
			if got != test.want || ok != test.ok {
				t.Fatalf("parseBearer() = %q, %v", got, ok)
			}
		})
	}
}

func TestParseBearerHeadersRejectsDuplicates(t *testing.T) {
	if _, ok := parseBearerHeaders([]string{"Bearer one", "Bearer two"}); ok {
		t.Fatal("duplicate Authorization headers were accepted")
	}
}

func testAPI() *ProtectedAPI {
	return &ProtectedAPI{
		config: Config{
			IDPHint:     "upstream",
			APIAudience: "protected-api",
		},
		oauthConfig:  oauthConfigForTest(),
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		cookieSecure: true,
		flows:        make(map[string]loginFlow),
		sessions:     make(map[string]session),
		stop:         make(chan struct{}),
	}
}

func oauthConfigForTest() oauth2.Config {
	return oauth2.Config{
		ClientID:    "protected-api",
		RedirectURL: "https://app.example.test/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://id.example.test/authorize",
			TokenURL: "https://id.example.test/token",
		},
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
}
