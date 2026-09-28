package oidc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func TestAuthorizationCodeFlowWithPKCE(t *testing.T) {
	var logs bytes.Buffer
	cfg := validTestConfig()
	cfg.AllowEphemeralDevelopment = true
	cfg.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	server := newTestServer(t, cfg)

	redirectURI := cfg.RedirectURIs[0]
	state := "state +&/?"
	nonce := "nonce-must-return"
	verifier := strings.Repeat("v", 43)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	authorizeURL := "/authorize?" + url.Values{
		"client_id":             {cfg.ClientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	authorize := performRequest(server, fasthttp.MethodGet, authorizeURL, "", nil)
	require.Equal(t, fasthttp.StatusOK, authorize.Response.StatusCode())
	flowID := extractFlowID(t, string(authorize.Response.Body()))

	login := performRequest(server, fasthttp.MethodPost, "/authorize", url.Values{
		"auth_flow_id": {flowID},
		"username":     {"user@example.com"},
		"password":     {"correct-password"},
	}.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	require.Equal(t, fasthttp.StatusFound, login.Response.StatusCode())
	callback, err := url.Parse(string(login.Response.Header.Peek("Location")))
	require.NoError(t, err)
	require.Equal(t, state, callback.Query().Get("state"))
	require.Equal(t, "1", callback.Query().Get("existing"))
	code := callback.Query().Get("code")
	require.NotEmpty(t, code)

	wrongRedirect := tokenRequest(server, cfg, code, "https://broker.example/other", verifier)
	require.Equal(t, fasthttp.StatusBadRequest, wrongRedirect.Response.StatusCode())

	wrongVerifier := tokenRequest(server, cfg, code, redirectURI, strings.Repeat("x", 43))
	require.Equal(t, fasthttp.StatusBadRequest, wrongVerifier.Response.StatusCode())
	require.JSONEq(t, `{"error":"invalid_grant","error_description":"authorization code is invalid"}`, string(wrongVerifier.Response.Body()))

	tokenResponse := tokenRequest(server, cfg, code, redirectURI, verifier)
	require.Equal(t, fasthttp.StatusOK, tokenResponse.Response.StatusCode())
	var tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	require.NoError(t, json.Unmarshal(tokenResponse.Response.Body(), &tokens))
	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.IDToken)
	require.NotEqual(t, tokens.AccessToken, tokens.IDToken)

	accessClaims, accessHeader := parseToken(t, server.oidcService.provider, tokens.AccessToken)
	idClaims, idHeader := parseToken(t, server.oidcService.provider, tokens.IDToken)
	require.Equal(t, server.oidcService.provider.kid, accessHeader["kid"])
	require.Equal(t, accessHeader["kid"], idHeader["kid"])
	require.Equal(t, "access", accessClaims.TokenUse)
	require.Empty(t, accessClaims.Nonce)
	require.Equal(t, "id", idClaims.TokenUse)
	require.Equal(t, nonce, idClaims.Nonce)
	require.Equal(t, cfg.ClientID, idClaims.Audience[0])
	require.Equal(t, "https://issuer.example", idClaims.Issuer)
	require.Equal(t, "user-123", idClaims.Subject)
	require.NotNil(t, idClaims.IssuedAt)
	require.NotNil(t, idClaims.ExpiresAt)

	replay := tokenRequest(server, cfg, code, redirectURI, verifier)
	require.Equal(t, fasthttp.StatusBadRequest, replay.Response.StatusCode())

	userinfo := performRequest(server, fasthttp.MethodGet, "/userinfo", "", map[string]string{"Authorization": "Bearer " + tokens.AccessToken})
	require.Equal(t, fasthttp.StatusOK, userinfo.Response.StatusCode())
	require.JSONEq(t, `{"sub":"user-123","name":"user@example.com","given_name":"user","family_name":"user","preferred_username":"user@example.com","email":"user@example.com"}`, string(userinfo.Response.Body()))

	idAsAccess := performRequest(server, fasthttp.MethodGet, "/userinfo", "", map[string]string{"Authorization": "Bearer " + tokens.IDToken})
	require.Equal(t, fasthttp.StatusUnauthorized, idAsAccess.Response.StatusCode())

	discovery := performRequest(server, fasthttp.MethodGet, "/.well-known/openid-configuration", "", nil)
	require.Contains(t, string(discovery.Response.Body()), `"issuer":"https://issuer.example"`)
	require.Contains(t, string(discovery.Response.Body()), `"code_challenge_methods_supported":["S256"]`)
	jwks := performRequest(server, fasthttp.MethodGet, "/jwks", "", nil)
	var keySet JWKSResponse
	require.NoError(t, json.Unmarshal(jwks.Response.Body(), &keySet))
	require.Len(t, keySet.Keys, 1)
	require.Equal(t, accessHeader["kid"], keySet.Keys[0].Kid)

	logOutput := logs.String()
	require.GreaterOrEqual(t, strings.Count(logOutput, flowID), 4)
	for _, sensitive := range []string{"correct-password", cfg.ClientSecret, code, state, nonce, tokens.AccessToken, tokens.IDToken} {
		require.NotContains(t, logOutput, sensitive)
	}
}

func TestAuthorizeRequiresExactRegisteredRedirectURI(t *testing.T) {
	cfg := validTestConfig()
	cfg.AllowEphemeralDevelopment = true
	server := newTestServer(t, cfg)
	response := performRequest(server, fasthttp.MethodGet, "/authorize?"+url.Values{
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {"https://broker.example/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}.Encode(), "", nil)
	require.Equal(t, fasthttp.StatusBadRequest, response.Response.StatusCode())
	require.Empty(t, response.Response.Header.Peek("Location"))
	require.Contains(t, string(response.Response.Body()), `"error":"invalid_request"`)
}

func TestLoginRejectsMissingPasswordBeforeAuthenticator(t *testing.T) {
	cfg := validTestConfig()
	cfg.AllowEphemeralDevelopment = true
	provider, err := NewProvider(cfg, fakeAuthenticator{password: "", subject: "user-123"})
	require.NoError(t, err)
	server, err := NewHTTPServerWithLogger(":0", cfg.Logger)
	require.NoError(t, err)
	server.oidcService = NewOIDCService(provider)

	authorize := performRequest(server, fasthttp.MethodGet, "/authorize?"+url.Values{
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {cfg.RedirectURIs[0]},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"state"},
	}.Encode(), "", nil)
	require.Equal(t, fasthttp.StatusOK, authorize.Response.StatusCode())
	flowID := extractFlowID(t, string(authorize.Response.Body()))

	login := performRequest(server, fasthttp.MethodPost, "/authorize", url.Values{
		"auth_flow_id": {flowID},
		"username":     {"user@example.com"},
	}.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	require.Equal(t, fasthttp.StatusFound, login.Response.StatusCode())
	target, err := url.Parse(string(login.Response.Header.Peek("Location")))
	require.NoError(t, err)
	require.Equal(t, "access_denied", target.Query().Get("error"))
	require.Empty(t, target.Query().Get("code"))
}

func TestAuthorizationErrorEscapesStateAndPreservesRedirectQuery(t *testing.T) {
	cfg := validTestConfig()
	cfg.AllowEphemeralDevelopment = true
	server := newTestServer(t, cfg)
	state := "x&injected=true"
	response := performRequest(server, fasthttp.MethodGet, "/authorize?"+url.Values{
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {cfg.RedirectURIs[0]},
		"response_type": {"token"},
		"scope":         {"openid"},
		"state":         {state},
	}.Encode(), "", nil)
	require.Equal(t, fasthttp.StatusFound, response.Response.StatusCode())
	target, err := url.Parse(string(response.Response.Header.Peek("Location")))
	require.NoError(t, err)
	require.Equal(t, state, target.Query().Get("state"))
	require.Equal(t, "", target.Query().Get("injected"))
	require.Equal(t, "1", target.Query().Get("existing"))
}

func newTestServer(t *testing.T, cfg Config) *HTTPServer {
	t.Helper()
	provider, err := NewProvider(cfg, fakeAuthenticator{password: "correct-password", subject: "user-123"})
	require.NoError(t, err)
	server, err := NewHTTPServerWithLogger(":0", cfg.Logger)
	require.NoError(t, err)
	server.oidcService = NewOIDCService(provider)
	return server
}

func performRequest(server *HTTPServer, method, requestURI, body string, headers map[string]string) *fasthttp.RequestCtx {
	request := new(fasthttp.Request)
	request.Header.SetMethod(method)
	request.SetRequestURI(requestURI)
	request.SetBodyString(body)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	ctx := new(fasthttp.RequestCtx)
	ctx.Init(request, nil, nil)
	server.oidcHandler(ctx)
	return ctx
}

func tokenRequest(server *HTTPServer, cfg Config, code, redirectURI, verifier string) *fasthttp.RequestCtx {
	credentials := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(cfg.ClientID) + ":" + url.QueryEscape(cfg.ClientSecret)))
	return performRequest(server, fasthttp.MethodPost, "/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}.Encode(), map[string]string{
		"Authorization": "Basic " + credentials,
		"Content-Type":  "application/x-www-form-urlencoded",
	})
}

func extractFlowID(t *testing.T, body string) string {
	t.Helper()
	matches := regexp.MustCompile(`name="auth_flow_id" value="([^"]+)"`).FindStringSubmatch(body)
	require.Len(t, matches, 2, fmt.Sprintf("login form did not contain flow ID: %s", body))
	return matches[1]
}

func parseToken(t *testing.T, provider *OIDCProvider, raw string) (*tokenClaims, map[string]any) {
	t.Helper()
	claims := new(tokenClaims)
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		return &provider.privateKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(provider.issuer), jwt.WithAudience(provider.clientID))
	require.NoError(t, err)
	require.True(t, token.Valid)
	return claims, token.Header
}
