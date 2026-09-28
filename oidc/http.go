package oidc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"time"

	"auth-service/entity"

	"github.com/golang-jwt/jwt/v5"
	"github.com/valyala/fasthttp"
)

//go:embed static/login.html
var loginFiles embed.FS

type HTTPServer struct {
	addr        string
	template    *template.Template
	oidcService *OIDCService
	logger      *slog.Logger
}

// NewHTTPServerWithLogger is the preferred, error-returning HTTP constructor.
func NewHTTPServerWithLogger(addr string, logger *slog.Logger) (*HTTPServer, error) {
	loginTemplate, err := template.ParseFS(loginFiles, "static/login.html")
	if err != nil {
		return nil, fmt.Errorf("parse embedded OIDC login template: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &HTTPServer{addr: addr, template: loginTemplate, logger: logger}, nil
}

// NewHTTPServer preserves the prototype API. Use NewHTTPServerWithLogger in new code.
func NewHTTPServer(addr string) *HTTPServer {
	server, err := NewHTTPServerWithLogger(addr, nil)
	if err != nil {
		return &HTTPServer{addr: addr, logger: slog.Default()}
	}
	return server
}

// Run validates initialization and reports listen failures to its caller.
func (s *HTTPServer) Run(provider *OIDCProvider) error {
	if provider == nil {
		return errors.New("OIDC provider is required")
	}
	if provider.initErr != nil {
		provider.logger.Error("OIDC provider startup failed", "error", provider.initErr)
		return provider.initErr
	}
	if s.template == nil {
		return errors.New("OIDC login template is unavailable")
	}
	s.oidcService = NewOIDCService(provider)
	s.logger = provider.logger
	s.logger.Info("OIDC HTTP server starting", "addr", s.addr, "issuer", provider.issuer, "kid", provider.kid)
	if err := fasthttp.ListenAndServe(s.addr, s.oidcHandler); err != nil {
		s.logger.Error("OIDC HTTP server stopped", "addr", s.addr, "error", err)
		return err
	}
	return nil
}

func (s *HTTPServer) oidcHandler(ctx *fasthttp.RequestCtx) {
	switch string(ctx.Path()) {
	case "/authorize":
		if ctx.IsGet() {
			s.handleAuthorize(ctx)
		} else if ctx.IsPost() {
			s.handleLogin(ctx)
		} else {
			s.writeOAuthError(ctx, fasthttp.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		}
	case "/token":
		s.handleToken(ctx)
	case "/userinfo":
		s.handleUserInfo(ctx)
	case "/.well-known/openid-configuration":
		s.handleDiscovery(ctx)
	case "/jwks":
		s.handleJWKS(ctx)
	default:
		s.writeOAuthError(ctx, fasthttp.StatusNotFound, "invalid_request", "endpoint not found")
	}
}

func (s *HTTPServer) handleAuthorize(ctx *fasthttp.RequestCtx) {
	p := s.oidcService.provider
	args := ctx.QueryArgs()
	clientID := string(args.Peek("client_id"))
	redirectURI := string(args.Peek("redirect_uri"))
	state := string(args.Peek("state"))

	if clientID != p.clientID {
		p.logger.Warn("authorization request rejected", "decision", "unknown_client")
		s.writeOAuthError(ctx, fasthttp.StatusBadRequest, "unauthorized_client", "client is not registered")
		return
	}
	if _, ok := p.redirectURIs[redirectURI]; !ok {
		p.logger.Warn("authorization request rejected", "client_id", clientID, "decision", "redirect_uri_mismatch")
		s.writeOAuthError(ctx, fasthttp.StatusBadRequest, "invalid_request", "redirect_uri is not registered")
		return
	}
	if string(args.Peek("response_type")) != "code" {
		p.logger.Warn("authorization request rejected", "client_id", clientID, "decision", "unsupported_response_type")
		s.redirectError(ctx, redirectURI, state, "unsupported_response_type", "only code is supported")
		return
	}
	scope := string(args.Peek("scope"))
	if !hasScope(scope, "openid") {
		p.logger.Warn("authorization request rejected", "client_id", clientID, "decision", "openid_scope_missing")
		s.redirectError(ctx, redirectURI, state, "invalid_scope", "openid scope is required")
		return
	}
	challenge := string(args.Peek("code_challenge"))
	challengeMethod := string(args.Peek("code_challenge_method"))
	if challenge != "" && (challengeMethod != "S256" || !validCodeChallenge(challenge)) {
		p.logger.Warn("authorization request rejected", "client_id", clientID, "decision", "invalid_pkce")
		s.redirectError(ctx, redirectURI, state, "invalid_request", "PKCE requires a valid S256 code challenge")
		return
	}
	if challenge == "" && challengeMethod != "" {
		s.redirectError(ctx, redirectURI, state, "invalid_request", "code_challenge is required with code_challenge_method")
		return
	}

	flowID, err := randomHandle()
	if err != nil {
		p.logger.Error("authorization flow creation failed", "error", err)
		s.writeOAuthError(ctx, fasthttp.StatusInternalServerError, "server_error", "unable to start authorization")
		return
	}
	request := authorizationRequest{
		FlowID:        flowID,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		State:         state,
		Nonce:         string(args.Peek("nonce")),
		Scope:         scope,
		CodeChallenge: challenge,
		ExpiresAt:     time.Now().Add(p.authorizationLifetime),
	}
	s.oidcService.putFlow(request)
	p.logger.Info("authorization request accepted",
		"auth_flow_id", flowID,
		"client_id", clientID,
		"redirect_uri_registered", true,
		"response_type", "code",
		"scope", scope,
		"state_present", state != "",
		"nonce_present", request.Nonce != "",
		"pkce", challenge != "",
	)
	ctx.SetContentType("text/html; charset=utf-8")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Response.Header.Set("Cache-Control", "no-store")
	if err := s.template.ExecuteTemplate(ctx, "login.html", struct{ FlowID string }{FlowID: flowID}); err != nil {
		p.logger.Error("login page rendering failed", "auth_flow_id", flowID, "error", err)
	}
}

func (s *HTTPServer) handleLogin(ctx *fasthttp.RequestCtx) {
	flowID := string(ctx.PostArgs().Peek("auth_flow_id"))
	logger := s.oidcService.provider.logger.With("auth_flow_id", flowID)
	request, ok := s.oidcService.getFlow(flowID)
	if !ok {
		logger.Warn("login rejected", "decision", "authorization_flow_missing_or_expired")
		s.writeOAuthError(ctx, fasthttp.StatusBadRequest, "invalid_request", "authorization flow is missing or expired")
		return
	}

	user := entity.User{
		Username: string(ctx.PostArgs().Peek("username")),
		Password: string(ctx.PostArgs().Peek("password")),
	}
	if user.Username == "" || user.Password == "" {
		logger.Warn("login rejected", "client_id", request.ClientID, "decision", "credentials_missing")
		s.redirectError(ctx, request.RedirectURI, request.State, "access_denied", "invalid credentials")
		return
	}
	authenticated, userID, err := s.oidcService.provider.auth.CheckUserAuth(ctx, user)
	if err != nil || !authenticated || userID == "" {
		logger.Warn("login rejected", "client_id", request.ClientID, "decision", "invalid_credentials")
		s.redirectError(ctx, request.RedirectURI, request.State, "access_denied", "invalid credentials")
		return
	}
	request, ok = s.oidcService.consumeFlow(flowID)
	if !ok {
		logger.Warn("login rejected", "decision", "authorization_flow_already_consumed")
		s.writeOAuthError(ctx, fasthttp.StatusBadRequest, "invalid_request", "authorization flow is missing or expired")
		return
	}
	code, err := randomHandle()
	if err != nil {
		logger.Error("authorization code creation failed", "error", err)
		s.redirectError(ctx, request.RedirectURI, request.State, "server_error", "unable to complete authorization")
		return
	}
	s.oidcService.putCode(code, AuthCodeData{
		FlowID:        flowID,
		UserID:        userID,
		Username:      user.Username,
		ClientID:      request.ClientID,
		RedirectURI:   request.RedirectURI,
		Nonce:         request.Nonce,
		Scope:         request.Scope,
		CodeChallenge: request.CodeChallenge,
		ExpiresAt:     time.Now().Add(s.oidcService.provider.codeLifetime),
	})
	logger.Info("login accepted", "client_id", request.ClientID, "decision", "authorization_code_issued")
	redirectWithParams(ctx, request.RedirectURI, map[string]string{"code": code, "state": request.State})
}

func (s *HTTPServer) handleToken(ctx *fasthttp.RequestCtx) {
	if !ctx.IsPost() {
		s.writeOAuthError(ctx, fasthttp.StatusMethodNotAllowed, "invalid_request", "token endpoint requires POST")
		return
	}
	clientID, clientSecret, err := clientCredentials(ctx)
	if err != nil || clientID != s.oidcService.provider.clientID || !constantTimeEqual(clientSecret, s.oidcService.provider.clientSecret) {
		s.oidcService.provider.logger.Warn("token request rejected", "client_id_match", clientID == s.oidcService.provider.clientID, "decision", "invalid_client")
		ctx.Response.Header.Set("WWW-Authenticate", `Basic realm="token"`)
		s.writeOAuthError(ctx, fasthttp.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if string(ctx.PostArgs().Peek("grant_type")) != "authorization_code" {
		s.oidcService.provider.logger.Warn("token request rejected", "client_id", clientID, "decision", "unsupported_grant_type")
		s.writeOAuthError(ctx, fasthttp.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code")
		return
	}
	code := string(ctx.PostArgs().Peek("code"))
	redirectURI := string(ctx.PostArgs().Peek("redirect_uri"))
	if code == "" || redirectURI == "" {
		s.writeOAuthError(ctx, fasthttp.StatusBadRequest, "invalid_request", "code and redirect_uri are required")
		return
	}
	data, decision := s.oidcService.consumeCode(code, clientID, redirectURI, string(ctx.PostArgs().Peek("code_verifier")))
	if decision != "accepted" {
		logger := s.oidcService.provider.logger
		if data.FlowID != "" {
			logger = logger.With("auth_flow_id", data.FlowID)
		}
		logger.Warn("token request rejected", "client_id", clientID, "decision", decision)
		s.writeOAuthError(ctx, fasthttp.StatusBadRequest, "invalid_grant", "authorization code is invalid")
		return
	}
	logger := s.oidcService.provider.logger.With("auth_flow_id", data.FlowID)
	accessToken, idToken, err := s.issueTokens(data)
	if err != nil {
		logger.Error("token signing failed", "client_id", clientID, "error", err)
		s.writeOAuthError(ctx, fasthttp.StatusInternalServerError, "server_error", "unable to issue tokens")
		return
	}
	logger.Info("token request accepted",
		"client_id", clientID,
		"decision", "tokens_issued",
		"grant_type", "authorization_code",
		"code_client_matched", true,
		"code_redirect_matched", true,
		"pkce_verified", data.CodeChallenge != "",
		"issuer", s.oidcService.provider.issuer,
		"audience", data.ClientID,
		"subject", data.UserID,
		"nonce_in_id_token", data.Nonce != "",
	)
	s.writeJSON(ctx, fasthttp.StatusOK, map[string]any{
		"access_token": accessToken,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   int64(s.oidcService.provider.accessTokenLifetime.Seconds()),
		"scope":        data.Scope,
	})
}

type tokenClaims struct {
	TokenUse          string `json:"token_use"`
	AuthFlowID        string `json:"auth_flow_id"`
	Nonce             string `json:"nonce,omitempty"`
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
	jwt.RegisteredClaims
}

func (s *HTTPServer) issueTokens(data AuthCodeData) (string, string, error) {
	now := time.Now()
	profileName := data.Username
	if local, _, found := strings.Cut(data.Username, "@"); found && local != "" {
		profileName = local
	}
	email := ""
	if strings.Contains(data.Username, "@") {
		email = data.Username
	}
	base := func(lifetime time.Duration) jwt.RegisteredClaims {
		return jwt.RegisteredClaims{
			Issuer:    s.oidcService.provider.issuer,
			Subject:   data.UserID,
			Audience:  jwt.ClaimStrings{data.ClientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(lifetime)),
		}
	}
	access, err := s.signToken("at+jwt", tokenClaims{
		TokenUse: "access", AuthFlowID: data.FlowID, Name: data.Username,
		GivenName: profileName, FamilyName: profileName, PreferredUsername: data.Username,
		Email: email, RegisteredClaims: base(s.oidcService.provider.accessTokenLifetime),
	})
	if err != nil {
		return "", "", err
	}
	idToken, err := s.signToken("JWT", tokenClaims{
		TokenUse: "id", AuthFlowID: data.FlowID, Nonce: data.Nonce, Name: data.Username,
		GivenName: profileName, FamilyName: profileName, PreferredUsername: data.Username,
		Email: email, RegisteredClaims: base(s.oidcService.provider.idTokenLifetime),
	})
	return access, idToken, err
}

func (s *HTTPServer) signToken(tokenType string, claims tokenClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.oidcService.provider.kid
	token.Header["typ"] = tokenType
	return token.SignedString(s.oidcService.provider.privateKey)
}

func (s *HTTPServer) handleUserInfo(ctx *fasthttp.RequestCtx) {
	header := string(ctx.Request.Header.Peek("Authorization"))
	if !strings.HasPrefix(header, "Bearer ") || len(header) == len("Bearer ") {
		s.userInfoError(ctx, "missing bearer access token")
		return
	}
	claims, err := s.verifyAccessToken(strings.TrimPrefix(header, "Bearer "))
	if err != nil {
		s.oidcService.provider.logger.Warn("userinfo request rejected", "decision", "invalid_access_token")
		s.userInfoError(ctx, "invalid access token")
		return
	}
	logger := s.oidcService.provider.logger.With("auth_flow_id", claims.AuthFlowID)
	if claims.Subject == "" {
		logger.Warn("userinfo request rejected", "decision", "subject_missing")
		s.userInfoError(ctx, "access token subject is missing")
		return
	}
	logger.Info("userinfo request accepted",
		"client_id", s.oidcService.provider.clientID,
		"decision", "subject_matched",
		"issuer", claims.Issuer,
		"audience", claims.Audience,
		"subject", claims.Subject,
	)
	response := map[string]any{
		"sub":                claims.Subject,
		"name":               claims.Name,
		"given_name":         claims.GivenName,
		"family_name":        claims.FamilyName,
		"preferred_username": claims.PreferredUsername,
	}
	if claims.Email != "" {
		response["email"] = claims.Email
	}
	s.writeJSON(ctx, fasthttp.StatusOK, response)
}

func (s *HTTPServer) verifyAccessToken(raw string) (*tokenClaims, error) {
	claims := new(tokenClaims)
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 || token.Header["kid"] != s.oidcService.provider.kid {
			return nil, errors.New("unexpected signing key or algorithm")
		}
		return &s.oidcService.provider.privateKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(s.oidcService.provider.issuer),
		jwt.WithAudience(s.oidcService.provider.clientID), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !token.Valid || claims.TokenUse != "access" {
		return nil, errors.New("invalid access token")
	}
	return claims, nil
}

func (s *HTTPServer) userInfoError(ctx *fasthttp.RequestCtx, description string) {
	ctx.Response.Header.Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	s.writeOAuthError(ctx, fasthttp.StatusUnauthorized, "invalid_token", description)
}

func (s *HTTPServer) handleDiscovery(ctx *fasthttp.RequestCtx) {
	issuer := s.oidcService.provider.issuer
	s.writeJSON(ctx, fasthttp.StatusOK, OIDCDiscovery{
		Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token",
		UserinfoEndpoint: issuer + "/userinfo", JwksURI: issuer + "/jwks",
		ResponseTypesSupported: []string{"code"}, SubjectTypesSupported: []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"}, ScopesSupported: []string{"openid", "profile", "email"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat", "nonce", "name", "given_name", "family_name", "email", "preferred_username"},
		CodeChallengeMethodsSupported:     []string{"S256"},
	})
}

func (s *HTTPServer) handleJWKS(ctx *fasthttp.RequestCtx) {
	key := &s.oidcService.provider.privateKey.PublicKey
	s.writeJSON(ctx, fasthttp.StatusOK, JWKSResponse{Keys: []JWK{{
		Kty: "RSA", Kid: s.oidcService.provider.kid, Alg: "RS256", Use: "sig",
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}})
}

func (s *HTTPServer) redirectError(ctx *fasthttp.RequestCtx, redirectURI, state, code, description string) {
	redirectWithParams(ctx, redirectURI, map[string]string{"error": code, "error_description": description, "state": state})
}

func redirectWithParams(ctx *fasthttp.RequestCtx, rawURL string, params map[string]string) {
	target, err := url.Parse(rawURL)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		return
	}
	query := target.Query()
	for key, value := range params {
		if value != "" {
			query.Set(key, value)
		}
	}
	target.RawQuery = query.Encode()
	ctx.Redirect(target.String(), fasthttp.StatusFound)
}

func (s *HTTPServer) writeOAuthError(ctx *fasthttp.RequestCtx, status int, code, description string) {
	s.writeJSON(ctx, status, map[string]string{"error": code, "error_description": description})
}

func (s *HTTPServer) writeJSON(ctx *fasthttp.RequestCtx, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		return
	}
	ctx.SetContentType("application/json")
	ctx.Response.Header.Set("Cache-Control", "no-store")
	ctx.Response.Header.Set("Pragma", "no-cache")
	ctx.SetStatusCode(status)
	_, _ = ctx.Write(data)
}

func randomHandle() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func validPKCE(challenge, verifier string) bool {
	if challenge == "" {
		return verifier == ""
	}
	if len(verifier) < 43 || len(verifier) > 128 || !validPKCEChars(verifier) {
		return false
	}
	digest := sha256.Sum256([]byte(verifier))
	return hmac.Equal([]byte(challenge), []byte(base64.RawURLEncoding.EncodeToString(digest[:])))
}

func validCodeChallenge(challenge string) bool {
	return len(challenge) == 43 && validPKCEChars(challenge)
}

func validPKCEChars(value string) bool {
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("-._~", r)) {
			return false
		}
	}
	return true
}

func hasScope(scopes, wanted string) bool {
	return slices.Contains(strings.Fields(scopes), wanted)
}

func clientCredentials(ctx *fasthttp.RequestCtx) (string, string, error) {
	header := string(ctx.Request.Header.Peek("Authorization"))
	postID := string(ctx.PostArgs().Peek("client_id"))
	postSecret := string(ctx.PostArgs().Peek("client_secret"))
	if header == "" {
		if postID == "" || postSecret == "" {
			return postID, postSecret, errors.New("missing client credentials")
		}
		return postID, postSecret, nil
	}
	if postID != "" || postSecret != "" || !strings.HasPrefix(header, "Basic ") {
		return "", "", errors.New("conflicting or unsupported client authentication")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "Basic "))
	if err != nil {
		return "", "", errors.New("invalid basic authentication")
	}
	pair := strings.SplitN(string(decoded), ":", 2)
	if len(pair) != 2 {
		return "", "", errors.New("invalid basic authentication")
	}
	clientID, err := url.QueryUnescape(pair[0])
	if err != nil {
		return "", "", err
	}
	secret, err := url.QueryUnescape(pair[1])
	return clientID, secret, err
}

func constantTimeEqual(actual, expected string) bool {
	return len(actual) == len(expected) && hmac.Equal([]byte(actual), []byte(expected))
}

type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type OIDCDiscovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}
