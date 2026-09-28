package protected_api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	sessionCookieName = "protected_api_session"
	flowLifetime      = 10 * time.Minute
)

type contextKey int

const requestIDKey contextKey = iota

//go:embed keycloak.html
var webFiles embed.FS

type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	IDPHint      string
	APIAudience  string
	ListenAddr   string
}

type UserClaims struct {
	Sub               string `json:"sub"`
	Email             string `json:"email,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access,omitempty"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access,omitempty"`
}

type loginFlow struct {
	State        string
	Nonce        string
	CodeVerifier string
	RequestID    string
	ExpiresAt    time.Time
}

type session struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	User         UserClaims
	AuthFlowID   string
	ExpiresAt    time.Time
}

type ProtectedAPI struct {
	config         Config
	oauthConfig    oauth2.Config
	idVerifier     *oidc.IDTokenVerifier
	accessVerifier *oidc.IDTokenVerifier
	logger         *slog.Logger
	cookieSecure   bool

	mu       sync.RWMutex
	flows    map[string]loginFlow
	sessions map[string]session
	stop     chan struct{}
	stopOnce sync.Once
}

func LoadConfigFromEnv() (Config, error) {
	cfg := Config{
		Issuer:       strings.TrimSuffix(strings.TrimSpace(os.Getenv("KEYCLOAK_ISSUER")), "/"),
		ClientID:     strings.TrimSpace(os.Getenv("KEYCLOAK_CLIENT_ID")),
		ClientSecret: os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		RedirectURL:  strings.TrimSpace(os.Getenv("KEYCLOAK_REDIRECT_URL")),
		IDPHint:      strings.TrimSpace(os.Getenv("KEYCLOAK_IDP_HINT")),
		APIAudience:  strings.TrimSpace(os.Getenv("PROTECTED_API_AUDIENCE")),
		ListenAddr:   strings.TrimSpace(os.Getenv("PROTECTED_API_LISTEN_ADDR")),
	}

	var missing []string
	for name, value := range map[string]string{
		"KEYCLOAK_ISSUER":           cfg.Issuer,
		"KEYCLOAK_CLIENT_ID":        cfg.ClientID,
		"KEYCLOAK_CLIENT_SECRET":    cfg.ClientSecret,
		"KEYCLOAK_REDIRECT_URL":     cfg.RedirectURL,
		"PROTECTED_API_AUDIENCE":    cfg.APIAudience,
		"PROTECTED_API_LISTEN_ADDR": cfg.ListenAddr,
	} {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	redirectURL, err := url.Parse(cfg.RedirectURL)
	if err != nil || redirectURL.Host == "" || (redirectURL.Scheme != "http" && redirectURL.Scheme != "https") {
		return Config{}, errors.New("KEYCLOAK_REDIRECT_URL must be an absolute http or https URL")
	}
	issuerURL, err := url.Parse(cfg.Issuer)
	if err != nil || issuerURL.Host == "" || (issuerURL.Scheme != "http" && issuerURL.Scheme != "https") {
		return Config{}, errors.New("KEYCLOAK_ISSUER must be an absolute http or https URL")
	}

	return cfg, nil
}

func NewProtectedAPI(ctx context.Context, cfg Config, logger *slog.Logger) (*ProtectedAPI, error) {
	if logger == nil {
		logger = slog.Default()
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover Keycloak issuer: %w", err)
	}
	redirectURL, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		return nil, fmt.Errorf("parse redirect URL: %w", err)
	}

	api := &ProtectedAPI{
		config: cfg,
		oauthConfig: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		idVerifier:     provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		accessVerifier: provider.Verifier(&oidc.Config{SkipClientIDCheck: true}),
		logger:         logger,
		cookieSecure:   redirectURL.Scheme == "https",
		flows:          make(map[string]loginFlow),
		sessions:       make(map[string]session),
		stop:           make(chan struct{}),
	}
	go api.cleanupLoop()
	return api, nil
}

func (api *ProtectedAPI) Close() {
	api.stopOnce.Do(func() { close(api.stop) })
}

func (api *ProtectedAPI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", api.indexHandler)
	mux.HandleFunc("/login", api.loginHandler)
	mux.HandleFunc("/callback", api.callbackHandler)
	mux.HandleFunc("/session", api.sessionHandler)
	mux.HandleFunc("/logout", api.logoutHandler)
	mux.HandleFunc("/api/protected", api.protectedHandler)
	return api.withRequestID(mux)
}

func (api *ProtectedAPI) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFileFS(w, r, webFiles, "keycloak.html")
}

func (api *ProtectedAPI) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	state, err := randomString(32)
	if err != nil {
		api.internalError(w, r, "generate_state", err)
		return
	}
	nonce, err := randomString(32)
	if err != nil {
		api.internalError(w, r, "generate_nonce", err)
		return
	}
	verifier, err := randomString(64)
	if err != nil {
		api.internalError(w, r, "generate_pkce", err)
		return
	}
	flowID, err := randomString(32)
	if err != nil {
		api.internalError(w, r, "generate_flow_id", err)
		return
	}

	flow := loginFlow{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		RequestID:    requestID(r.Context()),
		ExpiresAt:    time.Now().Add(flowLifetime),
	}
	api.mu.Lock()
	api.flows[flowID] = flow
	api.mu.Unlock()
	api.setCookie(w, flowID, flow.ExpiresAt)

	challenge := sha256.Sum256([]byte(verifier))
	options := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	if api.config.IDPHint != "" {
		options = append(options, oauth2.SetAuthURLParam("kc_idp_hint", api.config.IDPHint))
	}
	api.logDecision(r, flowID, "login_started", slog.Time("expires_at", flow.ExpiresAt))
	http.Redirect(w, r, api.oauthConfig.AuthCodeURL(state, options...), http.StatusSeeOther)
}

func (api *ProtectedAPI) callbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		api.rejectCallback(w, r, "", "missing_flow_cookie")
		return
	}
	flowID := cookie.Value

	api.mu.Lock()
	flow, ok := api.flows[flowID]
	delete(api.flows, flowID)
	api.mu.Unlock()
	api.clearCookie(w)
	if !ok {
		api.rejectCallback(w, r, flowID, "unknown_or_consumed_flow")
		return
	}
	if time.Now().After(flow.ExpiresAt) {
		api.rejectCallback(w, r, flowID, "expired_flow")
		return
	}
	state := r.URL.Query().Get("state")
	if state == "" || !hmac.Equal([]byte(state), []byte(flow.State)) {
		api.rejectCallback(w, r, flowID, "state_mismatch")
		return
	}
	if providerError := r.URL.Query().Get("error"); providerError != "" {
		api.logDecision(r, flowID, "provider_rejected_login", slog.String("provider_error", safeOAuthError(providerError)))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login rejected by identity provider"})
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		api.rejectCallback(w, r, flowID, "missing_code")
		return
	}

	oauthToken, err := api.oauthConfig.Exchange(r.Context(), code, oauth2.SetAuthURLParam("code_verifier", flow.CodeVerifier))
	if err != nil {
		api.logDecision(r, flowID, "code_exchange_failed", slog.String("error_type", fmt.Sprintf("%T", err)))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login failed"})
		return
	}
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		api.rejectCallback(w, r, flowID, "missing_id_token")
		return
	}
	idToken, err := api.idVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		api.logDecision(r, flowID, "id_token_rejected", slog.String("error_type", fmt.Sprintf("%T", err)))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login failed"})
		return
	}
	if !hmac.Equal([]byte(idToken.Nonce), []byte(flow.Nonce)) {
		api.rejectCallback(w, r, flowID, "nonce_mismatch")
		return
	}
	api.logDecision(r, flowID, "id_token_accepted",
		slog.String("issuer", idToken.Issuer),
		slog.Any("audience", idToken.Audience),
		slog.String("subject", idToken.Subject),
		slog.Time("expires_at", idToken.Expiry),
		slog.Bool("signature_valid", true),
		slog.Bool("nonce_matched", true),
	)
	if oauthToken.AccessToken == "" {
		api.rejectCallback(w, r, flowID, "missing_access_token")
		return
	}
	accessToken, accessClaims, err := api.verifyAccessToken(r.Context(), oauthToken.AccessToken)
	if err != nil {
		api.logDecision(r, flowID, "access_token_rejected", slog.String("reason", err.Error()))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login failed"})
		return
	}
	api.logDecision(r, flowID, "access_token_accepted",
		slog.String("issuer", accessToken.Issuer),
		slog.Any("audience", accessToken.Audience),
		slog.String("required_audience", api.config.APIAudience),
		slog.String("subject", accessToken.Subject),
		slog.Time("expires_at", accessToken.Expiry),
		slog.Bool("signature_valid", true),
		slog.Bool("audience_matched", true),
	)
	var user UserClaims
	if err := idToken.Claims(&user); err != nil || user.Sub == "" {
		api.rejectCallback(w, r, flowID, "invalid_id_token_claims")
		return
	}
	if user.Sub != idToken.Subject || user.Sub != accessClaims.Sub {
		api.rejectCallback(w, r, flowID, "subject_mismatch")
		return
	}
	// Authorization data belongs to the access token. Keep identity profile fields from the ID token.
	user.RealmAccess = accessClaims.RealmAccess
	user.ResourceAccess = accessClaims.ResourceAccess

	sessionID, err := randomString(32)
	if err != nil {
		api.internalError(w, r, "generate_session_id", err)
		return
	}
	expiresAt := earlierTime(idToken.Expiry, accessToken.Expiry)
	newSession := session{
		AccessToken:  oauthToken.AccessToken,
		IDToken:      rawIDToken,
		RefreshToken: oauthToken.RefreshToken,
		User:         user,
		AuthFlowID:   flowID,
		ExpiresAt:    expiresAt,
	}
	api.mu.Lock()
	api.sessions[sessionID] = newSession
	api.mu.Unlock()
	api.setCookie(w, sessionID, expiresAt)
	api.logDecision(r, flowID, "session_created", slog.String("subject", user.Sub), slog.Time("expires_at", expiresAt))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (api *ProtectedAPI) sessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	current, ok := api.sessionFromRequest(r)
	if !ok {
		api.logDecision(r, "", "session_missing_or_expired")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}
	api.logDecision(r, current.AuthFlowID, "session_accepted", slog.String("subject", current.User.Sub))
	writeJSON(w, http.StatusOK, api.sessionResponse(current))
}

func (api *ProtectedAPI) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	authFlowID := ""
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		api.mu.Lock()
		if current, ok := api.sessions[cookie.Value]; ok {
			authFlowID = current.AuthFlowID
		}
		delete(api.sessions, cookie.Value)
		delete(api.flows, cookie.Value)
		api.mu.Unlock()
	}
	api.clearCookie(w)
	api.logDecision(r, authFlowID, "session_logged_out")
	w.WriteHeader(http.StatusNoContent)
}

func (api *ProtectedAPI) protectedHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	var user UserClaims
	authType := "session"
	authFlowID := ""
	authorizationHeaders := r.Header.Values("Authorization")
	if len(authorizationHeaders) > 0 {
		rawToken, ok := parseBearerHeaders(authorizationHeaders)
		if !ok {
			api.logDecision(r, "", "bearer_rejected", slog.String("reason", "malformed_authorization_header"))
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid bearer token"})
			return
		}
		_, claims, err := api.verifyAccessToken(r.Context(), rawToken)
		if err != nil {
			api.logDecision(r, "", "bearer_rejected", slog.String("reason", err.Error()))
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid bearer token"})
			return
		}
		user = claims
		authType = "bearer"
		api.logDecision(r, "", "bearer_token_accepted",
			slog.String("issuer", api.config.Issuer),
			slog.String("required_audience", api.config.APIAudience),
			slog.String("subject", claims.Sub),
			slog.Bool("signature_valid", true),
			slog.Bool("audience_matched", true),
		)
	} else {
		current, ok := api.sessionFromRequest(r)
		if !ok {
			api.logDecision(r, "", "protected_access_rejected", slog.String("reason", "missing_or_expired_session"))
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
			return
		}
		user = current.User
		authFlowID = current.AuthFlowID
	}
	api.logDecision(r, authFlowID, "protected_access_allowed", slog.String("auth_type", authType), slog.String("subject", user.Sub))
	writeJSON(w, http.StatusOK, map[string]any{
		"message":     "access granted",
		"auth_type":   authType,
		"user":        api.profileResponse(user),
		"secret_data": "protected demo data",
	})
}

func (api *ProtectedAPI) verifyAccessToken(ctx context.Context, rawToken string) (*oidc.IDToken, UserClaims, error) {
	if rawToken == "" || strings.Count(rawToken, ".") != 2 {
		return nil, UserClaims{}, errors.New("malformed_token")
	}
	token, err := api.accessVerifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, UserClaims{}, errors.New("signature_or_standard_claims_invalid")
	}
	if !slices.Contains(token.Audience, api.config.APIAudience) {
		return nil, UserClaims{}, errors.New("audience_invalid")
	}
	var claims UserClaims
	if err := token.Claims(&claims); err != nil || claims.Sub == "" || claims.Sub != token.Subject {
		return nil, UserClaims{}, errors.New("subject_invalid")
	}
	return token, claims, nil
}

func (api *ProtectedAPI) sessionFromRequest(r *http.Request) (session, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return session{}, false
	}
	api.mu.RLock()
	current, ok := api.sessions[cookie.Value]
	api.mu.RUnlock()
	if !ok {
		return session{}, false
	}
	if !time.Now().Before(current.ExpiresAt) {
		api.mu.Lock()
		delete(api.sessions, cookie.Value)
		api.mu.Unlock()
		return session{}, false
	}
	return current, true
}

func (api *ProtectedAPI) sessionResponse(current session) map[string]any {
	return map[string]any{
		"authenticated": true,
		"expires_at":    current.ExpiresAt,
		"user":          api.profileResponse(current.User),
	}
}

func (api *ProtectedAPI) profileResponse(user UserClaims) map[string]any {
	clientRoles := []string{}
	if access, ok := user.ResourceAccess[api.config.APIAudience]; ok {
		clientRoles = access.Roles
	}
	return map[string]any{
		"id":                 user.Sub,
		"preferred_username": user.PreferredUsername,
		"email":              user.Email,
		"realm_roles":        user.RealmAccess.Roles,
		"client_roles":       clientRoles,
	}
}

func (api *ProtectedAPI) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !validRequestID(id) {
			var err error
			id, err = randomString(18)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
				return
			}
		}
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (api *ProtectedAPI) setCookie(w http.ResponseWriter, value string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   max(1, int(time.Until(expiresAt).Seconds())),
		HttpOnly: true,
		Secure:   api.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (api *ProtectedAPI) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   api.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (api *ProtectedAPI) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			api.mu.Lock()
			for id, flow := range api.flows {
				if !now.Before(flow.ExpiresAt) {
					delete(api.flows, id)
				}
			}
			for id, current := range api.sessions {
				if !now.Before(current.ExpiresAt) {
					delete(api.sessions, id)
				}
			}
			api.mu.Unlock()
		case <-api.stop:
			return
		}
	}
}

func (api *ProtectedAPI) rejectCallback(w http.ResponseWriter, r *http.Request, flowID, reason string) {
	api.logDecision(r, flowID, "callback_rejected", slog.String("reason", reason))
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login failed"})
}

func (api *ProtectedAPI) internalError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	api.logger.ErrorContext(r.Context(), "request failed",
		slog.String("request_id", requestID(r.Context())),
		slog.String("operation", operation),
		slog.String("error_type", fmt.Sprintf("%T", err)),
	)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
}

func (api *ProtectedAPI) logDecision(r *http.Request, authFlowID, decision string, attrs ...slog.Attr) {
	base := []slog.Attr{
		slog.String("request_id", requestID(r.Context())),
		slog.String("auth_flow_id", authFlowID),
		slog.String("decision", decision),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
	}
	api.logger.LogAttrs(r.Context(), slog.LevelInfo, "authentication decision", append(base, attrs...)...)
}

func randomString(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func parseBearer(header string) (string, bool) {
	parts := strings.Fields(header)
	returnToken := ""
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		returnToken = parts[1]
	}
	return returnToken, returnToken != "" && !strings.ContainsAny(header, "\r\n")
}

func parseBearerHeaders(headers []string) (string, bool) {
	if len(headers) != 1 {
		return "", false
	}
	return parseBearer(headers[0])
}

func contains(values []string, expected string) bool {
	return slices.Contains(values, expected)
}

func earlierTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}

func validRequestID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' && char != '_' && char != '.' {
			return false
		}
	}
	return true
}

func safeOAuthError(value string) string {
	switch value {
	case "access_denied", "interaction_required", "login_required", "temporarily_unavailable", "server_error":
		return value
	default:
		return "other"
	}
}

func requestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// RunAPI loads environment configuration, discovers Keycloak, and blocks while serving HTTP.
func RunAPI() error {
	cfg, err := LoadConfigFromEnv()
	if err != nil {
		return err
	}
	api, err := NewProtectedAPI(context.Background(), cfg, slog.Default())
	if err != nil {
		return err
	}
	defer api.Close()

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	api.logger.Info("protected API listening", slog.String("listen_addr", cfg.ListenAddr), slog.String("issuer", cfg.Issuer), slog.String("api_audience", cfg.APIAudience))
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve protected API: %w", err)
	}
	return nil
}
