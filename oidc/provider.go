package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"auth-service/entity"
	"auth-service/sso"
)

const (
	defaultCodeLifetime        = 2 * time.Minute
	defaultAuthorizationExpiry = 5 * time.Minute
	defaultAccessTokenLifetime = 15 * time.Minute
	defaultIDTokenLifetime     = 5 * time.Minute
)

// Authenticator is the application boundary needed by the OIDC login page.
type Authenticator interface {
	CheckUserAuth(context.Context, entity.User) (bool, string, error)
}

// Config contains the externally managed OIDC provider registration and key settings.
type Config struct {
	Issuer                    string
	ClientID                  string
	ClientSecret              string
	RedirectURIs              []string
	PrivateKeyFile            string
	AllowEphemeralDevelopment bool
	CodeLifetime              time.Duration
	AuthorizationLifetime     time.Duration
	AccessTokenLifetime       time.Duration
	IDTokenLifetime           time.Duration
	Logger                    *slog.Logger
}

// ConfigFromEnv reads the provider's runtime registration. Secrets are never defaulted.
func ConfigFromEnv() (Config, error) {
	ephemeral, err := strconv.ParseBool(envOrDefault("OIDC_ALLOW_EPHEMERAL_KEY", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse OIDC_ALLOW_EPHEMERAL_KEY: %w", err)
	}

	redirects := strings.FieldsFunc(os.Getenv("OIDC_REDIRECT_URIS"), func(r rune) bool {
		return r == ',' || r == '\n'
	})
	for i := range redirects {
		redirects[i] = strings.TrimSpace(redirects[i])
	}

	return Config{
		Issuer:                    os.Getenv("OIDC_ISSUER"),
		ClientID:                  os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret:              os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectURIs:              redirects,
		PrivateKeyFile:            os.Getenv("OIDC_PRIVATE_KEY_FILE"),
		AllowEphemeralDevelopment: ephemeral,
	}, nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

type OIDCProvider struct {
	issuer                string
	clientID              string
	clientSecret          string
	redirectURIs          map[string]struct{}
	privateKey            *rsa.PrivateKey
	kid                   string
	auth                  Authenticator
	logger                *slog.Logger
	codeLifetime          time.Duration
	authorizationLifetime time.Duration
	accessTokenLifetime   time.Duration
	idTokenLifetime       time.Duration
	initErr               error
}

// NewProvider constructs a fully validated provider and is the preferred API.
func NewProvider(cfg Config, auth Authenticator) (*OIDCProvider, error) {
	if auth == nil {
		return nil, errors.New("OIDC authenticator is required")
	}
	cfg.Issuer = strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || issuer.Scheme == "" || issuer.Host == "" || issuer.RawQuery != "" || issuer.Fragment != "" {
		return nil, errors.New("OIDC issuer must be an absolute URL without query or fragment")
	}
	if issuer.Path != "" && issuer.Path != "/" {
		return nil, errors.New("OIDC issuer path is not supported; publish the provider at a dedicated origin")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("OIDC client ID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("OIDC client secret is required")
	}
	if len(cfg.RedirectURIs) == 0 {
		return nil, errors.New("at least one OIDC redirect URI is required")
	}

	redirects := make(map[string]struct{}, len(cfg.RedirectURIs))
	for _, raw := range cfg.RedirectURIs {
		parsed, parseErr := url.Parse(raw)
		if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("invalid OIDC redirect URI %q", raw)
		}
		redirects[raw] = struct{}{}
	}

	key, err := loadPrivateKey(cfg.PrivateKeyFile, cfg.AllowEphemeralDevelopment)
	if err != nil {
		return nil, err
	}
	if key.N.BitLen() < 2048 {
		return nil, errors.New("OIDC RSA private key must be at least 2048 bits")
	}
	keyID, err := keyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &OIDCProvider{
		issuer:                cfg.Issuer,
		clientID:              cfg.ClientID,
		clientSecret:          cfg.ClientSecret,
		redirectURIs:          redirects,
		privateKey:            key,
		kid:                   keyID,
		auth:                  auth,
		logger:                logger,
		codeLifetime:          durationOrDefault(cfg.CodeLifetime, defaultCodeLifetime),
		authorizationLifetime: durationOrDefault(cfg.AuthorizationLifetime, defaultAuthorizationExpiry),
		accessTokenLifetime:   durationOrDefault(cfg.AccessTokenLifetime, defaultAccessTokenLifetime),
		idTokenLifetime:       durationOrDefault(cfg.IDTokenLifetime, defaultIDTokenLifetime),
	}, nil
}

// NewProviderFromEnv loads the environment registration and validates it.
func NewProviderFromEnv(auth Authenticator) (*OIDCProvider, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return NewProvider(cfg, auth)
}

// NewOIDCProvider preserves the prototype API. New callers should use NewProvider
// so configuration errors can be handled before server startup.
func NewOIDCProvider(auth *sso.AuthService) *OIDCProvider {
	provider, err := NewProviderFromEnv(auth)
	if err == nil {
		return provider
	}
	return &OIDCProvider{auth: auth, logger: slog.Default(), initErr: err}
}

func durationOrDefault(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func loadPrivateKey(path string, allowEphemeral bool) (*rsa.PrivateKey, error) {
	if path == "" {
		if !allowEphemeral {
			return nil, errors.New("OIDC_PRIVATE_KEY_FILE is required unless OIDC_ALLOW_EPHEMERAL_KEY=true")
		}
		return rsa.GenerateKey(rand.Reader, 2048)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read OIDC private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("OIDC private key file does not contain PEM data")
	}
	if key, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes); parseErr == nil {
		return key, key.Validate()
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse OIDC private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("OIDC private key must be RSA")
	}
	return key, key.Validate()
}

func keyID(publicKey *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal OIDC public key: %w", err)
	}
	digest := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}
