package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"auth-service/entity"

	"github.com/stretchr/testify/require"
)

type fakeAuthenticator struct {
	password string
	subject  string
}

func (a fakeAuthenticator) CheckUserAuth(_ context.Context, user entity.User) (bool, string, error) {
	return user.Password == a.password, a.subject, nil
}

func TestNewProviderRequiresExplicitEphemeralKeyOptIn(t *testing.T) {
	_, err := NewProvider(validTestConfig(), fakeAuthenticator{password: "password", subject: "user-1"})
	require.ErrorContains(t, err, "OIDC_PRIVATE_KEY_FILE")
}

func TestNewProviderLoadsStablePEMKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "oidc.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0o600))

	cfg := validTestConfig()
	cfg.PrivateKeyFile = path
	first, err := NewProvider(cfg, fakeAuthenticator{password: "password", subject: "user-1"})
	require.NoError(t, err)
	second, err := NewProvider(cfg, fakeAuthenticator{password: "password", subject: "user-1"})
	require.NoError(t, err)
	require.Equal(t, first.kid, second.kid)
	require.Equal(t, key.N, first.privateKey.N)
}

func TestAuthorizationCodeExpiresAndCannotBeConsumed(t *testing.T) {
	service := NewOIDCService(&OIDCProvider{})
	service.putCode("expired", AuthCodeData{
		ClientID:    "client",
		RedirectURI: "https://broker.example/callback",
		ExpiresAt:   time.Now().Add(-time.Second),
	})
	_, decision := service.consumeCode("expired", "client", "https://broker.example/callback", "")
	require.Equal(t, "code_expired", decision)
	_, decision = service.consumeCode("expired", "client", "https://broker.example/callback", "")
	require.Equal(t, "code_not_found", decision)
}

func TestNewProviderRejectsIssuerPath(t *testing.T) {
	cfg := validTestConfig()
	cfg.AllowEphemeralDevelopment = true
	cfg.Issuer = "https://issuer.example/oidc"
	_, err := NewProvider(cfg, fakeAuthenticator{password: "password", subject: "user-1"})
	require.ErrorContains(t, err, "issuer path")
}

func validTestConfig() Config {
	return Config{
		Issuer:       "https://issuer.example/",
		ClientID:     "keycloak-broker",
		ClientSecret: "test-client-secret",
		RedirectURIs: []string{"https://broker.example/callback?existing=1"},
		Logger:       slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}
}
