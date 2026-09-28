package main

import (
	"auth-service/oidc"
	protectedapi "auth-service/protected-api"
	"auth-service/rpc"
	"auth-service/sso"
	"log/slog"
	"os"
	"time"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	auth := sso.NewAuthService()
	server := rpc.NewServer(auth)

	provider, err := oidc.NewProviderFromEnv(auth)
	if err != nil {
		logger.Error("OIDC provider configuration rejected", "error", err)
		os.Exit(1)
	}
	httpServer, err := oidc.NewHTTPServerWithLogger(":4888", logger)
	if err != nil {
		logger.Error("OIDC HTTP server initialization failed", "error", err)
		os.Exit(1)
	}
	go func() {
		if err := httpServer.Run(provider); err != nil {
			logger.Error("OIDC HTTP server stopped", "error", err)
		}
	}()
	go func() {
		for {
			if err := protectedapi.RunAPI(); err != nil {
				logger.Error("protected API stopped; retrying", "error", err, "retry_after", "5s")
				time.Sleep(5 * time.Second)
				continue
			}
			return
		}
	}()

	server.Listen()
}
