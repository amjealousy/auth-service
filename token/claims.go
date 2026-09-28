package token

import (
	"auth-service/entity"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type UserClaims struct {
	Email   string `json:"email"`
	Iss     string `json:"iss"`
	IsAdmin bool   `json:"is_admin"`
	Aud     string `json:"aud"`
	Sub     string `json:"sub"`
	jwt.RegisteredClaims
}

func NewUserClaims(user entity.User, isAdmin bool, duration time.Duration, iss string, clientID string) (*UserClaims, error) {
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("error generating token ID: %w", err)
	}

	return &UserClaims{
		Email:   user.Username,
		Aud:     clientID,
		Sub:     user.Id.String(),
		Iss:     iss,
		IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID.String(),
			Subject:   user.Username,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
		},
	}, nil
}
