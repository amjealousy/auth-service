package token

import (
	"auth-service/entity"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTMaker struct {
	secretKey  string
	issuer     string
	clientID   string
	signMethod jwt.SigningMethod
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewJWTMaker(secretKey string, method jwt.SigningMethod, clientId string) *JWTMaker {
	return &JWTMaker{secretKey: secretKey, issuer: "amjealousy", signMethod: method, clientID: clientId}
}
func (maker *JWTMaker) SetKeys(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) {
	maker.privateKey = privateKey
	maker.publicKey = publicKey
}

func (maker *JWTMaker) CreateToken(user entity.User, isAdmin bool, duration time.Duration) (string, *UserClaims, error) {
	switch maker.signMethod {
	case jwt.SigningMethodHS256:
		claims, err := NewUserClaims(user, isAdmin, duration, maker.issuer, maker.clientID)
		if err != nil {
			return "", nil, err
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenStr, err := token.SignedString([]byte(maker.secretKey))
		if err != nil {
			return "", nil, fmt.Errorf("error signing token: %w", err)
		}
		return tokenStr, claims, nil
	case jwt.SigningMethodRS256:
		claims, err := NewUserClaims(user, isAdmin, duration, maker.issuer, maker.clientID)
		if err != nil {
			return "", nil, fmt.Errorf("error signing token: %w", err)
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "1"
		tokenStr, err := token.SignedString(maker.privateKey)
		if err != nil {
			return "", nil, fmt.Errorf("error signing token: %w", err)
		}
		return tokenStr, claims, nil
	default:
		return "", nil, fmt.Errorf("unknown sign method: %v", maker.signMethod)
	}
}

func (maker *JWTMaker) VerifyToken(tokenStr string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		switch maker.signMethod {
		case jwt.SigningMethodHS256:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
				return []byte(maker.secretKey), nil
			}
		case jwt.SigningMethodRS256:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); ok {
				return maker.publicKey, nil
			}
		}
		return nil, fmt.Errorf("invalid token signing method")
	})

	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(*UserClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}
