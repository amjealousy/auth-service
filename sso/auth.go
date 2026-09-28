package sso

import (
	"auth-service/entity"
	"auth-service/repository"
	"auth-service/token"
	"auth-service/utils"
	"context"
	"crypto/rand"
	"crypto/rsa"

	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuthService struct {
	ur       repository.UserRepository
	sr       repository.SessionRepository
	pool     *pgxpool.Pool
	appToken string
	clientID string
	scope    string
	privkey  *rsa.PrivateKey
	pubkey   *rsa.PublicKey
}

func NewAuthService() *AuthService {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	publicKey := &privateKey.PublicKey
	pool := repository.GetDBTX()
	var connector repository.DBTX = pool
	return &AuthService{
		ur:       repository.NewUserRepository(&connector),
		sr:       repository.NewSessionRepository(&connector),
		pool:     pool,
		appToken: os.Getenv("AUTH_TOKEN_SECRET"),
		clientID: envOrDefault("AUTH_TOKEN_AUDIENCE", "auth-service"),
		privkey:  privateKey,
		pubkey:   publicKey,
		scope:    "user",
	}
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
func (as AuthService) CheckUserAuth(ctx context.Context, user entity.User) (bool, string, error) {
	if err, userauth := as.ur.FindUserByName(ctx, user.Username); err == nil {
		if user.Password != "" {
			err := utils.CheckPassword(user.Password, userauth.Hpassword)
			if err != nil {
				return false, "", fmt.Errorf("the password does not match the hash ")
			}
			user.Id, _ = uuid.Parse(userauth.ID.String())
		}
		return true, userauth.ID.String(), nil
	} else {
		fmt.Println("Error after FindUserByName - " + err.Error())
		return false, "", fmt.Errorf("cant't find user with username %s", user.Username)
	}
}
func (as AuthService) GenerateTokenPair(user entity.User, method jwt.SigningMethod) (error, string, string) {
	maker := token.NewJWTMaker(as.appToken, method, as.clientID)
	maker.SetKeys(as.privkey, as.pubkey)
	accessToken, _, err := maker.CreateToken(user, false, 15*time.Minute)
	if err != nil {
		return err, "", ""
	}

	refreshToken, _, err := maker.CreateToken(user, false, 24*time.Hour)
	if err != nil {
		return err, "", ""
	}

	return nil, accessToken, refreshToken
}
func (as AuthService) Login(ctx context.Context, user entity.User) (error, string, entity.SessionDTO) {
	value, ok := ctx.Value("method").(jwt.SigningMethod)
	if !ok || value == nil {
		value = jwt.SigningMethodRS256
	}

	err, access, refresh := as.GenerateTokenPair(user, value)
	if err != nil {
		fmt.Println("Error after GenerateTokenPair - " + err.Error())
		return err, "", entity.SessionDTO{}
	}
	session := entity.NewSession(as.scope, refresh)
	err = repository.ExecTx(ctx, as.pool, func(tx pgx.Tx) error {
		txSessionRepo := as.sr.WithTx(tx)
		var txErr error
		session.ID, txErr = txSessionRepo.CreateSession(ctx, session, user.Id)
		return txErr
	})
	if err != nil {
		return err, "", entity.SessionDTO{}
	}
	return nil, access, session
}
func (as AuthService) GetPublic() *rsa.PublicKey {
	return as.pubkey
}

func (as AuthService) SignUP(ctx context.Context, user entity.User) (error, string, entity.SessionDTO) {
	fmt.Println("SignUP user + create Session")
	var err error
	var session entity.SessionDTO
	user.Password, err = utils.HashPassword(user.Password)
	err = repository.ExecTx(ctx, as.pool, func(tx pgx.Tx) error {
		txUserRepo := as.ur.WithTx(tx)
		urErr, userauth := txUserRepo.SaveUser(ctx, user)
		if urErr != nil {
			return urErr
		}
		txSessionRepo := as.sr.WithTx(tx)
		var srErr error
		pgid := userauth.ID.String()
		uuid, urErr := uuid.Parse(pgid)
		session.ID, srErr = txSessionRepo.CreateSession(ctx, session, uuid)
		return srErr
	})
	if err != nil {
		return err, "", entity.SessionDTO{}
	}
	value, ok := ctx.Value("method").(jwt.SigningMethod)
	if !ok || value == nil {
		value = jwt.SigningMethodRS256
	}
	err, access, refresh := as.GenerateTokenPair(user, value)
	session.Refresh = refresh
	return err, access, session

}
func (as AuthService) VerifyAccessToken(tokenStr string) (*token.UserClaims, error) {
	maker := token.NewJWTMaker(as.appToken, jwt.SigningMethodRS256, as.clientID)
	maker.SetKeys(as.privkey, as.pubkey)
	return maker.VerifyToken(tokenStr)
}
