package repository

import (
	"auth-service/entity"
	"context"

	"github.com/jackc/pgx/v5"
)

type UserRepository interface {
	FindUserByName(ctx context.Context, username string) (error, *Userauth)
	SaveUser(ctx context.Context, user entity.User) (error, *Userauth)
	WithTx(tx pgx.Tx) UserRepository
}

func (uri UserRepositoryImpl) SaveUser(ctx context.Context, user entity.User) (error, *Userauth) {
	params := CreateUserParams{Userqn: user.Username, Hpassword: user.Password}
	userauth, err := uri.query.CreateUser(ctx, params)
	return err, &userauth
}

type UserRepositoryImpl struct {
	ctx       context.Context
	connector *DBTX
	query     *Queries
}

func (uri UserRepositoryImpl) WithTx(tx pgx.Tx) UserRepository {
	return &UserRepositoryImpl{
		ctx:       uri.ctx,
		connector: uri.connector,
		query:     uri.query.WithTx(tx),
	}
}

func NewUserRepository(connector *DBTX) *UserRepositoryImpl {

	q := New(*connector)
	return &UserRepositoryImpl{

		context.Background(),
		connector,
		q,
	}
}

func (uri UserRepositoryImpl) FindUserByName(ctx context.Context, username string) (error, *Userauth) {
	user, err := uri.query.GetUser(ctx, username)
	if err != nil {
		return err, nil
	}
	return nil, &user
}
