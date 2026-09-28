package rpc

import (
	"auth-service/entity"
	"context"
	"fmt"

	"github.com/amjealousy/secure-grpc/gen/auth"
	"github.com/google/uuid"
)

type CredentialError struct {
	err     error
	message string
}

const CredentialErrorMessage = "credential error"
const WrongUserErrorMessage = "user invalid"

func (e *CredentialError) Error() string {
	if e.err != nil {
		return e.message + ": " + e.err.Error()
	}
	return e.message
}
func (e *CredentialError) Unwrap() error {
	return e.err
}

func (sv *RPCServer) CheckUserAuth(ctx context.Context, req *auth.CheckUserRequest) (*auth.CheckUserReply, error) {
	user := entity.User{Username: req.Fqdn}
	status, _, err := sv.service.CheckUserAuth(ctx, user)
	if err != nil {
		return &auth.CheckUserReply{Status: status}, err
	}

	return &auth.CheckUserReply{Status: status}, nil
}
func (sv *RPCServer) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginReply, error) {
	if req.Fqdn == "" || req.Password == "" {
		return &auth.LoginReply{}, fmt.Errorf("%v", &CredentialError{message: CredentialErrorMessage})
	}
	user := entity.User{Username: req.Fqdn, Password: req.Password, Id: uuid.New()}
	status, userId, err := sv.service.CheckUserAuth(ctx, user)
	if err != nil || status == false {
		return &auth.LoginReply{}, fmt.Errorf("%v", &CredentialError{err: err, message: CredentialErrorMessage})
	}
	user.Id, err = uuid.Parse(userId)
	if err != nil {
		return &auth.LoginReply{}, fmt.Errorf("%v", &CredentialError{err: err, message: WrongUserErrorMessage})
	}
	err, access, session := sv.service.Login(ctx, user)
	if err != nil {
		return nil, err
	}
	return &auth.LoginReply{
		AccessToken:  access,
		RefreshToken: session.Refresh,
		Scope:        session.GetScope(),
		SessionId:    session.ID.String(),
	}, nil
}
