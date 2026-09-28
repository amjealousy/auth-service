package sso

import (
	"auth-service/entity"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestAuthService_CheckUserAuth(t *testing.T) {
	as := NewAuthService()
	type args struct {
		user entity.User
	}
	tstUsr := entity.User{
		Username: "authUser",
		Password: "authPassword",
	}
	arg := args{user: tstUsr}
	var tests []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}
	tests = append(tests, struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{name: "happyCheck", args: arg, want: true, wantErr: false})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := as.CheckUserAuth(t.Context(), tt.args.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckUserAuth() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("CheckUserAuth() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthService_GenerateTokenPair(t *testing.T) {
	as := NewAuthService()
	type args struct {
		user entity.User
	}
	tstUsr := entity.User{
		Username: "authUser",
		Password: "authPassword",
	}
	arg := args{user: tstUsr}
	var tests []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}
	tests = append(tests, struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{name: "generatePair", args: arg, want: true, wantErr: false})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			err, _, _ := as.GenerateTokenPair(tt.args.user, jwt.SigningMethodHS256)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateTokenPair() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
