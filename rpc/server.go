package rpc

import (
	"auth-service/sso"
	"fmt"
	"net"
	"strconv"

	"github.com/amjealousy/secure-grpc/gen/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	PORT = 5888
)

type RPCServer struct {
	auth.UnimplementedAuthServiceServer
	service *sso.AuthService
	port    int
}

func NewServer(auth *sso.AuthService) (server *RPCServer) {
	server = &RPCServer{port: PORT, service: auth}
	return
}
func (sv *RPCServer) Listen() {
	gs := grpc.NewServer()
	auth.RegisterAuthServiceServer(gs, sv)
	reflection.Register(gs)
	lis, err := net.Listen("tcp", ":"+strconv.Itoa(sv.port))
	if err != nil {
		panic(err)
	}
	fmt.Println("[*RPCServer] Listening on " + strconv.Itoa(sv.port))
	gs.Serve(lis)
}
