package test

import (
	"auth-service/repository"
	"auth-service/utils"
	"context"
	"log"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	_ "github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testPool *pgxpool.Pool
var queries *repository.Queries

func TestMain(m *testing.M) {
	var err error
	testPool, err = pgxpool.New(context.Background(), "postgresql://postgres:postgres@localhost:5432/postgres?sslmode=disable")
	if err != nil {
		log.Fatal("cannot connect to test db:", err)
	}
	defer testPool.Close()
	queries = repository.New(testPool)
	os.Exit(m.Run())
}

func TestCreateUser(t *testing.T) {
	ctx := context.Background()
	password, err := utils.HashPassword(`authPassword`)
	require.NoError(
		t,
		err,
	)

	user, err := queries.CreateUser(ctx, repository.CreateUserParams{
		Userqn:    "authUser",
		Hpassword: password,
	})
	assert.NoError(t, err, "unexpected error creating user")

	assert.Equal(t, "testuser", user.Userqn, "username should be 'testuser'")

	assert.NotEmpty(t, user.ID, "user ID should not be empty")
}
