-- name: CreateUser :one
INSERT INTO userauth(userqn, hpassword)
VALUES ($1, $2)
RETURNING *;

-- name: GetUser :one
SELECT id,userqn,hpassword FROM userauth WHERE userqn = $1;