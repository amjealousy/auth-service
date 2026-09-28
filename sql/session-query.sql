-- name: GetSessionByID :one
SELECT * FROM SESSIONS WHERE id = $1;

-- name: ListSessions :many
SELECT * FROM SESSIONS;

-- name: CreateSession :one
INSERT INTO SESSIONS(user_id, refresh_token)
VALUES ($1, $2) RETURNING id;

-- name: DeleteSession :exec
DELETE FROM SESSIONS WHERE id = $1;