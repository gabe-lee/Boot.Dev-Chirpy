-- name: NewRefresh :exec
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at)
VALUES ($1, NOW(), NOW(), $2, $3);

-- name: CheckRevoke :one
SELECT revoked_at FROM refresh_tokens WHERE token=$1;

-- name: UpdateRefresh :one
UPDATE refresh_tokens SET updated_at=NOW(), expires_at=$2 WHERE token=$1 RETURNING user_id;

-- name: RevokeRefresh :exec
UPDATE refresh_tokens SET updated_at=NOW(), revoked_at=NOW() WHERE token=$1;