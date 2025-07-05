-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (gen_random_uuid(), NOW(), NOW(), $1, $2)
RETURNING id, created_at, updated_at, email;

-- name: DeleteAllUsers :exec
TRUNCATE TABLE users CASCADE;

-- name: FindUserByEmail :one
SELECT id, created_at, updated_at, email, hashed_password FROM users WHERE email=$1;

-- name: UpdateLogin :one
UPDATE users SET email=$2, hashed_password=$3, updated_at=NOW() WHERE id=$1 RETURNING id, created_at, updated_at, email;