-- name: PostChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (gen_random_uuid(), NOW(), NOW(), $1, $2)
RETURNING *;

-- name: GetAllChirps :many
SELECT * FROM chirps ORDER BY created_at;

-- name: GetChirp :one
SELECT * FROM chirps WHERE id=$1;

-- name: GetChirpAuthor :one
SELECT user_id FROM chirps WHERE id=$1;

-- name: DeleteChirp :exec
DELETE FROM chirps WHERE id=$1;