
-- name: StoreProfile :exec
INSERT INTO profile
    (id, nik, nik_bidx, name, name_bidx, phone, phone_bidx, email, email_bidx, dob)
VALUES
    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (id) 
    DO UPDATE SET updated_at = NOW();

-- name: FetchProfile :one
SELECT 
    nik, name, phone, email, dob 
FROM 
    profile 
WHERE 
    id = $1;

-- name: FindProfilesByName :many
SELECT 
    id, nik, name, phone, email, dob 
FROM 
    profile 
WHERE 
   name_bidx = ANY($1);

-- name: FindTextHeap :many
SELECT 
    content 
FROM 
    text_heap 
WHERE 
    type = $1
    AND content LIKE sqlc.arg(content) || '%'; -- https://docs.sqlc.dev/en/latest/howto/named_parameters.html#naming-parameters


-- name: StoreTextHeap :exec
INSERT INTO text_heap 
	(type, content)
VALUES
	($1, $2)
ON CONFLICT (type, content) 
    DO NOTHING;
