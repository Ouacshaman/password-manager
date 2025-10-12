-- +goose Up
CREATE TABLE passwords(
	id UUID PRIMARY KEY,
	created_at TIMESTAMP NOT NULL,
	updated_at TIMESTAMP NOT NULL,
	name TEXT UNIQUE NOT NULL,
	password TEXT NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS passwords
