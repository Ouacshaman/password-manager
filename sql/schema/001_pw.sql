-- +goose Up

CREATE TABLE IF NOT EXISTS vault_meta (
    id              INTEGER PRIMARY KEY CHECK (id = 1),          -- Always a single row
    kdf_salt        BLOB    NOT NULL,                            -- Random salt for Argon2id
    kdf_params      TEXT    NOT NULL,                            -- JSON or serialized Argon2 config
    nonce           BLOB    NOT NULL,                            -- Nonce used to encrypt the DK
    sealed_data_key BLOB    NOT NULL,                            -- DK encrypted with KEK (derived from master password)
    verifier        BLOB,                                        -- Optional encrypted verifier/header for quick password check
    created_at      DATETIME
);

CREATE TABLE IF NOT EXISTS entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,            -- Unique entry ID
    name            TEXT    NOT NULL,                             -- Label (e.g., "github", "gmail")
    username        TEXT,                                         -- Login/email (optionally encrypted later)
    url             TEXT,                                         -- Optional website/app
    nonce           BLOB    NOT NULL,                             -- Nonce used to encrypt this entry's secret
    secret_cipher   BLOB    NOT NULL,                             -- AEAD ciphertext of the stored password
    aad             TEXT,                                         -- Associated data string (e.g., name|username|url)
    created_at      DATETIME,
    updated_at      DATETIME
);

-- +goose Down
DROP TABLE IF EXISTS vault_meta;
DROP TABLE IF EXISTS enties;
