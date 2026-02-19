# Password Manager (Rust)

A lightweight, secure, **local-first** password manager written in Rust — no cloud, no telemetry, and no external services. Everything is encrypted locally using proven cryptography and stored in a simple SQLite database.

---


This project uses **Goose** for database migrations.  
You must create the folders:

```
mkdir -p sql/schema
```

Create your first migration file:

```
touch sql/schema/0001_init.sql
```

### Example `0001_init.sql`:

```sql
-- Vault metadata (stores sealed DK)

CREATE TABLE IF NOT EXISTS vault_meta (
    id               INTEGER PRIMARY KEY,
    kdf_salt         BLOB NOT NULL,
    kdf_params       TEXT NOT NULL,
    nonce            BLOB NOT NULL,
    sealed_data_key  BLOB NOT NULL,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Entries table (per-password storage)

CREATE TABLE IF NOT EXISTS entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    username        TEXT,
    url             TEXT,
    nonce           BLOB NOT NULL,
    secret_cipher   BLOB NOT NULL,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

Run migrations using Goose:

```bash
goose -dir ./sql/schema sqlite3 ./pman.db up
```

---


## CLI Usage

### Initialize Vault
```bash
pman init --password <MASTER_PASSWORD>
```

### Check Master Password
```bash
pman check --password <MASTER_PASSWORD>
```

### Add Credential Entry
```bash
pman add   --mpw <MASTER_PASSWORD>   --name github   --url https://github.com   --username johndoe   --password hunter2
```

### Retrieve Password
```bash
pman get --mpw <MASTER_PASSWORD> --name github
```

### List Entries
```bash
pman list --mpw <MASTER_PASSWORD>
```

---

### Dependencies

```bash
cargo add sqlx --features sqlite,runtime-tokio,macros,chrono
cargo add argon2 chacha20poly1305 rand clap dotenvy serde serde_json zeroize secrecy
go install github.com/pressly/goose/v3/cmd/goose@latest
```

### Create `.env`

```bash
echo "DATABASE_URL=sqlite://./pman.db" > .env
```

### Run Goose Migration

```bash
goose -dir ./sql/schema sqlite3 ./pman.db up
```

### Run App

```bash
cargo run -- <COMMAND> [OPTIONS]
```

```bash
target/release/pman <COMMAND>
```

---

## License

MIT License © 2025  
Created by Shi Hong
