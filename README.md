# 🗝️ Password Manager (Rust)

A lightweight, secure, **local-first** password manager written in Rust — no cloud, no telemetry, and no external services. Everything is encrypted locally using proven cryptography and stored in a simple SQLite database.

---

## ✨ Features

- 🔐 **Master password–based encryption**
  - Argon2id for password KDF  
  - Master password → Key Encryption Key (KEK)  
  - KEK encrypts a random Data Key (DK)
- 🔒 **Per-entry authenticated encryption**  
  - ChaCha20-Poly1305 with a unique nonce per entry  
  - AEAD guarantees integrity + tamper detection
- 🗃️ **SQLite backend**
  - No server required  
  - Portable `.db` file  
- 🧰 **Typed queries with SQLx**
- ⚙️ **Clap-powered CLI**  
  - Clear and explicit `--flags`  
  - Easy to extend with subcommands
- 🧩 **Goose migrations** for clean schema versioning
- 🐧 Works on macOS / Linux / Windows

---

## 🧱 Database Schema (via Goose)

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

## 🧩 Crypto Architecture

```
       Master Password
              |
           Argon2id
              ↓
          KEK (32b)
              |
   -----------------------
   |                     |
 Seal DK            Unseal DK
   |                     |
sealed_data_key      data_key (DK)
                      |
          Encrypt / Decrypt Entries
```

---

## 🖥️ CLI Usage

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

## 🧱 Build & Development

### 1. Install Rust & Dependencies

```bash
cargo add sqlx --features sqlite,runtime-tokio,macros,chrono
cargo add argon2 chacha20poly1305 rand clap dotenvy serde serde_json zeroize secrecy
go install github.com/pressly/goose/v3/cmd/goose@latest
```

### 2. Create `.env`

```bash
echo "DATABASE_URL=sqlite://./pman.db" > .env
```

### 3. Run Goose Migration

```bash
goose -dir ./sql/schema sqlite3 ./pman.db up
```

### 4. Run App

```bash
cargo run -- <COMMAND> [OPTIONS]
```

```bash
target/release/pman <COMMAND>
```

---

## 🔒 Security Notes

- The DK is *never written* to disk.  
- The sealed DK uses AEAD (ChaCha20-Poly1305) via the KEK.  
- Each entry uses a **unique 12-byte nonce**.  
- AEAD prevents tampering: wrong master password → decryption fails.  
- Avoid logging secrets; zeroize sensitive buffers where possible.  
- Future improvements:
  - OS keychain integration  
  - Background agent to keep DK unlocked temporarily  
  - Auto-lock timers  
  - Entry editing and search  

---

## 📄 License

MIT License © 2025  
Created by Shi Hong
