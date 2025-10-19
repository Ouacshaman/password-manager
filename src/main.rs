// Argon2 package is used to generate a master key

use argon2::Argon2;

use rand::{RngCore, rngs::OsRng};

use chacha20poly1305::{self, AeadCore, KeyInit, aead::Aead};

use clap::Parser;
use dotenvy::dotenv;
use sqlx;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long, value_name = "initialize master password")]
    init: Option<String>,

    #[arg(short, long, value_name = "master password entry")]
    master_pw: Option<String>,
}

#[tokio::main]

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    dotenv().ok();

    let conn_str =
        std::env::var("DATABASE_URL").expect("Database Url is not entered into dotenv file");

    println!("{}", conn_str);

    let pool = sqlx::SqlitePool::connect(&conn_str).await?;

    let vault = get_vault(&pool).await?;

    if vault.is_empty() {
        println!("Auth/Vault not setup. Use '--init' to setup the master password");
        std::process::exit(0);
    }

    let init_pw = cli.init.unwrap_or_else(|| "No String Found".to_string());
    let b_pw: &[u8] = init_pw.as_bytes();
    let mut output_key_material = [0u8; 32];

    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let mut data_key = [0u8; 32];
    OsRng.fill_bytes(&mut data_key);

    let _ = Argon2::default()
        .hash_password_into(b_pw, &salt, &mut output_key_material)
        .expect("failed hash");

    let cipher = chacha20poly1305::ChaCha20Poly1305::new((&output_key_material).into());

    let nonce =
        chacha20poly1305::ChaCha20Poly1305::generate_nonce(&mut chacha20poly1305::aead::OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, data_key.as_ref())
        .expect("unable to generate sealed key");

    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .expect("unable to decrypt");

    assert_eq!(&plaintext, &data_key);

    Ok(())
}

#[derive(sqlx::FromRow, Debug)]
pub struct Vault {
    pub id: i32,
    pub kdf_salt: Vec<u8>,
    pub kdf_params: String,
    pub nonce: Vec<u8>,
    pub sealed_data_key: Vec<u8>,
    pub verifier: Option<Vec<u8>>,
    pub created_at: Option<String>,
}

async fn get_vault(p: &sqlx::SqlitePool) -> Result<Vec<Vault>, Box<dyn std::error::Error>> {
    let vault = sqlx::query_as::<_, Vault>(
        r#"
        SELECT
            id,
            kdf_salt,
            kdf_params,
            nonce,
            sealed_data_key,
            verifier,
            created_at
        FROM vault_meta
        WHERE id = 1
        "#,
    )
    .fetch_all(p)
    .await?;

    Ok(vault)
}
