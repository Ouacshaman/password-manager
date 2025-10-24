use std::str::FromStr;

use argon2::{Argon2, Params};

use rand::{RngCore, rngs::OsRng};

use chacha20poly1305::{self, AeadCore, KeyInit, aead::Aead};

use clap::{Parser, Subcommand};
use dotenvy::dotenv;

use serde::{Deserialize, Serialize};

use password_manager::vault;

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init { password: Option<String> },
    Login { login: Option<String> },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KdfParams {
    #[serde(rename = "Algorithm")]
    pub algorithm: String,

    #[serde(rename = "Version")]
    pub version: u32,

    #[serde(rename = "Memory_size")]
    pub memory_size: u32,

    #[serde(rename = "Iteration")]
    pub iteration: u32,

    #[serde(rename = "Parallelism")]
    pub parallelism: u32,

    #[serde(rename = "Output_len")]
    pub output_len: Option<usize>,
}

#[tokio::main]

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    dotenv().ok();

    let conn_str =
        std::env::var("DATABASE_URL").expect("Database Url is not entered into dotenv file");

    println!("{}", conn_str);

    let pool = sqlx::SqlitePool::connect(&conn_str).await?;

    let vault = vault::get_vault(&pool).await?;

    match &cli.command {
        Commands::Init { password } => {
            if !vault.is_empty() {
                println!("Init has been called");
                std::process::exit(0);
            }
            let _ = init(password.clone(), &pool).await?;
        }
        Commands::Login { login } => {
            if vault.is_empty() {
                println!(
                    "The password manager hasn't been initiated, kindly utilize the Init command Ex: Init <password>"
                );

                std::process::exit(0);
            }
            let init_pw = login.clone().unwrap_or_default();
            let b_pw: &[u8] = init_pw.as_bytes();
            let mut output_key_material = [0u8; 32];

            let kdfp: KdfParams = serde_json::from_str(&vault[0].kdf_params)?;

            let _ = Argon2::new(
                argon2::Algorithm::from_str(&kdfp.algorithm).unwrap_or_default(),
                argon2::Version::try_from(kdfp.version).unwrap_or_default(),
                Params::new(
                    kdfp.memory_size,
                    kdfp.iteration,
                    kdfp.parallelism,
                    kdfp.output_len,
                )
                .unwrap_or_default(),
            )
            .hash_password_into(b_pw, &vault[0].kdf_salt, &mut output_key_material);

            let cipher = chacha20poly1305::ChaCha20Poly1305::new((&output_key_material).into());

            let nonce = chacha20poly1305::Nonce::from_slice(&vault[0].nonce);

            let _ = cipher
                .decrypt(nonce, vault[0].sealed_data_key.as_ref())
                .expect("Incorrect Password");
        }
    }

    Ok(())
}

async fn init(pw: Option<String>, p: &sqlx::SqlitePool) -> Result<(), Box<dyn std::error::Error>> {
    let init_pw = pw.unwrap_or_default();
    let b_pw: &[u8] = init_pw.as_bytes();
    let mut output_key_material = [0u8; 32];

    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let mut data_key = [0u8; 32];
    OsRng.fill_bytes(&mut data_key);

    let _ = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        Params::new(262_144, 3, 2, None).unwrap_or_default(),
    )
    .hash_password_into(b_pw, &salt, &mut output_key_material);

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

    let params = r#"{
        "Algorithm": "Argon2id",
        "Version": 19,
        "Memory_size": 262144,
        "Iteration": 3,
        "Parallelism": 2,
        "Output_len": 32
    }"#;

    vault::init_vault(
        p,
        salt.to_vec(),
        params.to_string(),
        nonce.to_vec(),
        ciphertext,
    )
    .await?;

    Ok(())
}
