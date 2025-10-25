use argon2::{Argon2, Params};
use password_manager::vault;
use rand::{RngCore, rngs::OsRng};

use chacha20poly1305::{self, AeadCore, KeyInit, aead::Aead};

pub async fn init(
    pw: Option<String>,
    p: &sqlx::SqlitePool,
) -> Result<(), Box<dyn std::error::Error>> {
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
