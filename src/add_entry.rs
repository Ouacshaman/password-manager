use crate::verification::KdfParams;
use crate::verification::verify;

use chacha20poly1305::{self, AeadCore, KeyInit, aead::Aead};

pub async fn add_entry(
    p: &sqlx::SqlitePool,
    name: &String,
    url: &Option<String>,
    username: &String,
    password: &String,
    kdfp: KdfParams,
    salt: &Vec<u8>,
    nonce: &Vec<u8>,
    b_pw: &[u8],
    sealed_data_key: &Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let dk = verify(kdfp, salt, nonce, b_pw, sealed_data_key).await?;

    let cipher = chacha20poly1305::ChaCha20Poly1305::new(&dk.into());

    let nonce =
        chacha20poly1305::ChaCha20Poly1305::generate_nonce(&mut chacha20poly1305::aead::OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, password.as_ref())
        .expect("Unable to Encrypt");

    return Ok(());
}
