use crate::verification::KdfParams;
use crate::verification::verify;
use chacha20poly1305::{self, AeadCore, KeyInit, aead::Aead};
use password_manager::cred::get_list;
use sqlx::SqlitePool;

pub async fn get_entry(
    p: &SqlitePool,
    name: String,
    kdfp: KdfParams,
    salt: &Vec<u8>,
    nonce: &Vec<u8>,
    b_pw: &[u8],
    sealed_data_key: &Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let res = get_list(p, name).await?;

    let dk = verify(kdfp, salt, nonce, b_pw, sealed_data_key).await?;

    let key = chacha20poly1305::Key::from_slice(&dk);

    let cipher = chacha20poly1305::ChaCha20Poly1305::new(key);

    let nonce =
        chacha20poly1305::ChaCha20Poly1305::generate_nonce(&mut chacha20poly1305::aead::OsRng);

    for item in res {
        let password = item.secret_cipher;
        let decrypted = cipher.decrypt(&nonce, password.as_ref());
        println!("{:#?}", decrypted.unwrap_or_default())
    }

    Ok(())
}
