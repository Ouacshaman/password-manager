use crate::verification::KdfParams;
use crate::verification::verify;
use chacha20poly1305::Nonce;
use chacha20poly1305::{self, KeyInit, aead::Aead};
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

    for item in res {
        let password = item.secret_cipher;
        let nonce = Nonce::from_slice(&item.nonce);
        let decrypted = cipher.decrypt(&nonce, password.as_ref());
        println!(
            "Name: {} Username: {} Url: {}",
            item.name, item.username, item.url
        );

        let stringed_pw: String =
            String::from_utf8(decrypted.unwrap_or_default()).unwrap_or_default();
        println!("Decrypted: {}", stringed_pw);
    }

    Ok(())
}
