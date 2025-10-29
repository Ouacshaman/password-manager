mod verification;
use crate::verification::cred;
use argon2::{Argon2, Params};
use password_manager::vault;
use rand::{RngCore, rngs::OsRng};

use chacha20poly1305::{self, AeadCore, KeyInit, aead::Aead};


pub async fn add_entry(
    p: &sqlx::SqlitePool,
    name: String,
    url: String,
    username: String,
    password: String,
    kdfp: KdfParams,
    salt: &Vec<u8>,
    nonce: &Vec<u8>,
    b_pw: &[u8],
    sealed_data_key: &Vec<u8>,
    ) -> Result< (), Box<dyn std::error::Error>> {

    return Ok(())
}
