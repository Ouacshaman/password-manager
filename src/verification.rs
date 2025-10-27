use serde::{Deserialize, Serialize};
use argon2::{Argon2, Params};
use chacha20poly1305::{self, KeyInit, aead::Aead};
use std::str::FromStr;


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

pub async fn verify(
    kdfp: KdfParams,
    salt: &Vec<u8>,
    nonce: &Vec<u8>,
    b_pw: &[u8],
    sealed_data_key: &Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
    
    let mut output_key_material = [0u8; 32];

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
            .hash_password_into(b_pw, &salt, &mut output_key_material);

            let cipher = chacha20poly1305::ChaCha20Poly1305::new((&output_key_material).into());

            let nonce = chacha20poly1305::Nonce::from_slice(&nonce);

            let _ = cipher
                .decrypt(nonce, sealed_data_key.as_ref())
                .expect("Incorrect Password");

    Ok(())

} 
