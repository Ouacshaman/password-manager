use sqlx::{self, types::chrono};
use std;

#[derive(sqlx::FromRow, Debug)]
pub struct Vault {
    pub id: i32,
    pub kdf_salt: Vec<u8>,
    pub kdf_params: String,
    pub nonce: Vec<u8>,
    pub sealed_data_key: Vec<u8>,
    pub created_at: Option<String>,
}

pub async fn get_vault(p: &sqlx::SqlitePool) -> Result<Vec<Vault>, Box<dyn std::error::Error>> {
    let vault = sqlx::query_as::<_, Vault>(
        r#"
        SELECT
            id,
            kdf_salt,
            kdf_params,
            nonce,
            sealed_data_key,
            created_at
        FROM vault_meta
        WHERE id = 1
        "#,
    )
    .fetch_all(p)
    .await?;

    Ok(vault)
}

pub async fn init_vault(
    p: &sqlx::SqlitePool,
    salt: Vec<u8>,
    params: String,
    nonce: Vec<u8>,
    sealed_dk: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = chrono::Local::now().naive_local();
    let res = sqlx::query(
        r#"
INSERT INTO vault_meta(id, kdf_salt, kdf_params, nonce, sealed_data_key, created_at)
VALUES(1, ?, ?, ?, ?, ?);
        "#,
    )
    .bind(salt)
    .bind(params)
    .bind(nonce)
    .bind(sealed_dk)
    .bind(now)
    .execute(p)
    .await?;

    println!("{}", res.rows_affected());

    Ok(())
}
