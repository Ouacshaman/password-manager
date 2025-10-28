use sqlx::{self, types::chrono};
use std;

#[derive(sqlx::FromRow, Debug)]
pub struct Entries{
    pub id: i32,
    pub name: String,
    pub username: String,
    pub url String,
    pub nonce: Vec<u8>,
    pub secret_cipher: Vec<u8>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

pub async fn get_list(p: &sqlx::SqlitePool, name: String) -> Result<Vec<Creds>, Box<dyn std::error::Error>>{
    let creds = sqlx::query_as::<_, Entires>(
        r#"
        SELECT
            id,
            name,
            username,
            url,
            nonce,
            secret_cipher,
            created_at,
            updated_at,
        FROM entries
        Where name = ?
        "#,
        )
        .bind(name)
        .fetch_all(p)
        .await?;

    Ok(creds)
}
