use password_manager::cred::Entries;
use password_manager::cred::get_list;
use sqlx::SqlitePool;

pub async fn get_entry(
    p: &SqlitePool,
    name: String,
) -> Result<Vec<Entries>, Box<dyn std::error::Error>> {
    let res = get_list(p, name).await?;
    Ok(res)
}
