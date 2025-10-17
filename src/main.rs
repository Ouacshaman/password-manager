// Argon2 package is used to generate a master key

use argon2::Argon2;
use clap::{Parser, Subcommand};
use sqlx;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "user_name")]
    name: Option<String>,

    #[arg(short, long, value_name = "master_password")]
    master_pw: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    List {
        #[arg(long)]
        list: Option<String>,
    },
}

#[tokio::main]

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let conn_str =
        std::env::var("DATABASE_URL").expect("Database Url is not entered into dotenv file");

    let _pool = sqlx::SqlitePool::connect(&conn_str).await?;

    let arg_entry_pw = cli
        .master_pw
        .unwrap_or_else(|| "No String Found".to_string());
    let b_pw: &[u8] = arg_entry_pw.as_bytes();
    let salt = b"testing password encryption";

    let mut output_key_material = [0u8; 32];
    let _ = Argon2::default().hash_password_into(b_pw, salt, &mut output_key_material);

    println!("{:?}", &output_key_material.to_ascii_lowercase());

    Ok(())
}
