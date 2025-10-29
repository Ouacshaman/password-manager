use clap::{Parser, Subcommand};
use dotenvy::dotenv;

use password_manager::vault;

mod init;
use crate::init as mpw_init;

mod verification;
use crate::verification::verify;

mod add_entry;
use crate::add_entry::add_entry;

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init {
        password: Option<String>,
    },
    Login {
        login: Option<String>,
    },
    Add {
        mpw: String,
        name: String,
        url: Option<String>,
        username: String,
        password: String,
    },
    Get {
        name: String,
    },
    List,
}

#[tokio::main]

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    dotenv().ok();

    let conn_str =
        std::env::var("DATABASE_URL").expect("Database Url is not entered into dotenv file");

    println!("{}", conn_str);

    let pool = sqlx::SqlitePool::connect(&conn_str).await?;

    let vault = vault::get_vault(&pool).await?;

    match &cli.command {
        Commands::Init { password } => {
            if !vault.is_empty() {
                println!("Init has been called");
                std::process::exit(0);
            }
            let _ = mpw_init::init(password.clone(), &pool).await?;
        }
        Commands::Login { login } => {
            if vault.is_empty() {
                println!(
                    "The password manager hasn't been initiated, kindly utilize the Init command Ex: Init <password>"
                );

                std::process::exit(0);
            }
            let init_pw = login.clone().unwrap_or_default();
            let b_pw: &[u8] = init_pw.as_bytes();

            let kdfp: verification::KdfParams = serde_json::from_str(&vault[0].kdf_params)?;

            let _ = verify(
                kdfp,
                &vault[0].kdf_salt,
                &vault[0].nonce,
                b_pw,
                &vault[0].sealed_data_key,
            )
            .await?;
        }
        Commands::Add {
            mpw,
            name,
            url,
            username,
            password,
        } => {
            let init_pw = mpw.clone();
            let b_pw: &[u8] = init_pw.as_bytes();

            let kdfp: verification::KdfParams = serde_json::from_str(&vault[0].kdf_params)?;
            add_entry(
                &pool,
                name,
                url,
                username,
                password,
                kdfp,
                &vault[0].kdf_salt,
                &vault[0].nonce,
                b_pw,
                &vault[0].sealed_data_key,
            )
            .await?;
            println!("blank");
        }
        Commands::Get { name } => {
            println!("{:#?}", name);
        }
        Commands::List => {
            println!("blank");
        }
    }

    Ok(())
}
