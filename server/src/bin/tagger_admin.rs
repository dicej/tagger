#![deny(warnings)]

use anyhow::Result;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "tagger-admin", about = "Image tagging webapp admin tool")]
enum Command {
    /// Add a new user to the database
    AddUser {
        /// SQLite database to create or reuse
        file: String,

        /// Name of new user
        user: String,

        /// Password of new user
        password: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init_timed();

    match Command::from_args() {
        Command::AddUser {
            file,
            user,
            password,
        } => {
            let mut conn = tagger_server::open(&file).await?;

            let hash = tagger_server::hash_password(user.as_bytes(), password.as_bytes());

            sqlx::query!(
                "INSERT INTO users (name, password_hash) VALUES (?1, ?2)",
                user,
                hash,
            )
            .execute(&mut conn)
            .await?;
        }
    }

    println!("success!");

    Ok(())
}
