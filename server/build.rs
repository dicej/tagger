use anyhow::{anyhow, Result};
use sqlx::{sqlite::SqliteConnectOptions, ConnectOptions};
use std::env;
use tokio::fs;

#[tokio::main]
async fn main() -> Result<()> {
    lalrpop::process_root().unwrap();

    let mut db = env::current_dir()?;
    db.push("target");
    db.push("schema.dat");

    let db = db.to_str().ok_or_else(|| anyhow!("invalid UTF-8"))?;

    let _ = fs::remove_file(db).await;

    let mut conn = format!("sqlite://{}", db)
        .parse::<SqliteConnectOptions>()?
        .create_if_missing(true)
        .connect()
        .await?;

    for statement in schema::DDL_STATEMENTS {
        sqlx::query(statement).execute(&mut conn).await?;
    }

    println!("cargo:rustc-env=DATABASE_URL=sqlite://{}", db);

    Ok(())
}
