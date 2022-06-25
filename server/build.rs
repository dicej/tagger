use {
    anyhow::{anyhow, Result},
    sqlx::{sqlite::SqliteConnectOptions, ConnectOptions},
    std::env,
    tokio::fs,
};

#[tokio::main]
async fn main() -> Result<()> {
    let mut path = env::current_dir()?;
    path.push("target");

    let _ = fs::create_dir(&path).await;

    path.push("schema.dat");

    let db = path.to_str().ok_or_else(|| anyhow!("invalid UTF-8"))?;

    let _ = fs::remove_file(db).await;

    let mut conn = format!("sqlite://{db}")
        .parse::<SqliteConnectOptions>()?
        .create_if_missing(true)
        .connect()
        .await?;

    for statement in schema::DDL_STATEMENTS {
        sqlx::query(statement).execute(&mut conn).await?;
    }

    println!("cargo:rustc-env=DATABASE_URL=sqlite://{db}");

    Ok(())
}
