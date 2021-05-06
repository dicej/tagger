use anyhow::Result;
use sqlx::SqliteConnection;

#[tokio::main]
async fn main() -> Result<()> {
    let db_name = "target/schema.dat";

    let mut conn = SqliteConnection::connect(&format!("sqlite://{}", db_name)).await?;

    for statement in schema::DDL_STATEMENTS {
        sqlx::query(statement).execute(&mut conn).await?;
    }

    println!(&format!("cargo:rustc-env=DATABASE_URL={}", DB_NAME));
}
