#![deny(warnings)]

use {
    anyhow::Result,
    futures::stream::{Stream, TryStreamExt},
    structopt::StructOpt,
    tagger_server::FileData,
};

#[derive(StructOpt, Debug)]
#[structopt(name = "tagger-admin", about = "Image tagging webapp admin tool")]
enum Command {
    /// Add a new user to the database
    AddUser {
        /// SQLite database to create or reuse
        state_file: String,

        /// Name of new user
        user: String,

        /// Password of new user
        password: String,
    },

    /// Generate thumbnail/transcode cache for all images and videos
    PreloadCache {
        /// SQLite database to create or reuse
        state_file: String,

        /// Directory containing source image and video files
        image_directory: String,

        /// Directory in which to cache lazily generated image and video variants
        cache_directory: String,

        /// Image hash to generate cache files for.  If not specified, cache files are generated for all images.
        hash: Option<String>,
    },
}

async fn preload_cache(
    image_directory: &str,
    cache_directory: &str,
    mut images: impl Stream<Item = Result<(String, Option<i64>, String), sqlx::Error>> + Unpin,
) -> Result<()> {
    while let Some((hash, video_offset, path)) = images.try_next().await? {
        let file_data = FileData { path, video_offset };

        if let Err(e) =
            tagger_server::preload_cache(image_directory, &file_data, cache_directory, &hash).await
        {
            tracing::warn!("error preloading cache for {}: {:?}", hash, e);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init_timed();

    match Command::from_args() {
        Command::AddUser {
            state_file,
            user,
            password,
        } => {
            let mut conn = tagger_server::open(&state_file).await?;

            let hash = tagger_server::hash_password(user.as_bytes(), password.as_bytes());

            sqlx::query!(
                "INSERT INTO users (name, password_hash) VALUES (?1, ?2)",
                user,
                hash,
            )
            .execute(&mut conn)
            .await?;
        }

        Command::PreloadCache {
            state_file,
            image_directory,
            cache_directory,
            hash,
        } => {
            let mut conn = tagger_server::open(&state_file).await?;

            if let Some(hash) = hash {
                preload_cache(
                    &image_directory,
                    &cache_directory,
                    sqlx::query!(
                        "SELECT i.hash, i.video_offset, p.path \
                         FROM images i \
                         INNER JOIN paths p \
                         ON i.hash = p.hash \
                         WHERE i.hash = ?1",
                        hash
                    )
                    .fetch(&mut conn)
                    .map_ok(|row| (row.hash, row.video_offset, row.path)),
                )
                .await
            } else {
                preload_cache(
                    &image_directory,
                    &cache_directory,
                    sqlx::query!(
                        "SELECT i.hash, i.video_offset, p.path \
                         FROM images i \
                         INNER JOIN paths p \
                         ON i.hash = p.hash"
                    )
                    .fetch(&mut conn)
                    .map_ok(|row| (row.hash, row.video_offset, row.path)),
                )
                .await
            }?;
        }
    }

    println!("success!");

    Ok(())
}
