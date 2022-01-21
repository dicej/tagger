#![deny(warnings)]

use {
    anyhow::Result,
    futures::stream::TryStreamExt,
    structopt::StructOpt,
    tagger_server::{FileData, Item, ItemData},
    tagger_shared::tag_expression::TagExpression,
    tokio::sync::RwLock as AsyncRwLock,
};

#[derive(StructOpt, Debug)]
#[structopt(name = "tagger-admin", about = "Image tagging webapp admin tool")]
enum Command {
    /// Add a new user to the database.
    AddUser {
        /// SQLite database to create or reuse
        state_file: String,

        /// Name of new user
        user: String,

        /// Password of new user
        password: String,

        /// Optional filter applied to user's queries
        #[structopt(long)]
        filter: Option<TagExpression>,

        /// If set, allow user to add and remove tags to/from images
        #[structopt(long)]
        may_patch: bool,
    },

    /// Generate thumbnail/transcode cache for images and videos.
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

    /// Calculate perceptual hashes for the specified items and identify any duplicates among them.
    ///
    /// Note that this command does not update the database -- it only prints the results to standard output.
    Compare {
        /// SQLite database to create or reuse
        state_file: String,

        /// Directory containing source image and video files
        image_directory: String,

        /// Directory in which to cache lazily generated image and video variants
        cache_directory: String,

        /// Image hashes to analyze
        hashes: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init_timed();

    match Command::from_args() {
        Command::AddUser {
            state_file,
            user,
            password,
            filter,
            may_patch,
        } => {
            let mut conn = tagger_server::open(&state_file).await?;

            let hash = tagger_server::hash_password(user.as_bytes(), password.as_bytes());

            let filter = filter.map(|e| e.to_string());

            sqlx::query!(
                "INSERT INTO users (name, password_hash, filter, may_patch) VALUES (?1, ?2, ?3, ?4)",
                user,
                hash,
                filter,
                may_patch
            )
            .execute(&mut conn)
            .await?;

            println!("success!");
        }

        Command::PreloadCache {
            state_file,
            image_directory,
            cache_directory,
            hash,
        } => {
            let mut conn = tagger_server::open(&state_file).await?;

            let image_lock = AsyncRwLock::new(());

            if let Some(hash) = hash {
                tagger_server::preload_cache_all(
                    &image_lock,
                    &image_directory,
                    &cache_directory,
                    sqlx::query!(
                        "SELECT i.hash, i.video_offset, min(p.path) as \"path!: String\" \
                         FROM images i \
                         INNER JOIN paths p \
                         ON i.hash = p.hash \
                         WHERE i.hash = ?1 \
                         GROUP BY i.hash",
                        hash
                    )
                    .fetch(&mut conn)
                    .map_ok(|row| ItemData {
                        hash: row.hash,
                        file: FileData {
                            video_offset: row.video_offset,
                            path: row.path,
                        },
                    }),
                )
                .await
            } else {
                tagger_server::preload_cache_all(
                    &image_lock,
                    &image_directory,
                    &cache_directory,
                    sqlx::query!(
                        "SELECT i.hash, i.video_offset, min(p.path) as \"path!: String\" \
                         FROM images i \
                         INNER JOIN paths p \
                         ON i.hash = p.hash \
                         GROUP BY i.hash"
                    )
                    .fetch(&mut conn)
                    .map_ok(|row| ItemData {
                        hash: row.hash,
                        file: FileData {
                            video_offset: row.video_offset,
                            path: row.path,
                        },
                    }),
                )
                .await
            }?;

            println!("success!");
        }

        Command::Compare {
            state_file,
            image_directory,
            cache_directory,
            hashes,
        } => {
            let mut conn = tagger_server::open(&state_file).await?;

            let image_lock = AsyncRwLock::new(());

            let mut items = Vec::new();

            for hash in hashes {
                if let Some(row) = sqlx::query!(
                    "SELECT i.video_offset, min(p.path) as \"path!: String\" \
                     FROM images i \
                     INNER JOIN paths p \
                     ON i.hash = p.hash \
                     WHERE i.hash = ?1 \
                     GROUP BY i.hash",
                    hash
                )
                .fetch_optional(&mut conn)
                .await?
                {
                    let ordinal = tagger_server::perceptual_ordinal(
                        &image_lock,
                        &image_directory,
                        &cache_directory,
                        &hash,
                        &row.path,
                        row.video_offset,
                    )
                    .await?;

                    println!("perceptual ordinal for {hash} is {ordinal}");

                    items.push(Item {
                        ordinal,
                        duplicate_group: None,
                        duplicate_index: None,
                        data: ItemData {
                            hash,
                            file: FileData {
                                video_offset: row.video_offset,
                                path: row.path,
                            },
                        },
                    });
                } else {
                    println!("no item found for {hash}");
                }
            }

            items.sort_by(|a, b| a.ordinal.cmp(&b.ordinal));

            let mut previous = None::<&Item>;

            for item in &items {
                if let Some(previous) = previous {
                    println!(
                        "is {} similar to {}? {}",
                        previous.ordinal,
                        item.ordinal,
                        previous.ordinal.is_similar_to(&item.ordinal)
                    );
                }

                previous = Some(item);
            }

            let groups =
                tagger_server::deduplicate(&image_lock, &image_directory, &cache_directory, &items)
                    .await?;

            println!("{groups:#?}");
        }
    }

    Ok(())
}
