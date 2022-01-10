//! This module provides the [sync] function, responsible for synchronizing the Tagger database with the media
//! items on the filesystem.

use {
    crate::media::{FileData, ItemData},
    anyhow::{anyhow, Error, Result},
    chrono::{DateTime, Datelike, NaiveDateTime, Utc},
    futures::{future::BoxFuture, stream, FutureExt, StreamExt, TryStreamExt},
    lazy_static::lazy_static,
    regex::Regex,
    rexiv2::Metadata as ExifMetadata,
    sha2::{Digest, Sha256},
    sqlx::{Connection, SqliteConnection},
    std::{
        collections::HashMap,
        convert::{TryFrom, TryInto},
        fs::File,
        ops::DerefMut,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicU64, Ordering::Relaxed},
            Arc,
        },
        time::Instant,
    },
    tokio::{
        fs::{self, File as AsyncFile},
        io::{AsyncRead, AsyncReadExt},
        sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock},
        task,
    },
    tracing::{info, warn},
};

/// Calculate the SHA-256 hash of the specified `input` and return the result as a hex-encoded string.
async fn hash(input: &mut (dyn AsyncRead + Unpin + Send + 'static)) -> Result<String> {
    let mut hasher = Sha256::default();

    let mut buffer = vec![0; crate::BUFFER_SIZE];

    loop {
        let count = input.read(&mut buffer[..]).await?;
        if count == 0 {
            break;
        } else {
            hasher.update(&buffer[0..count]);
        }
    }

    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .concat())
}

/// Represents metadata for a given media item
#[derive(Debug)]
struct Metadata {
    /// Creation time for the item (e.g. Exif.Image.DateTimeOriginal)
    datetime: DateTime<Utc>,

    /// Offset in bytes from the start of the file where an MPEG-4 can be found, if any
    ///
    /// This will be zero for MP4 files, nonzero for "motion photo" files, and `None` for simple still images.
    video_offset: Option<i64>,
}

/// Summary statistics for a deduplication pass
///
/// See also [deduplicate].
struct DeduplicationSummary {
    /// Number of media items visited during deduplication
    item_count: u64,

    /// Number of items found which are considered duplicates
    duplicate_count: u64,
}

/// Extract relevant metadata from the EXIF content found in the file at `path`.
fn exif_metadata(path: &Path) -> Result<Metadata> {
    let length = i64::try_from(File::open(path)?.metadata()?.len()).unwrap();

    let metadata = ExifMetadata::new_from_path(path)?;

    let datetime = metadata
        .get_tag_string("Exif.Image.DateTimeOriginal")
        .or_else(|_| metadata.get_tag_string("Exif.Image.DateTime"))?;

    lazy_static! {
        static ref DATE_TIME_PATTERN: Regex =
            Regex::new(r"(\d{4}):(\d{2}):(\d{2}) (\d{2}):(\d{2}):(\d{2})").unwrap();
    };

    Ok(Metadata {
        datetime: DATE_TIME_PATTERN
            .captures(&datetime)
            .map(|c| {
                format!(
                    "{}-{}-{}T{}:{}:{}Z",
                    &c[1], &c[2], &c[3], &c[4], &c[5], &c[6]
                )
            })
            .ok_or_else(|| anyhow!("unrecognized DateTime format: {}", datetime))?
            .parse()?,

        // Some Android phones embed MPEG-4 video clips in the JPEG files they create, called "motion photos".
        // There are two versions of this format, each with its own EXIF tags.  We support both versions here:
        video_offset: if metadata
            .get_tag_string("Xmp.Container.Directory[2]/Container:Item/Item:Mime")
            .ok()
            .as_deref()
            == Some("video/mp4")
        {
            metadata
                .get_tag_string("Xmp.Container.Directory[2]/Container:Item/Item:Length")
                .ok()
        } else {
            metadata.get_tag_string("Xmp.GCamera.MicroVideoOffset").ok()
        }
        .and_then(|video_length| video_length.parse::<i64>().ok())
        .map(|video_length| length - video_length),
    })
}

/// Extract relevant metadata from the MPEG-4 content found in te file at `path`.
fn mp4_metadata(path: &Path) -> Result<Metadata> {
    const SECONDS_FROM_1904_TO_1970: u64 = 2_082_844_800;

    Ok(Metadata {
        datetime: DateTime::<Utc>::from_utc(
            NaiveDateTime::from_timestamp(
                mp4parse::read_mp4(&mut File::open(path)?)?
                    .creation
                    .ok_or_else(|| anyhow!("missing creation time"))?
                    .0
                    .saturating_sub(SECONDS_FROM_1904_TO_1970)
                    .try_into()
                    .unwrap(),
                0,
            ),
            Utc,
        ),
        video_offset: Some(0),
    })
}

/// Recursively search the specified `dir` directory for JPEG and MPEG-4 media items, identifying any that aren't
/// already in the database and attempting to extract metadata from them to be recorded in the database later.
///
/// The full path of each file found is expected to have a prefix of `root`, and this is stripped off prior to
/// looking the path up in the database.
///
/// Results are appended to `result` as (path, metadata) tuples, where the path is relative to `root`.
fn find_new<'a>(
    conn: &'a AsyncMutex<SqliteConnection>,
    root: &'a str,
    result: &'a mut Vec<(String, Option<Metadata>)>,
    dir: impl AsRef<Path> + 'a + Send,
) -> BoxFuture<'a, Result<()>> {
    let dir_buf = dir.as_ref().to_path_buf();

    async move {
        let mut dir = fs::read_dir(dir).await?;

        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();

            if path.is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    let lowercase = name.to_lowercase();

                    // Some android phones "hide" files which have been "deleted" by prepending a ".trashed-"
                    // prefix to them.  We assume here that users don't want to see those.
                    if !lowercase.starts_with(".trashed-")
                        && (lowercase.ends_with(".jpg")
                            || lowercase.ends_with(".jpeg")
                            || lowercase.ends_with(".mp4")
                            || lowercase.ends_with(".mov"))
                    {
                        let mut path = dir_buf.clone();
                        path.push(name);

                        let stripped = path
                            .strip_prefix(root)?
                            .to_str()
                            .ok_or_else(|| anyhow!("bad utf8"))?;

                        let found =
                            sqlx::query!("SELECT 1 as x FROM paths WHERE path = ?1", stripped)
                                .fetch_optional(conn.lock().await.deref_mut())
                                .await?
                                .is_some();

                        if !found {
                            let found_bad = sqlx::query!(
                                "SELECT 1 as x FROM bad_paths WHERE path = ?1",
                                stripped
                            )
                            .fetch_optional(conn.lock().await.deref_mut())
                            .await?
                            .is_some();

                            if !found_bad {
                                let metadata = task::block_in_place(|| {
                                    if lowercase.ends_with(".mp4") || lowercase.ends_with(".mov") {
                                        mp4_metadata(&path)
                                    } else {
                                        exif_metadata(&path)
                                    }
                                });

                                result.push((
                                    stripped.to_string(),
                                    match metadata {
                                        Ok(data) => Some(data),
                                        Err(e) => {
                                            warn!(
                                                "unable to get metadata for {}: {:?}",
                                                path.to_string_lossy(),
                                                e
                                            );

                                            None
                                        }
                                    },
                                ));
                            }
                        }
                    }
                }
            } else if path.is_dir() {
                find_new(conn, root, result, path).await?;
            }
        }

        Ok(())
    }
    .boxed()
}

/// Query the database for items for which we have not yet calculated a perceptual hash (e.g. files that have been
/// newly added), calculate their perceptual hashes, and look for duplicates among all files which share each
/// perceptual hash.
async fn deduplicate(
    conn: &AsyncMutex<SqliteConnection>,
    image_lock: &AsyncRwLock<()>,
    image_dir: &str,
    cache_dir: &str,
) -> Result<DeduplicationSummary> {
    // First, find the items for which we have not yet calculated a perceptual hash (p-hash), calculate the p-hash,
    // and group the items by their p-ashes.

    let unhashed = sqlx::query!(
        "SELECT i.hash, i.video_offset, min(p.path) as \"path!: String\" \
         FROM images i \
         INNER JOIN paths p \
         ON i.hash = p.hash \
         WHERE i.perceptual_hash IS NULL \
         GROUP BY i.hash"
    )
    .fetch(conn.lock().await.deref_mut())
    .try_collect::<Vec<_>>()
    .await?;

    let mut dirty = HashMap::<_, Vec<_>>::new();

    for row in unhashed {
        let perceptual_hash = crate::media::perceptual_hash(
            image_lock,
            image_dir,
            cache_dir,
            &row.hash,
            &row.path,
            row.video_offset,
        )
        .await
        .unwrap_or_else(|e| {
            warn!(
                "error calculating perceptual hash for {}: {:?}",
                row.hash, e
            );

            // If we can't calculate the p-hash now, assume we never will be able to (i.e. the file will never
            // change) and don't bother trying again.  Instead, record the p-hash as "(unknown)" and move on.
            "(unknown)".into()
        });

        dirty.entry(perceptual_hash).or_default().push(ItemData {
            hash: row.hash,
            file: FileData {
                path: row.path,
                video_offset: row.video_offset,
            },
        });
    }

    if !dirty.is_empty() {
        info!(
            "calculated {} unique perceptual hashes for {} items",
            dirty.len(),
            dirty.values().map(|v| v.len()).sum::<usize>()
        );
    }

    // Next, for each p-hash, collect all the new and old items with that p-hash and deduplicate them, recording
    // the results in the database.

    let mut item_count = 0;
    let duplicate_count = Arc::new(AtomicU64::new(0));

    for (perceptual_hash, dirty) in dirty {
        let potential_duplicates = sqlx::query!(
            "SELECT i.hash, i.video_offset, min(p.path) as \"path!: String\" \
             FROM images i \
             INNER JOIN paths p \
             ON i.hash = p.hash \
             WHERE i.perceptual_hash = ?1 \
             GROUP BY i.hash",
            perceptual_hash
        )
        .fetch(conn.lock().await.deref_mut())
        .map_ok(|row| ItemData {
            hash: row.hash,
            file: FileData {
                path: row.path,
                video_offset: row.video_offset,
            },
        })
        .chain(stream::iter(dirty).map(Ok))
        .try_collect::<Vec<_>>()
        .await?;

        item_count += potential_duplicates.len();

        let duplicates =
            crate::media::deduplicate(image_lock, image_dir, cache_dir, &potential_duplicates)
                .await
                .unwrap_or_else(|e| {
                    warn!(
                        "error deduplicating for perceptual hash {}: {:?}",
                        perceptual_hash, e
                    );

                    // If anything goes wrong deduplicating, assume there's no point in trying again (i.e. assume
                    // none of the files will change and the error was deterministic).  Instead, we assume none of
                    // the items is a duplicate of the others.
                    potential_duplicates.iter().map(|item| vec![item]).collect()
                });

        let duplicate_count = duplicate_count.clone();

        let duplicates = duplicates
            .iter()
            .map(|duplicates| {
                duplicates
                    .iter()
                    .map(|image| image.hash.clone())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // Note that we use a transaction here to ensure everything for this p-hash is updated atomically.  If any
        // part fails or is interrupted, we can just try again in the next pass without worrying about inconsistent
        // state.
        conn.lock()
            .await
            .transaction(move |conn| {
                async move {
                    for (group, duplicates) in duplicates.iter().enumerate() {
                        match &duplicates[..] {
                            [hash] => {
                                sqlx::query!(
                                    "UPDATE images \
                                     SET \
                                     perceptual_hash = ?1, \
                                     duplicate_group = 0, \
                                     duplicate_index = 0 \
                                     WHERE hash = ?2",
                                    perceptual_hash,
                                    hash,
                                )
                                .execute(&mut *conn)
                                .await?;
                            }

                            _ => {
                                duplicate_count
                                    .fetch_add(u64::try_from(duplicates.len()).unwrap(), Relaxed);

                                for (index, hash) in duplicates.iter().enumerate() {
                                    let group = i64::try_from(group + 1).unwrap();
                                    let index = i64::try_from(index).unwrap();

                                    sqlx::query!(
                                        "UPDATE images \
                                         SET \
                                         perceptual_hash = ?1, \
                                         duplicate_group = ?2, \
                                         duplicate_index = ?3 \
                                         WHERE hash = ?4",
                                        perceptual_hash,
                                        group,
                                        index,
                                        hash,
                                    )
                                    .execute(&mut *conn)
                                    .await?;
                                }
                            }
                        }
                    }

                    Ok::<_, Error>(())
                }
                .boxed()
            })
            .await?;
    }

    Ok(DeduplicationSummary {
        item_count: item_count.try_into().unwrap(),
        duplicate_count: duplicate_count.load(Relaxed),
    })
}

/// Synchronize the Tagger database with the filesystem.
///
/// This includes:
///
/// * Checking for new files not yet recorded in the database and adding them
///
/// * Checking for old files which have disappeared from the filesystem and removing them from the database
///
/// * Optionally generating preview artifacts from any new files
///
/// * Optionally comparing new files with each other and existing files to identify duplicates
pub async fn sync(
    conn: &AsyncMutex<SqliteConnection>,
    image_lock: &AsyncRwLock<()>,
    image_dir: &str,
    cache_dir: &str,
    preload: bool,
    deduplicate: bool,
) -> Result<()> {
    info!(
        "starting sync (preload: {}; deduplicate: {})",
        preload, deduplicate
    );

    let then = Instant::now();

    // First, identify any files recorded in the database but no longer present on the filesystem.

    let obsolete = {
        let mut lock = conn.lock().await;
        let mut rows = sqlx::query!("SELECT path FROM paths").fetch(lock.deref_mut());

        let mut obsolete = Vec::new();

        while let Some(row) = rows.try_next().await? {
            if ![image_dir, &row.path].iter().collect::<PathBuf>().is_file() {
                obsolete.push(row.path)
            }
        }

        obsolete
    };

    let obsolete_len = obsolete.len();

    // Next, identify any files on the filesystem but not yet recorded in the database.

    let new = {
        let mut new = Vec::new();

        find_new(conn, image_dir, &mut new, image_dir).await?;

        new
    };

    let new_len = new.len();

    // For each new file, atomically record it in the database.

    for (index, (path, data)) in new.into_iter().enumerate() {
        if let Some(data) = data {
            let hash =
                hash(&mut AsyncFile::open([image_dir, &path].iter().collect::<PathBuf>()).await?)
                    .await?;

            info!(
                "({} of {}) insert {} (hash {}; data {:?})",
                index + 1,
                new_len,
                path,
                hash,
                data
            );

            conn.lock()
            .await
            .transaction(|conn| {
                let path = path.clone();
                let hash = hash.clone();
                let year = data.datetime.year();
                let month = data.datetime.month();
                let datetime = data.datetime.to_string();
                let video_offset = data.video_offset;

                async move {
                    sqlx::query!("INSERT INTO paths (path, hash) VALUES (?1, ?2)", path, hash)
                        .execute(&mut *conn)
                        .await?;

                    sqlx::query!(
                        "INSERT OR IGNORE INTO images (hash, datetime, video_offset) VALUES (?1, ?2, ?3)",
                        hash,
                        datetime,
                        video_offset
                    )
                    .execute(&mut *conn)
                    .await?;

                    sqlx::query!(
                        "INSERT OR IGNORE INTO tags (hash, category, tag) VALUES (?1, 'year', ?2)",
                        hash,
                        year
                    )
                    .execute(&mut *conn)
                    .await?;

                    sqlx::query!(
                        "INSERT OR IGNORE INTO tags (hash, category, tag) VALUES (?1, 'month', ?2)",
                        hash,
                        month
                    )
                    .execute(&mut *conn)
                    .await
                }
                .boxed()
            })
                .await?;

            if preload {
                if let Err(e) = crate::media::preload_cache(
                    image_lock,
                    image_dir,
                    &FileData {
                        path,
                        video_offset: data.video_offset,
                    },
                    cache_dir,
                    &hash,
                )
                .await
                {
                    warn!("error preloading cache for {}: {:?}", hash, e);
                }
            }
        } else {
            // Files for which we could not extract metadata are excluded from further consideration, i.e. we
            // assume they will never change and thus will never have the metadata we need to sort and display them
            // in this application.

            info!("({} of {}) insert bad path {}", index + 1, new_len, path);

            sqlx::query!("INSERT INTO bad_paths (path) VALUES (?1)", path)
                .execute(conn.lock().await.deref_mut())
                .await?;
        }
    }

    // For each obsolete file found, atomically remove it from the database.

    for (index, path) in obsolete.into_iter().enumerate() {
        info!("({} of {}) delete {}", index + 1, obsolete_len, path);

        conn.lock()
            .await
            .transaction(|conn| {
                async move {
                    if let Some(row) = sqlx::query!("SELECT hash FROM paths WHERE path = ?1", path)
                        .fetch_optional(&mut *conn)
                        .await?
                    {
                        sqlx::query!("DELETE FROM paths WHERE path = ?1", path)
                            .execute(&mut *conn)
                            .await?;

                        if sqlx::query!("SELECT 1 as x FROM paths WHERE hash = ?1", row.hash)
                            .fetch_optional(&mut *conn)
                            .await?
                            .is_none()
                        {
                            sqlx::query!("DELETE FROM images WHERE hash = ?1", row.hash)
                                .execute(&mut *conn)
                                .await?;
                        }
                    } else {
                        sqlx::query!("DELETE FROM bad_paths WHERE path = ?1", path)
                            .execute(&mut *conn)
                            .await?;
                    }

                    Ok::<_, Error>(())
                }
                .boxed()
            })
            .await?;
    }

    info!(
        "sync took {:?} (added {}; deleted {})",
        then.elapsed(),
        new_len,
        obsolete_len
    );

    if deduplicate {
        info!("starting deduplication");

        let then = Instant::now();

        let summary = crate::sync::deduplicate(conn, image_lock, image_dir, cache_dir).await?;

        info!(
            "deduplication took {:?} (checked {} items; found {} duplicates)",
            then.elapsed(),
            summary.item_count,
            summary.duplicate_count
        );
    }

    Ok(())
}
