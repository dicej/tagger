//! This module provides the [sync] function, responsible for synchronizing the Tagger database with the media
//! items on the filesystem.

use {
    crate::{
        lock_map::LockMap,
        media::{
            self, FileData, Item, ItemData, PerceptualHash, JPEG_EXTENSIONS, MPEG4_EXTENSIONS,
            PERCEPTUAL_HASH_LENGTH,
        },
        BUFFER_SIZE,
    },
    anyhow::{anyhow, Error, Result},
    chrono::{DateTime, Datelike, Duration, Utc},
    futures::{
        future::{self, BoxFuture},
        FutureExt, TryStreamExt,
    },
    lazy_static::lazy_static,
    regex::Regex,
    rexiv2::Metadata as ExifMetadata,
    serde::{Deserialize as _, Deserializer},
    serde_derive::Deserialize,
    sha2::{Digest, Sha256},
    sqlx::{Connection, SqliteConnection},
    std::{
        collections::{BTreeMap, HashMap, HashSet, VecDeque},
        convert::{TryFrom, TryInto},
        fmt::Display,
        fs::File,
        io::BufReader,
        ops::{Deref, DerefMut},
        path::{Path, PathBuf},
        str::FromStr,
        sync::Arc,
        time::Instant,
    },
    tokio::{
        fs::{self, File as AsyncFile},
        io::{AsyncRead, AsyncReadExt},
        sync::Mutex as AsyncMutex,
        task,
    },
    tracing::{info, warn},
};

lazy_static! {
    /// Timestamp to use when either none can be found in the file's metadata or when the metadata one is clearly
    /// wrong (e.g. far in the future)
    static ref DEFAULT_DATETIME: DateTime<Utc> =
        DateTime::<Utc>::from_naive_utc_and_offset(DateTime::from_timestamp(0, 0).unwrap().naive_utc(), Utc);
}

/// Deserialize a `T` from the specified `deserializer` by expecting a string and parsing that string.
fn from_string<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    <T as FromStr>::Err: Display,
{
    String::deserialize(deserializer)?
        .parse()
        .map_err(serde::de::Error::custom)
}

/// Represents a timestamp object from metadata found in a Google Photos [export](https://takeout.google.com/)
///
/// See also [GooglePhotoMetadata].
#[derive(Deserialize, Debug, Copy, Clone)]
#[serde(rename_all = "camelCase")]
struct GoogleTimestamp {
    /// Number of seconds since 1970 UTC
    #[serde(deserialize_with = "from_string")]
    timestamp: i64,
}

/// Represents metadata found in a Google Photos [export](https://takeout.google.com/)
///
/// The metadata for each item in a Google Photos export is stored in a JSON file.  For the time being, we only
/// care about the timestamp(s) in that file.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct GooglePhotoMetadata {
    /// When the photo was taken, if known
    photo_taken_time: Option<GoogleTimestamp>,

    /// When the file was created, which may be later than `photo_taken_time` if the file has been copied
    creation_time: Option<GoogleTimestamp>,
}

/// Calculate the SHA-256 hash of the specified `input` and return the result as a hex-encoded string.
async fn hash(input: &mut (dyn AsyncRead + Unpin + Send + 'static)) -> Result<String> {
    let mut hasher = Sha256::default();

    let mut buffer = vec![0; BUFFER_SIZE];

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
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .concat())
}

/// Represents metadata for a given media item
#[derive(Debug, Copy, Clone)]
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
    item_count: usize,

    /// Number of items found which are considered duplicates
    duplicate_count: usize,
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
            .ok_or_else(|| anyhow!("unrecognized DateTime format: {datetime}"))?
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
        datetime: DateTime::<Utc>::from_naive_utc_and_offset(
            DateTime::from_timestamp(
                mp4parse::read_mp4(&mut File::open(path)?)?
                    .creation
                    .ok_or_else(|| anyhow!("missing creation time"))?
                    .0
                    .saturating_sub(SECONDS_FROM_1904_TO_1970)
                    .try_into()
                    .unwrap(),
                0,
            )
            .unwrap()
            .naive_utc(),
            Utc,
        ),
        video_offset: Some(0),
    })
}

/// Attempt to find the timestamp for the specified `path` in a Google Photo export metadata file.
///
/// See also [GooglePhotoMetadata].
fn google_datetime(path: &Path) -> Option<DateTime<Utc>> {
    let mut path = path.to_path_buf();
    let mut name = path.file_name().unwrap().to_os_string();
    name.push(".json");
    path.set_file_name(name);

    let metadata =
        serde_json::from_reader::<_, GooglePhotoMetadata>(BufReader::new(File::open(&path).ok()?))
            .ok()?;

    metadata
        .photo_taken_time
        .or(metadata.creation_time)
        .map(|GoogleTimestamp { timestamp }| {
            DateTime::<Utc>::from_naive_utc_and_offset(
                DateTime::from_timestamp(timestamp, 0).unwrap().naive_utc(),
                Utc,
            )
        })
}

/// Generate a [Metadata] object for the specified file.
///
/// We attempt to determine the creation timestamp in the following order:
///
/// 1. Check the metadata inside the file (e.g. EXIF or MPEG-4 metadata).
///
/// 2. Check for Google Photo metadata (see [GooglePhotoMetadata]).
///
/// 3. Try to extract the date from the filename.
///
/// 4. If all else fails, use [DEFAULT_DATETIME], which will result in a "year:unknown" tag being added later.
fn metadata_for(path: &Path) -> Metadata {
    let lowercase = path.file_name().unwrap().to_str().unwrap().to_lowercase();

    let is_video = MPEG4_EXTENSIONS.iter().any(|&ext| lowercase.ends_with(ext));

    lazy_static! {
        static ref DATE_TIME_PATTERN: Regex =
            Regex::new(r".*(?:(?:img)|(?:vid))[-_](\d{4})(\d{2})(\d{2})[-_].*").unwrap();
        static ref UNIX_EPOCH_PATTERN: Regex =
            Regex::new(r".*(?:(?:img)|(?:vid))[-_](\d{13})\..*").unwrap();
    }

    fn validate(datetime: DateTime<Utc>) -> Option<DateTime<Utc>> {
        // Currently, we consider any date in 1970 and any date more than a year in the future to be invalid.
        if datetime.year() == 1970 || datetime > (Utc::now() + Duration::days(366)) {
            None
        } else {
            Some(datetime)
        }
    }

    task::block_in_place(|| {
        let mut metadata = if is_video {
            mp4_metadata(path)
        } else {
            exif_metadata(path)
        }
        .unwrap_or(Metadata {
            datetime: *DEFAULT_DATETIME,
            video_offset: if is_video { Some(0) } else { None },
        });

        metadata.datetime = validate(metadata.datetime)
            .or_else(|| google_datetime(path))
            .and_then(validate)
            .or_else(|| {
                DATE_TIME_PATTERN
                    .captures(&lowercase)
                    .map(|c| format!("{}-{}-{}T00:00:00Z", &c[1], &c[2], &c[3]))
                    .and_then(|string| string.parse().ok())
            })
            .and_then(validate)
            .or_else(|| {
                UNIX_EPOCH_PATTERN.captures(&lowercase).and_then(|c| {
                    let millis = c[1].parse::<i64>().ok()?;
                    Some(DateTime::<Utc>::from_naive_utc_and_offset(
                        DateTime::from_timestamp(
                            millis / 1000,
                            u32::try_from((millis % 1000) * 1_000_000).unwrap(),
                        )
                        .unwrap()
                        .naive_utc(),
                        Utc,
                    ))
                })
            })
            .and_then(validate)
            .unwrap_or(*DEFAULT_DATETIME);

        metadata
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
    result: &'a mut Vec<(String, Metadata)>,
    dir: impl AsRef<Path> + 'a + Send,
) -> BoxFuture<'a, Result<()>> {
    let dir_buf = dir.as_ref().to_path_buf();

    async move {
        if dir_buf.ends_with(".thumbnails") {
            return Ok(());
        }

        let mut dir = fs::read_dir(dir).await?;

        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();

            if path.is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    let lowercase = name.to_lowercase();

                    // Some android phones "hide" files which have been "deleted" by prepending a ".trashed-"
                    // prefix to them.  We assume here that users don't want to see those.
                    //
                    // Also, we assume files named "cover.jpg" are part of an e-book collection and should be skipped.
                    if !(lowercase.starts_with(".trashed-") || lowercase == "cover.jpg")
                        && (MPEG4_EXTENSIONS.iter().any(|&ext| lowercase.ends_with(ext))
                            || JPEG_EXTENSIONS.iter().any(|&ext| lowercase.ends_with(ext)))
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
                                result.push((stripped.to_string(), metadata_for(&path)));
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

/// Group the specified `items` according to transitive similarity.
///
/// Here we define two items to be similar if their `PerceptualHash`es are either directly similar or transitively
/// similar.  I.e. if A is similar to B, and B is similar to C, then A, B, and C will be grouped together even if A
/// is not directly similar to C.  See also `PerceptualHash::is_similar_to` and `media::group_similar`.
fn group_similar(items: &[Item]) -> Vec<HashSet<&Item>> {
    let mut map = BTreeMap::<_, VecDeque<_>>::new();

    for item in items {
        map.entry(item.perceptual_hash.ordinal())
            .or_default()
            .push_back(item);
    }

    let mut items = map.into_iter().collect::<VecDeque<_>>();

    let mut similar = HashMap::<&Item, HashSet<&Item>>::new();

    while let Some((ordinal, mut my_items)) = items.pop_front() {
        // We need not compare items whose `PerceptualOrdinal`s which are not similar -- if the
        // `PerceptualOrdinal`s are not similar then the `PerceptualHash`es will not be either.  See also
        // `PerceptualOrdinal::is_similar_to`.
        let others = items
            .iter()
            .take_while(|(o, _)| ordinal.is_similar_to(o))
            .flat_map(|(_, i)| i.iter())
            .copied()
            .collect::<Vec<_>>();

        while let Some(item) = my_items.pop_front() {
            similar.entry(item).or_default();

            for other in my_items.iter().chain(others.iter()) {
                if item.perceptual_hash.is_similar_to(&other.perceptual_hash) {
                    similar.entry(item).or_default().insert(other);

                    similar.entry(other).or_default().insert(item);
                }
            }
        }
    }

    media::group_similar(similar)
}

/// Scan the collection of media items in `all`, grouping them by similarity and deduplicating each group with at
/// least one `dirty` item in it, recording the results in the database.
async fn deduplicate_dirty(
    conn: &AsyncMutex<SqliteConnection>,
    image_locks: &LockMap<Arc<str>, ()>,
    image_dir: &str,
    cache_dir: &str,
    mut dirty: HashMap<String, Item>,
    all: Vec<Item>,
) -> Result<DeduplicationSummary> {
    let new_count = dirty.len();

    info!("{new_count} new items since previous deduplication");

    // First, group all the items according to similarity, and identify which groups contain at least one dirty
    // item.
    //
    // Note that we use task::block_in_place here since this is an O(n^2) operation and can take a while.

    let dirty_groups = task::block_in_place(|| {
        group_similar(&all)
            .into_iter()
            .filter(|similar| {
                similar
                    .iter()
                    .any(|item| dirty.contains_key(&item.data.hash))
            })
            .collect::<Vec<_>>()
    });

    // Next, deduplicate each of the groups identified above, and add any whose duplicate group or index has
    // changed to the `dirty` collection so we can update the database later.

    let mut duplicate_count = 0;

    let group_count = dirty_groups.len();

    for (group_index, similar) in dirty_groups.into_iter().enumerate() {
        info!(
            "({} of {group_count}) deduplicating similar items [{}]",
            group_index + 1,
            similar
                .iter()
                .map(|item| &item.data.hash as &str)
                .collect::<Vec<_>>()
                .join(", ")
        );

        let duplicates = media::deduplicate(image_locks, image_dir, cache_dir, &similar)
            .await
            .unwrap_or_else(|e| {
                warn!(
                    "error deduplicating group [{}]: {e:?}",
                    similar
                        .iter()
                        .map(|item| &item.data.hash as &str)
                        .collect::<Vec<_>>()
                        .join(", ")
                );

                // If anything goes wrong deduplicating, assume there's no point in trying again (i.e. assume none
                // of the files will change and the error was deterministic).  Instead, we consider all the items
                // to be unique.
                similar.iter().map(|&item| vec![item]).collect()
            });

        for duplicates in duplicates {
            let alone = duplicates.len() == 1;

            let duplicate_group = if alone {
                None
            } else {
                duplicates.first().map(|item| item.data.hash.clone())
            };

            for (index, item) in duplicates.into_iter().enumerate() {
                let duplicate_index = if alone {
                    None
                } else {
                    Some(i64::try_from(index).unwrap())
                };

                if item.duplicate_group != duplicate_group
                    || item.duplicate_index != duplicate_index
                {
                    if !alone {
                        duplicate_count += 1;
                    }

                    dirty.insert(
                        item.data.hash.clone(),
                        Item {
                            duplicate_group: duplicate_group.clone(),
                            duplicate_index,
                            perceptual_hash: item.perceptual_hash.clone(),
                            data: item.data.clone(),
                        },
                    );
                }
            }
        }
    }

    // Finally, update the database in a single transaction so that if it fails or is interrupted, we can try again
    // in the next pass without worrying about inconsistent state.

    let item_count = dirty.len();

    conn.lock()
        .await
        .transaction(move |conn| {
            async move {
                for item in dirty.values() {
                    let perceptual_hash = item.perceptual_hash.to_string();

                    sqlx::query!(
                        "UPDATE images \
                         SET \
                         perceptual_hash = ?1, \
                         duplicate_group = ?2, \
                         duplicate_index = ?3 \
                         WHERE hash = ?4",
                        perceptual_hash,
                        item.duplicate_group,
                        item.duplicate_index,
                        item.data.hash,
                    )
                    .execute(&mut *conn)
                    .await?;
                }

                Ok::<_, Error>(())
            }
            .boxed()
        })
        .await?;

    Ok(DeduplicationSummary {
        item_count,
        duplicate_count,
    })
}

/// Query the database for items for which we have not yet calculated a perceptual hash (e.g. files that have been
/// newly added), calculate their p-hashes, and look for duplicates among all files which have similar p-hashes.
async fn deduplicate(
    conn: &AsyncMutex<SqliteConnection>,
    image_locks: &LockMap<Arc<str>, ()>,
    image_dir: &str,
    cache_dir: &str,
) -> Result<DeduplicationSummary> {
    // First, collect all items, calculating any missing perceptual hashes.

    let rows = sqlx::query!(
        "SELECT \
         i.hash, \
         i.video_offset, \
         i.perceptual_hash, \
         i.duplicate_group, \
         i.duplicate_index, \
         min(p.path) as \"path!: String\" \
         FROM images i \
         INNER JOIN paths p \
         ON i.hash = p.hash \
         GROUP BY i.hash"
    )
    .fetch(conn.lock().await.deref_mut())
    .try_collect::<Vec<_>>()
    .await?;

    let mut dirty = HashMap::new();
    let mut all = Vec::new();

    let dirty_count = rows
        .iter()
        .filter(|row| row.perceptual_hash.is_none())
        .count();
    let mut dirty_index = 1;

    for row in rows {
        let (perceptual_hash, is_dirty) = if let Some(perceptual_hash) = &row.perceptual_hash {
            (PerceptualHash::from_str(perceptual_hash)?, false)
        } else {
            info!(
                "({dirty_index} of {dirty_count}) calculating perceptual hash for {}",
                row.hash
            );

            dirty_index += 1;

            (
                media::perceptual_hash(
                    image_locks.get(Arc::from(row.hash.as_str())).await.deref(),
                    image_dir,
                    cache_dir,
                    &row.hash,
                    &row.path,
                    row.video_offset,
                )
                .await
                .unwrap_or_else(|e| {
                    warn!("error calculating perceptual hash for {}: {e:?}", row.hash);

                    // If we can't calculate the p-hash now, assume we never will be able to (i.e. the file will
                    // never change) and don't bother trying again.  Instead, record the p-hash as all zeros and
                    // move on.
                    PerceptualHash {
                        video_length_seconds: None,
                        image_hash: vec![0u8; PERCEPTUAL_HASH_LENGTH],
                    }
                }),
                true,
            )
        };

        let item = Item {
            data: ItemData {
                hash: row.hash,
                file: FileData {
                    path: row.path,
                    video_offset: row.video_offset,
                },
            },
            perceptual_hash: perceptual_hash.clone(),
            duplicate_group: row.duplicate_group,
            duplicate_index: row.duplicate_index,
        };

        if is_dirty {
            dirty.insert(item.data.hash.clone(), item.clone());
        }

        all.push(item);
    }

    if dirty.is_empty() {
        // No new items present -- nothing else to do.
        info!("no new items found to deduplicate");

        Ok(DeduplicationSummary {
            item_count: 0,
            duplicate_count: 0,
        })
    } else {
        // Found new items -- recalculate duplicates accordingly.
        deduplicate_dirty(conn, image_locks, image_dir, cache_dir, dirty, all).await
    }
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
    image_locks: &LockMap<Arc<str>, ()>,
    image_dir: &str,
    cache_dir: &str,
    preload: bool,
    deduplicate: bool,
) -> Result<()> {
    info!("starting sync (preload: {preload}; deduplicate: {deduplicate})");

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

    for (index, (path, mut data)) in new.into_iter().enumerate() {
        let hash =
            hash(&mut AsyncFile::open([image_dir, &path].iter().collect::<PathBuf>()).await?)
                .await?;

        info!(
            "({} of {new_len}) insert {path} (hash {hash}; data {data:?})",
            index + 1
        );

        conn.lock()
            .await
            .transaction(|conn| {
                let path = path.clone();
                let hash = hash.clone();

                async move {
                    // If this image already exists in the database, use whichever timestamp is most recent.
                    if let Some(row)
                        = sqlx::query!("SELECT datetime FROM images WHERE hash = ?1", hash)
                        .fetch_optional(&mut *conn).await?
                    {
                        let row_datetime = DateTime::<Utc>::from_str(&row.datetime)?;

                        if row_datetime < data.datetime {
                            let datetime = data.datetime.to_string();

                            sqlx::query!(
                                "UPDATE images SET datetime = ?1 WHERE hash = ?2", datetime, hash
                            )
                            .execute(&mut *conn)
                            .await?;
                        } else {
                            data.datetime = row_datetime;
                        }
                    } else {
                        let datetime = data.datetime.to_string();
                        let video_offset = data.video_offset;

                        sqlx::query!(
                            "INSERT INTO images (hash, datetime, video_offset) VALUES (?1, ?2, ?3)",
                            hash,
                            datetime,
                            video_offset
                        )
                        .execute(&mut *conn)
                        .await?;
                    }

                    sqlx::query!("INSERT INTO paths (path, hash) VALUES (?1, ?2)", path, hash)
                        .execute(&mut *conn)
                        .await?;

                    let medium = match data.video_offset {
                        None => "image",
                        Some(0) => "video",
                        Some(_) => "image-with-video",
                    };

                    sqlx::query!(
                        "INSERT OR IGNORE INTO tags (hash, category, tag) VALUES (?1, 'medium', ?2)",
                        hash,
                        medium
                    )
                    .execute(&mut *conn)
                    .await?;

                    // Given the logic above, we may need to change the year and month tags to a latter date.

                    sqlx::query!(
                        "DELETE FROM tags WHERE (category = 'year' OR category = 'month') AND hash = ?1",
                        hash
                    )
                    .execute(&mut *conn)
                    .await?;

                    if data.datetime != *DEFAULT_DATETIME {
                        let year = data.datetime.year();

                        sqlx::query!(
                            "INSERT OR IGNORE INTO tags (hash, category, tag) VALUES (?1, 'year', ?2)",
                            hash,
                            year
                        )
                        .execute(&mut *conn)
                        .await?;

                        let month = data.datetime.month();

                        sqlx::query!(
                            "INSERT OR IGNORE INTO tags (hash, category, tag) VALUES (?1, 'month', ?2)",
                            hash,
                            month
                        )
                        .execute(&mut *conn)
                        .await?;
                    } else {
                        sqlx::query!(
                            "INSERT OR IGNORE INTO tags (hash, category, tag) VALUES (?1, 'year', 'unknown')",
                            hash
                        )
                        .execute(&mut *conn)
                        .await?;
                    }

                    Ok::<_, Error>(())
                }
                .boxed()
            })
            .await?;

        if preload {
            if let Err(e) = media::preload_cache(
                image_locks.get(Arc::from(hash.as_str())).await.deref(),
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
                warn!("error preloading cache for {hash}: {e:?}");

                mark_bad(conn, &hash).await?;
            }
        }
    }

    // For each obsolete file found, atomically remove it from the database.

    for (index, path) in obsolete.into_iter().enumerate() {
        info!("({} of {obsolete_len}) delete {path}", index + 1);

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
        "sync took {:?} (added {new_len}; deleted {obsolete_len})",
        then.elapsed()
    );

    if deduplicate {
        info!("starting deduplication");

        let then = Instant::now();

        let summary = crate::sync::deduplicate(conn, image_locks, image_dir, cache_dir).await?;

        info!(
            "deduplication took {:?} (checked {} items; found {} duplicates)",
            then.elapsed(),
            summary.item_count,
            summary.duplicate_count
        );
    }

    Ok(())
}

/// Move any and all paths for the specified item from the `paths` table to the `bad_paths` table and delete the
/// item from the `images` table.
///
/// This is the appropriate function to call if a file cannot be parsed; it ensures that we won't try again later,
/// e.g. on server restart.
pub async fn mark_bad(conn: &AsyncMutex<SqliteConnection>, hash: &str) -> Result<()> {
    warn!("marking {hash} as bad");

    conn.lock()
        .await
        .transaction(|conn| {
            let hash = hash.to_owned();

            async move {
                let paths = sqlx::query!("SELECT path FROM paths WHERE hash = ?1", hash)
                    .fetch(&mut *conn)
                    .and_then(|row| future::ok(row.path))
                    .try_collect::<Vec<_>>()
                    .await?;

                sqlx::query!("DELETE FROM images WHERE hash = ?1", hash)
                    .execute(&mut *conn)
                    .await?;

                for path in paths {
                    sqlx::query!("INSERT INTO bad_paths (path) VALUES (?1)", path)
                        .execute(&mut *conn)
                        .await?;
                }

                Ok::<_, Error>(())
            }
            .boxed()
        })
        .await
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn metadata_for_whatsapp_file() -> Result<()> {
        assert_eq!(
            metadata_for(&Path::new("/does-not-exist/IMG-20210515-WA0004.jpg")).datetime,
            "2021-05-15T00:00:00Z".parse::<DateTime<Utc>>()?
        );
        Ok(())
    }

    #[test]
    fn metadata_for_kraken_sports_file() -> Result<()> {
        assert_eq!(
            metadata_for(&Path::new("/does-not-exist/IMG-1748014806987.jpg")).datetime,
            "2025-05-23T15:40:06.987Z".parse::<DateTime<Utc>>()?
        );
        Ok(())
    }
}
