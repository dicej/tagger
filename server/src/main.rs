#![deny(warnings)]

use anyhow::{anyhow, Result};
use chrono::Local;
use image::{FilterType, GenericImage, ImageFormat, ImageOutputFormat};
use regex::Regex;
use rexiv2::Metadata;
use rusqlite::{Connection, DatabaseName};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env,
    ffi::OsStr,
    path::{Path, PathBuf},
    process,
    rc::Rc,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use structopt::StructOpt;
use unicase::Ascii;
use warp_util::HttpError;

mod warp_util;

const SMALL_BOUNDS: (u32, u32) = (320, 240);
const LARGE_BOUNDS: (u32, u32) = (1280, 960);
const JPEG_QUALITY: u8 = 90;
const SYNC_INTERVAL_SECONDS: u64 = 10;

fn open(state_file: &str) -> Result<SqliteConnection> {
    let conn = SqliteConnection::connect(&format!("sqlite://", state_file))?;

    for statement in schema::DDL_STATEMENTS {
        sqlx::query(statement).execute(&mut conn).await?;
    }

    Ok(conn)
}

async fn content<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    File::open(path).await?.read_to_end(&mut buffer).await?;

    Ok(buffer)
}

fn hash(data: &[u8]) -> String {
    let mut hasher = Sha256::default();

    hasher.input(data);

    hasher
        .result()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .concat()
}

async fn find_new<P: AsRef<Path>>(
    conn: &AsyncMutex<SqliteConnection>,
    root: &str,
    result: &mut Vec<(String, String)>,
    dir: P,
) -> Result<()> {
    lazy_static! {
        static ref DATE_TIME_PATTERN: Regex = Regex::new(r"(\d{4}):(\d{2}):(\d{2}) (\d{2}):(\d{2}):(\d{2})").unwrap();
    };

    let dir_buf = dir.as_ref().to_path_buf();
    for entry in read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(name) = entry.file_name().to_str() {
                let lowercase = name.to_lowercase();
                if lowercase.ends_with(".jpg") || lowercase.ends_with(".jpeg") {
                    let mut path = dir_buf.clone();
                    path.push(name);
                    let stripped = path.strip_prefix(root)?.to_str().ok_or_else(|| anyhow!("bad utf8"))?;

                    let found = sqlx::query!("SELECT 1 FROM paths WHERE path = ?1", path)
                        .fetch_optional(&mut conn.lock().await)
                        .await?
                        .is_some();

                    if !found {
                        if let Some(datetime) = Metadata::new_from_path(&path)
                            .await
                            .and_then(|m| m.get_tag_string("Exif.Image.DateTime"))
                            .ok()
                            .and_then(|s| {
                                DATE_TIME_PATTERN
                                    .captures(&s)
                                    .map(|c| format!("{}-{}-{} {}:{}:{}", &c[1], &c[2], &c[3], &c[4], &c[5], &c[6]))
                            })
                        {
                            result.push((stripped.to_string(), datetime))
                        } else {
                            warn!("unable to get metadata for {}", lowercase);
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

async fn sync(conn: &AsyncMutex<Connection>, image_dir: &str) -> Result<()> {
    let then = Instant::now();

    let obsolete = sqlx::query!("SELECT path FROM paths")
        .fetch(&mut conn.lock().await)
        .await?
        .filter(|path| ![image_dir, path].iter().collect::<PathBuf>().is_file())
        .collect::<Vec<_>>();

    let new = {
        let mut result = Vec::new();
        find_new(conn, image_dir, &mut result, image_dir, pattern).await?;
        result
    };

    for &(ref path, ref datetime) in new.iter() {
        let hash = hash(&content([image_dir, &path].iter().collect::<PathBuf>())?);

        info!("insert {} (hash {})", path, hash);

        conn.lock()
            .await
            .transaction(|conn| async {
                sqlx::query!("INSERT INTO paths (path, hash) VALUES (?1, ?2)", path, hash)
                    .execute(conn)
                    .await?;

                sqlx::query!(
                    "INSERT OR IGNORE INTO images (hash, datetime) VALUES (?1, ?2)",
                    hash,
                    datetime
                )
                .execute(conn)
                .await
            })
            .await?
    }

    for path in obsolete.iter() {
        info!("delete {}", path);

        conn.lock()
            .await
            .transaction(|conn| async {
                if let Some(hash) = sqlx::query!("SELECT hash FROM paths WHERE path = ?1", path)
                    .fetch_optional(conn)
                    .await
                {
                    sqlx::query!("DELETE FROM paths WHERE path = ?1", path)
                        .execute(conn)
                        .await?;

                    if sqlx::query!("SELECT 1 FROM paths WHERE hash = ?1", hash)
                        .fetch_optional(conn)
                        .await?
                        .is_none()
                    {
                        sqlx::query!("DELETE FROM images WHERE hash = ?1", hash)
                            .execute(conn)
                            .await?;
                    }
                }

                Ok(())
            })
            .await?;
    }

    info!(
        "sync took {:?} (added {}; deleted {})",
        then.elapsed(),
        new.len(),
        obsolete.len()
    );

    Ok(())
}

#[derive(Deserialize, Debug)]
struct StateQuery {
    start: Option<DateTime<Utc>>,
    limit: Option<i32>,
    tag: Vec<String>,
}

#[derive(Serialize, Debug)]
struct ImageState {
    datetime: DateTime<Utc>,
    tags: Vec<String>,
}

async fn state(conn: &mut Connection, query: &StateQuery) -> Result<Map<String, ImageState>> {
    let mut query = sqlx::query(&format!(
        "SELECT i.hash, i.datetime, t.tag FROM images AS i LEFT JOIN tags AS t ON i.hash = t.hash WHERE 1{}{}{}",
        if query.start.is_some() {
            " AND i.datetime > ?"
        } else {
            ""
        },
        if query.tag.is_empty() {
            ""
        } else {
            &iter::repeat(" AND t.tag = ?")
                .take(query.tag.len())
                .collect::<Vec<_>>()
                .concat()
        },
        if query.limit.is_some() { " LIMIT ?" } else { "" }
    ));

    if let Some(start) = &query.start {
        query = query.bind(start);
    }

    for tag in &query.tag {
        query = query.bind(tag);
    }

    if let Some(limit) = &query.limit {
        query = query.bind(limit);
    }

    let mut map = HashMap::new();

    for row in query.fetch(conn).await? {
        map.entry(row.get(0))
            .or_insert_with(|| ImageState {
                datetime: row.get(1),
                tags: Vec::new(),
            })
            .tags
            .push(row.get(2));
    }

    Ok(map)
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Action {
    Add,
    Remove,
}

#[derive(Deserialize)]
struct Patch {
    hash: String,
    tag: String,
    action: Action,
}

async fn apply(conn: &mut Connection, patch: Patch) -> Result<()> {
    Ok(match patch.action {
        Action::Add => {
            sqlx::query!("INSERT INTO tags (hash, tag) VALUES (?1, ?2)", hash, tag)
                .execute(conn)
                .await?
        }
        Action::Remove => {
            sqlx::query!("DELETE FROM tags WHERE hash = ?1 AND tag = ?2", hash, tag)
                .execute(conn)
                .await?
        }
    })
}

async fn full_size_image(conn: &mut Connection, image_dir: &str, path: &str) -> Result<Vec<u8>> {
    if let Some(path) = sql::query!("SELECT path FROM paths WHERE hash = ?1 LIMIT 1", path)
        .fetch_optional(conn)
        .await?
    {
        content([image_dir, &path].iter().collect::<PathBuf>()).await
    } else {
        Err(anyhow!("image not found: {}", path))
    }
}

fn bound((native_width, native_height): (u32, u32), (bound_width, bound_height): (u32, u32)) -> (u32, u32) {
    if native_width * bound_height > bound_width * native_height {
        (bound_width, (native_height * bound_width) / native_width)
    } else {
        ((native_width * bound_height) / native_height, bound_height)
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum ThumbnailSize {
    Small,
    Large,
}

async fn thumbnail(
    conn: &AsyncMutex<Connection>,
    image_dir: &str,
    size: ThumbnailSize,
    path: &str,
) -> Result<Vec<u8>> {
    let result = match size {
        ThumbnailSize::Small => {
            sqlx::query!("SELECT small FROM images WHERE hash = ?1 LIMIT 1", path)
                .fetch_optional(&mut conn.lock().await)
                .await?
        }
        ThumbnailSize::Large => {
            sqlx::query!("SELECT large FROM images WHERE hash = ?1 LIMIT 1", path)
                .fetch_optional(&mut conn.lock().await)
                .await?
        }
    };

    if let Some(result) = result {
        Ok(result)
    } else {
        let image = full_size_image(&mut conn.lock().unwrap(), image_dir, path).await?;

        let native_size = load_from_memory_with_format(&image, ImageFormat::JPEG)?;

        let resize = |bounds| {
            let (width, height) = bound(native_size.dimensions(), bounds);

            let mut encoded = Vec::new();

            native_size
                .resize(width, height, FilterType::Lanczos3)
                .write_to(&mut encoded, ImageOutputFormat::JPEG(JPEG_QUALITY))?;

            Ok(encoded)
        };

        let small = resize(SMALL_BOUNDS);
        sqlx::query!("UPDATE images SET small = ?1 WHERE hash = ?2", small, path)
            .execute(&mut conn.lock().await)
            .await?;

        let large = resize(LARGE_BOUNDS);
        sqlx::query!("UPDATE images SET large = ?1 WHERE hash = ?2", large, path)
            .execute(&mut conn.lock().await)
            .await?;

        Ok(match size {
            ThumbnailSize::Small => small,
            ThumbnailSize::Large => large,
        })
    }
}

#[derive(Deserialize, Debug)]
struct ImageQuery {
    size: Option<ThumbnailSize>,
}

async fn image(conn: &AsyncMutex<Connection>, image_dir: &str, path: &str, query: &ImageQuery) -> Result<Vec<u8>> {
    if let Some(size) = &query.size {
        thumbnail(conn, image_dir, size, path).await
    } else {
        full_size_image(&mut conn.lock().await, image_dir, path).await
    }
}

fn response() -> Response {
    Response::new()
        .with_header(AccessControlAllowOrigin::Any)
        .with_header(AccessControlAllowHeaders(vec![
            Ascii::new("content-type".to_string()),
            Ascii::new("content-length".to_string()),
        ]))
        .with_header(AccessControlAllowMethods(vec![
            Method::Get,
            Method::Post,
            Method::Options,
            Method::Head,
        ]))
}

fn routes(
    conn: Arc<AsyncMutex<Connection>>,
    options: &Options,
) -> impl Filter<Extract = (impl Reply,), Error = Infallible> + Clone {
    warp::get()
        .and(
            warp::path("state")
                .and(warp::query::<StateQuery>())
                .and_then({
                    let conn = conn.clone();

                    move |query| {
                        let conn = conn.clone();

                        async move {
                            let state = serde_json::to_vec(&state(&mut conn.lock().await, &query).await?)?;

                            Ok(response()
                                .with_header(ContentLength(state.len() as u64))
                                .with_header(ContentType::json())
                                .with_body(state)?)
                        }
                        .map_err(|e| {
                            warn!(?auth, "error retrieving state: {:?}", e);

                            Rejection::from(HttpError::from(e))
                        })
                    }
                })
                .or(warp::path("image" / String).and(warp::query::<ImageQuery>()).and_then({
                    let conn = conn.clone();

                    move |hash, query| {
                        let conn = conn.clone();

                        async move {
                            let image = image(&conn, image_dir, hash, &query).await?;

                            Ok(response()
                                .with_header(ContentLength(image.len() as u64))
                                .with_header(ContentType::jpeg())
                                .with_body(image)?)
                        }
                        .map_err(|e| {
                            warn!(?auth, "error retrieving image {}: {:?}", hash, e);

                            Rejection::from(HttpError::from(e))
                        })
                    }
                }))
                .or(warp::fs::dir(&options.public_dir)),
        )
        .or(warp::post()
            .and(warp::path("patch"))
            .and(warp::body::json())
            .and_then(move |patch: Patch| {
                let conn = conn.clone();

                async move {
                    apply(&mut conn.lock().await, patch).await?;

                    Ok(())
                }
                .map_err(|e| {
                    warn!(?auth, "error applying patch {}: {:?}", hash, e);

                    Rejection::from(HttpError::from(e))
                })
            }))
        .recover(warp_util::handle_rejection)
        .with(warp::log("tagger"))
}

fn catch_unwind<T>(fun: impl panic::UnwindSafe + FnOnce() -> T) -> Result<T> {
    panic::catch_unwind(fun).map_err(|e| {
        if let Some(s) = e.downcast_ref::<&str>() {
            anyhow!("{}", s)
        } else if let Some(s) = e.downcast_ref::<String>() {
            anyhow!("{}", s)
        } else {
            anyhow!("caught panic")
        }
    })
}

async fn serve(conn: Arc<Mutex<Connection>>, options: &Options) -> Result<()> {
    let (address, future) = if let Some((cert, key)) = &tls_cert_and_key {
        let server = server.tls().cert_path(cert).key_path(key);

        // As of this writing, warp::TlsServer does not have a try_bind_ephemeral method, so we must catch panics
        // explicitly.
        let (address, future) = catch_unwind(AssertUnwindSafe(move || server.bind_ephemeral(address)))?;

        (address, future.boxed())
    } else {
        let (address, future) = server.try_bind_ephemeral(address)?;

        (address, future.boxed())
    };

    info!("listening on {}", address);

    future.await;

    Ok(())
}

#[derive(StructOpt, Debug)]
#[structopt(name = "tagger-server", about = "Image tagging webapp backend")]
struct Options {
    #[structopt(long, help = "address to which to bind")]
    address: Ipv4Addr,

    #[structopt(long, help = "directory containing image files")]
    image_directory: Arc<str>,

    #[structopt(long, help = "SQLite database of image metadata to create or reuse")]
    state_file: PathBuf,

    #[structopt(long, help = "directory containing static resources")]
    public_directory: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init_timed();

    let options = Options::from_args();

    let conn = task::block_in_place(|| {
        let conn = Arc::new(Mutex::new(open(&options.state_file)?));

        sync(&conn, &options.image_directory);

        conn
    });

    thread::spawn({
        let image_dir = options.image_directory.clone();
        let conn = conn.clone();

        move || {
            thread::sleep(Duration::from_secs(SYNC_INTERVAL_SECONDS));

            if let Err(e) = sync(&conn, &image_dir) {
                error!("sync error: {:?}", e);
                exit(-1)
            }
        }
    });

    serve(&conn, &options).await
}
