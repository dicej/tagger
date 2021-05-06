#![deny(warnings)]

use anyhow::{anyhow, Error, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use futures::{
    future::{BoxFuture, FutureExt, TryFutureExt},
    stream::TryStreamExt,
};
use http::{
    header,
    response::{self, Response},
};
use hyper::Body;
use image::{imageops::FilterType, GenericImageView, ImageFormat, ImageOutputFormat};
use lazy_static::lazy_static;
use regex::Regex;
use rexiv2::Metadata;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{sqlite::SqliteConnectOptions, ConnectOptions, Connection, Row, SqliteConnection};
use std::{
    collections::HashMap,
    convert::Infallible,
    iter,
    net::SocketAddrV4,
    ops::DerefMut,
    panic::{self, AssertUnwindSafe},
    path::{Path, PathBuf},
    process,
    sync::Arc,
    time::{Duration, Instant},
};
use structopt::StructOpt;
use tokio::{
    fs::{self, File},
    io::AsyncReadExt,
    sync::Mutex as AsyncMutex,
    task, time,
};
use tracing::{error, info, warn};
use warp::{Filter, Rejection, Reply};
use warp_util::HttpError;

mod warp_util;

const SMALL_BOUNDS: (u32, u32) = (320, 240);
const LARGE_BOUNDS: (u32, u32) = (1280, 960);
const JPEG_QUALITY: u8 = 90;
const SYNC_INTERVAL_SECONDS: u64 = 10;

async fn open(state_file: &str) -> Result<SqliteConnection> {
    let mut conn = format!("sqlite://{}", state_file)
        .parse::<SqliteConnectOptions>()?
        .create_if_missing(true)
        .connect()
        .await?;

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

    hasher.update(data);

    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .concat()
}

fn find_new<'a>(
    conn: &'a AsyncMutex<SqliteConnection>,
    root: &'a str,
    result: &'a mut Vec<(String, String)>,
    dir: impl AsRef<Path> + 'a + Send,
) -> BoxFuture<'a, Result<()>> {
    lazy_static! {
        static ref DATE_TIME_PATTERN: Regex = Regex::new(r"(\d{4}):(\d{2}):(\d{2}) (\d{2}):(\d{2}):(\d{2})").unwrap();
    };

    let dir_buf = dir.as_ref().to_path_buf();

    async {
        let mut dir = fs::read_dir(dir).await?;

        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    let lowercase = name.to_lowercase();
                    if lowercase.ends_with(".jpg") || lowercase.ends_with(".jpeg") {
                        let mut path = dir_buf.clone();
                        path.push(name);
                        let stripped = path.strip_prefix(root)?.to_str().ok_or_else(|| anyhow!("bad utf8"))?;

                        let found = sqlx::query("SELECT 1 FROM paths WHERE path = ?1")
                            .bind(stripped)
                            .fetch_optional(conn.lock().await.deref_mut())
                            .await?
                            .is_some();

                        if !found {
                            if let Some(datetime) = Metadata::new_from_buffer(&content(&path).await?)
                                .and_then(|m| m.get_tag_string("Exif.Image.DateTime"))
                                .ok()
                                .and_then(|s| {
                                    DATE_TIME_PATTERN.captures(&s).map(|c| {
                                        format!("{}-{}-{} {}:{}:{}", &c[1], &c[2], &c[3], &c[4], &c[5], &c[6])
                                    })
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
    .boxed()
}

async fn sync(conn: &AsyncMutex<SqliteConnection>, image_dir: &str) -> Result<()> {
    let then = Instant::now();

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

    let new = {
        let mut new = Vec::new();

        find_new(conn, image_dir, &mut new, image_dir).await?;

        new
    };

    let new_len = new.len();

    for (path, datetime) in new {
        let hash = hash(&content([image_dir, &path].iter().collect::<PathBuf>()).await?);

        info!("insert {} (hash {})", path, hash);

        conn.lock()
            .await
            .transaction(|conn| {
                async move {
                    sqlx::query!("INSERT INTO paths (path, hash) VALUES (?1, ?2)", path, hash)
                        .execute(&mut *conn)
                        .await?;

                    sqlx::query!(
                        "INSERT OR IGNORE INTO images (hash, datetime) VALUES (?1, ?2)",
                        hash,
                        datetime
                    )
                    .execute(&mut *conn)
                    .await
                }
                .boxed()
            })
            .await?;
    }

    for path in obsolete {
        info!("delete {}", path);

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

                        if sqlx::query("SELECT 1 FROM paths WHERE hash = ?1")
                            .bind(&row.hash)
                            .fetch_optional(&mut *conn)
                            .await?
                            .is_none()
                        {
                            sqlx::query!("DELETE FROM images WHERE hash = ?1", row.hash)
                                .execute(&mut *conn)
                                .await?;
                        }
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

async fn state(conn: &mut SqliteConnection, query: &StateQuery) -> Result<HashMap<String, ImageState>> {
    let select = format!(
        "SELECT i.hash, i.datetime, t.tag
         FROM images AS i
         LEFT JOIN tags AS t ON i.hash = t.hash
         WHERE 1{}{}{}
         SORT BY i.datetime",
        if query.start.is_some() {
            " AND i.datetime > ?"
        } else {
            ""
        },
        if query.tag.is_empty() {
            String::new()
        } else {
            iter::repeat(" AND t.tag = ?")
                .take(query.tag.len())
                .collect::<Vec<_>>()
                .concat()
        },
        if query.limit.is_some() { " LIMIT ?" } else { "" }
    );

    let mut select = sqlx::query(&select);

    if let Some(start) = &query.start {
        select = select.bind(start.naive_utc().to_string());
    }

    for tag in &query.tag {
        select = select.bind(tag);
    }

    if let Some(limit) = &query.limit {
        select = select.bind(limit);
    }

    let mut map = HashMap::new();

    let mut rows = select.fetch(conn);

    while let Some(row) = rows.try_next().await? {
        let datetime = DateTime::<Utc>::from_utc(row.get::<&str, _>(1).parse::<NaiveDateTime>()?, Utc);

        map.entry(row.get(0))
            .or_insert_with(|| ImageState {
                datetime,
                tags: Vec::new(),
            })
            .tags
            .push(row.get(2));
    }

    Ok(map)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Action {
    Add,
    Remove,
}

#[derive(Serialize, Deserialize)]
struct Patch {
    hash: String,
    tag: String,
    action: Action,
}

async fn apply(conn: &mut SqliteConnection, patch: Patch) -> Result<()> {
    match patch.action {
        Action::Add => {
            sqlx::query!("INSERT INTO tags (hash, tag) VALUES (?1, ?2)", patch.hash, patch.tag)
                .execute(conn)
                .await?;
        }
        Action::Remove => {
            sqlx::query!("DELETE FROM tags WHERE hash = ?1 AND tag = ?2", patch.hash, patch.tag)
                .execute(conn)
                .await?;
        }
    }

    Ok(())
}

async fn full_size_image(conn: &mut SqliteConnection, image_dir: &str, path: &str) -> Result<Vec<u8>> {
    if let Some(row) = sqlx::query!("SELECT path FROM paths WHERE hash = ?1 LIMIT 1", path)
        .fetch_optional(conn)
        .await?
    {
        content([image_dir, &row.path].iter().collect::<PathBuf>()).await
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

#[derive(Deserialize, Debug, Copy, Clone)]
#[serde(rename_all = "lowercase")]
enum ThumbnailSize {
    Small,
    Large,
}

async fn thumbnail(
    conn: &AsyncMutex<SqliteConnection>,
    image_dir: &str,
    size: ThumbnailSize,
    path: &str,
) -> Result<Vec<u8>> {
    let result = match size {
        ThumbnailSize::Small => sqlx::query!("SELECT small FROM images WHERE hash = ?1 LIMIT 1", path)
            .fetch_optional(conn.lock().await.deref_mut())
            .await?
            .and_then(|row| row.small),
        ThumbnailSize::Large => sqlx::query!("SELECT large FROM images WHERE hash = ?1 LIMIT 1", path)
            .fetch_optional(conn.lock().await.deref_mut())
            .await?
            .and_then(|row| row.large),
    };

    if let Some(result) = result {
        Ok(result)
    } else {
        let image = full_size_image(conn.lock().await.deref_mut(), image_dir, path).await?;

        let native_size = image::load_from_memory_with_format(&image, ImageFormat::Jpeg)?;

        let resize = |bounds| {
            let (width, height) = bound(native_size.dimensions(), bounds);

            let mut encoded = Vec::new();

            native_size
                .resize(width, height, FilterType::Lanczos3)
                .write_to(&mut encoded, ImageOutputFormat::Jpeg(JPEG_QUALITY))?;

            Ok::<_, Error>(encoded)
        };

        let small = resize(SMALL_BOUNDS)?;
        sqlx::query!("UPDATE images SET small = ?1 WHERE hash = ?2", small, path)
            .execute(conn.lock().await.deref_mut())
            .await?;

        let large = resize(LARGE_BOUNDS)?;
        sqlx::query!("UPDATE images SET large = ?1 WHERE hash = ?2", large, path)
            .execute(conn.lock().await.deref_mut())
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

async fn image(
    conn: &AsyncMutex<SqliteConnection>,
    image_dir: &str,
    path: &str,
    query: &ImageQuery,
) -> Result<Vec<u8>> {
    if let Some(size) = query.size {
        thumbnail(conn, image_dir, size, path).await
    } else {
        full_size_image(conn.lock().await.deref_mut(), image_dir, path).await
    }
}

fn response() -> response::Builder {
    Response::builder()
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "any")
        .header(header::ACCESS_CONTROL_ALLOW_HEADERS, "content-type, content-length")
        .header(header::ACCESS_CONTROL_ALLOW_METHODS, "get, post, options, head")
}

fn routes(
    conn: &Arc<AsyncMutex<SqliteConnection>>,
    options: &Arc<Options>,
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
                            let state = serde_json::to_vec(&state(conn.lock().await.deref_mut(), &query).await?)?;

                            Ok(response()
                                .header(header::CONTENT_LENGTH, state.len())
                                .header(header::CONTENT_TYPE, "application/json")
                                .body(Body::from(state))?)
                        }
                        .map_err(|e| {
                            warn!(?auth, "error retrieving state: {:?}", e);

                            Rejection::from(HttpError::from(e))
                        })
                    }
                })
                .or(warp::path!("image" / String)
                    .and(warp::query::<ImageQuery>())
                    .and_then({
                        let conn = conn.clone();
                        let options = options.clone();

                        move |hash: String, query| {
                            let conn = conn.clone();
                            let options = options.clone();

                            async move {
                                let image = image(&conn, &options.image_directory, &hash, &query).await?;

                                Ok(response()
                                    .header(header::CONTENT_LENGTH, image.len())
                                    .header(header::CONTENT_TYPE, "application/json")
                                    .body(Body::from(image))?)
                            }
                            .map_err(|e| {
                                warn!(?auth, "error retrieving image {}: {:?}", hash, e);

                                Rejection::from(HttpError::from(e))
                            })
                        }
                    }))
                .or(warp::fs::dir(&options.public_directory)),
        )
        .or(warp::post().and(warp::path("patch")).and(warp::body::json()).and_then({
            let conn = conn.clone();
            move |patch: Patch| {
                let conn = conn.clone();

                async move {
                    apply(conn.lock().await.deref_mut(), patch).await?;

                    Ok(String::new())
                }
                .map_err(|e| {
                    warn!(
                        ?auth,
                        "error applying patch {}: {:?}",
                        serde_json::to_string(&patch).unwrap_or_else(|_| "(unable to serialize patch)".to_string()),
                        e
                    );

                    Rejection::from(HttpError::from(e))
                })
            }
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

async fn serve(conn: &Arc<AsyncMutex<SqliteConnection>>, options: &Arc<Options>) -> Result<()> {
    let routes = routes(conn, options);

    let (address, future) = if let (Some(cert), Some(key)) = (&options.cert_file, &options.key_file) {
        let server = warp::serve(routes).tls().cert_path(cert).key_path(key);

        // As of this writing, warp::TlsServer does not have a try_bind_ephemeral method, so we must catch panics
        // explicitly.
        let (address, future) = catch_unwind(AssertUnwindSafe(move || server.bind_ephemeral(options.address)))?;

        (address, future.boxed())
    } else {
        let (address, future) = warp::serve(routes).try_bind_ephemeral(options.address)?;

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
    address: SocketAddrV4,

    #[structopt(long, help = "directory containing image files")]
    image_directory: String,

    #[structopt(long, help = "SQLite database of image metadata to create or reuse")]
    state_file: String,

    #[structopt(long, help = "directory containing static resources")]
    public_directory: String,

    #[structopt(long, help = "file containing TLS certificate to use")]
    cert_file: Option<String>,

    #[structopt(long, help = "file containing TLS key to use")]
    key_file: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init_timed();

    let options = Arc::new(Options::from_args());

    let conn = Arc::new(AsyncMutex::new(open(&options.state_file).await?));

    sync(&conn, &options.image_directory);

    task::spawn({
        let options = options.clone();
        let conn = conn.clone();

        async move {
            time::sleep(Duration::from_secs(SYNC_INTERVAL_SECONDS));

            if let Err(e) = sync(&conn, &options.image_directory).await {
                error!("sync error: {:?}", e);
                process::exit(-1)
            }
        }
    });

    serve(&conn, &options).await
}
