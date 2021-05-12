#![deny(warnings)]

use anyhow::{anyhow, Error, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use futures::{
    future::{self, BoxFuture, FutureExt, TryFutureExt},
    stream::TryStreamExt,
};
use http::{
    header,
    response::{self, Response},
    status::StatusCode,
};
use hyper::Body;
use image::{imageops::FilterType, GenericImageView, ImageFormat, ImageOutputFormat};
use jsonwebtoken::{self, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use lalrpop_util::lalrpop_mod;
use lazy_static::lazy_static;
use rand::Rng;
use regex::Regex;
use rexiv2::Metadata;
use serde::Deserializer;
use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{sqlite::SqliteConnectOptions, ConnectOptions, Connection, Row, SqliteConnection};
use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddrV4,
    num::NonZeroU32,
    ops::DerefMut,
    panic::{self, AssertUnwindSafe},
    path::{Path, PathBuf},
    process,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use structopt::StructOpt;
use tag_expression::TagExpression;
use tokio::{
    fs::{self, File},
    io::AsyncReadExt,
    sync::Mutex as AsyncMutex,
    task, time,
};
use tracing::{error, info, warn};
use warp::{Filter, Rejection, Reply};
use warp_util::HttpError;

mod tag_expression;
mod warp_util;

lalrpop_mod!(
    #[allow(clippy::all)]
    tag_expression_grammar
);

const SMALL_BOUNDS: (u32, u32) = (320, 240);

const LARGE_BOUNDS: (u32, u32) = (1280, 960);

const JPEG_QUALITY: u8 = 90;

const SYNC_INTERVAL_SECONDS: u64 = 10;

const INVALID_CREDENTIAL_DELAY_SECS: u64 = 5;

const TOKEN_EXPIRATION_SECS: u64 = 24 * 60 * 60;

const DEFAULT_LIMIT: u32 = 1000;

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

    async move {
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
                                .and_then(|m| {
                                    m.get_tag_string("Exif.Image.DateTimeOriginal")
                                        .or_else(|_| m.get_tag_string("Exif.Image.DateTime"))
                                })
                                .ok()
                                .and_then(|s| {
                                    DATE_TIME_PATTERN.captures(&s).map(|c| {
                                        format!("{}-{}-{}T{}:{}:{}", &c[1], &c[2], &c[3], &c[4], &c[5], &c[6])
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

impl FromStr for TagExpression {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        tag_expression_grammar::TagExpressionParser::new()
            .parse(s)
            .map(|tags| *tags)
            .map_err(|e| e.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for TagExpression {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize, Debug)]
struct StateQuery {
    start: Option<DateTime<Utc>>,
    limit: Option<u32>,
    tags: Option<TagExpression>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ImageState {
    datetime: DateTime<Utc>,
    tags: Vec<String>,
}

async fn state(conn: &mut SqliteConnection, query: &StateQuery) -> Result<HashMap<String, ImageState>> {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);

    let select = format!(
        "SELECT i.hash, i.datetime, t.tag
         FROM images AS i
         LEFT JOIN tags AS t ON i.hash = t.hash
         WHERE 1{}
         ORDER BY i.datetime
         LIMIT ?",
        if query.start.is_some() {
            " AND i.datetime >= ?"
        } else {
            ""
        },
        if let Some(tags) = &query.tags {
            format!(" AND {}", tags.to_sql_string())
        } else {
            String::new()
        }
    );

    let mut select = sqlx::query(&select);

    if let Some(start) = &query.start {
        select = select.bind(start.naive_utc().to_string());
    }

    if let Some(tags) = &query.tags {
        select = tags.fold_tags(select, |select, tag| select.bind(tag));
    }

    select = select.bind(limit + 1);

    let mut map = HashMap::new();

    let mut rows = select.fetch(conn);

    while let Some(row) = rows.try_next().await? {
        let datetime = DateTime::<Utc>::from_utc(row.get::<&str, _>(1).parse::<NaiveDateTime>()?, Utc);

        let entry = map.entry(row.get(0)).or_insert_with(|| ImageState {
            datetime,
            tags: Vec::new(),
        });

        if let Some(tag) = row.get::<Option<String>, _>(2) {
            entry.tags.push(tag);
        }
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

async fn apply(conn: &mut SqliteConnection, patch: &Patch) -> Result<()> {
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

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum GrantType {
    Password,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRequest {
    #[serde(rename = "grant_type")]
    _grant_type: GrantType,
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TokenType {
    Jwt,
}

#[derive(Serialize, Deserialize)]
struct TokenSuccess {
    access_token: String,
    token_type: TokenType,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TokenErrorType {
    UnauthorizedClient,
}

#[derive(Serialize, Deserialize)]
struct TokenError {
    error: TokenErrorType,
    error_description: Option<String>,
}

fn hash_password(salt: &[u8], secret: &[u8]) -> String {
    let iterations = NonZeroU32::new(100_000).unwrap();
    const SIZE: usize = ring::digest::SHA256_OUTPUT_LEN;
    let mut hash: [u8; SIZE] = [0u8; SIZE];
    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, iterations, salt, secret, &mut hash);
    base64::encode(&hash)
}

async fn authenticate(
    conn: &AsyncMutex<SqliteConnection>,
    request: &TokenRequest,
    key: &[u8],
    mutex: &AsyncMutex<()>,
    invalid_credential_delay: Duration,
) -> Result<Response<Body>> {
    let _lock = mutex.lock().await;

    let hash = hash_password(request.username.as_bytes(), request.password.as_bytes());

    let found = sqlx::query("SELECT 1 FROM users WHERE name = ?1 AND password_hash = ?2")
        .bind(&request.username)
        .bind(&hash)
        .fetch_optional(conn.lock().await.deref_mut())
        .await?
        .is_some();

    Ok(if found {
        let expiration = (SystemTime::now() + Duration::from_secs(TOKEN_EXPIRATION_SECS))
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let success = serde_json::to_vec(&TokenSuccess {
            access_token: jsonwebtoken::encode(
                &Header::new(Algorithm::HS256),
                &json!({
                    "exp": expiration,
                    "sub": &request.username
                }),
                &EncodingKey::from_secret(key),
            )?,
            token_type: TokenType::Jwt,
        })?;

        response()
            .header(header::CONTENT_LENGTH, success.len())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(success))?
    } else {
        warn!("received invalid credentials; delaying response");

        time::sleep(invalid_credential_delay).await;

        let error = serde_json::to_vec(&TokenError {
            error: TokenErrorType::UnauthorizedClient,
            error_description: None,
        })?;

        response()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::CONTENT_LENGTH, error.len())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(error))?
    })
}

#[derive(Deserialize, Debug)]
struct Authorization {
    sub: String,
}

struct Bearer {
    pub body: String,
}

impl FromStr for Bearer {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let prefix = "Bearer ";
        if s.starts_with(prefix) {
            Ok(Self {
                body: s.chars().skip(prefix.len()).collect(),
            })
        } else {
            Err(anyhow!("expected prefix \"{}\"", prefix))
        }
    }
}

fn authorize(header: Option<Bearer>, key: &[u8]) -> Result<Arc<Authorization>, Rejection> {
    let token = header.map(|h| h.body).ok_or_else(|| {
        HttpError::from_slice(
            StatusCode::UNAUTHORIZED,
            "auth token query parameter or header required",
        )
    })?;

    Ok(Arc::new(
        jsonwebtoken::decode::<Authorization>(
            &token,
            &DecodingKey::from_secret(key),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|e| {
            warn!("received invalid token: {}: {:?}", token, e);

            HttpError::from_slice(StatusCode::UNAUTHORIZED, "invalid token")
        })?
        .claims,
    ))
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
    invalid_credential_delay: Duration,
) -> impl Filter<Extract = (impl Reply,), Error = Infallible> + Clone {
    let mut auth_key = [0u8; 32];
    rand::thread_rng().fill(&mut auth_key);

    let auth_mutex = Arc::new(AsyncMutex::new(()));

    let auth = warp::header::optional::<Bearer>("authorization")
        .and_then(move |header| future::ready(authorize(header, &auth_key)));

    warp::post()
        .and(warp::path("token"))
        .and(warp::body::form::<TokenRequest>())
        .and_then({
            let conn = conn.clone();

            move |body| {
                let conn = conn.clone();
                let auth_mutex = auth_mutex.clone();

                async move { authenticate(&conn, &body, &auth_key, &auth_mutex, invalid_credential_delay).await }
                    .map_err(|e| {
                        warn!("error authorizing: {:?}", e);

                        Rejection::from(HttpError::from(e))
                    })
            }
        })
        .or(warp::get()
            .and(
                warp::path("state")
                    .and(auth)
                    .and(warp::query::<StateQuery>())
                    .and_then({
                        let conn = conn.clone();

                        move |auth, query| {
                            let conn = conn.clone();

                            async move {
                                let state = serde_json::to_vec(&state(conn.lock().await.deref_mut(), &query).await?)?;

                                Ok(response()
                                    .header(header::CONTENT_LENGTH, state.len())
                                    .header(header::CONTENT_TYPE, "application/json")
                                    .body(Body::from(state))?)
                            }
                            .map_err(move |e| {
                                warn!(?auth, "error retrieving state: {:?}", e);

                                Rejection::from(HttpError::from(e))
                            })
                        }
                    })
                    .or(auth
                        .and(warp::path!("image" / String))
                        .and(warp::query::<ImageQuery>())
                        .and_then({
                            let conn = conn.clone();
                            let options = options.clone();

                            move |auth, hash: String, query| {
                                let hash = Arc::<str>::from(hash);

                                {
                                    let hash = hash.clone();
                                    let conn = conn.clone();
                                    let options = options.clone();

                                    async move {
                                        let image = image(&conn, &options.image_directory, &hash, &query).await?;

                                        Ok(response()
                                            .header(header::CONTENT_LENGTH, image.len())
                                            .header(header::CONTENT_TYPE, "application/json")
                                            .body(Body::from(image))?)
                                    }
                                }
                                .map_err(move |e| {
                                    warn!(?auth, "error retrieving image {}: {:?}", hash, e);

                                    Rejection::from(HttpError::from(e))
                                })
                            }
                        }))
                    .or(warp::fs::dir(options.public_directory.clone())),
            )
            .or(
                warp::patch().and(warp::path("tags").and(auth).and(warp::body::json()).and_then({
                    let conn = conn.clone();
                    move |auth, patch: Patch| {
                        let patch = Arc::new(patch);

                        {
                            let patch = patch.clone();
                            let conn = conn.clone();

                            async move {
                                apply(conn.lock().await.deref_mut(), &patch).await?;

                                Ok(String::new())
                            }
                        }
                        .map_err(move |e| {
                            warn!(
                                ?auth,
                                "error applying patch {}: {:?}",
                                serde_json::to_string(patch.as_ref())
                                    .unwrap_or_else(|_| "(unable to serialize patch)".to_string()),
                                e
                            );

                            Rejection::from(HttpError::from(e))
                        })
                    }
                })),
            ))
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
    let routes = routes(conn, options, Duration::from_secs(INVALID_CREDENTIAL_DELAY_SECS));

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

    sync(&conn, &options.image_directory).await?;

    task::spawn({
        let options = options.clone();
        let conn = conn.clone();

        async move {
            time::sleep(Duration::from_secs(SYNC_INTERVAL_SECONDS)).await;

            if let Err(e) = sync(&conn, &options.image_directory).await {
                error!("sync error: {:?}", e);
                process::exit(-1)
            }
        }
    });

    serve(&conn, &options).await
}

#[cfg(test)]
mod test {
    use super::*;
    use image::ImageBuffer;
    use rand::{rngs::StdRng, SeedableRng};
    use std::iter;
    use tempfile::TempDir;

    fn parse_te(s: &str) -> Result<TagExpression> {
        TagExpression::from_str(s).map_err(|e| anyhow!("{:?}", e))
    }

    #[test]
    fn tags() -> Result<()> {
        assert_eq!(TagExpression::Tag("foo".into()), parse_te("foo")?);
        assert_eq!(TagExpression::Tag("foo".into()), parse_te("(foo)")?);
        assert_eq!(TagExpression::Tag("foo".into()), parse_te(r#""foo""#)?);
        assert_eq!(TagExpression::Tag("(foo)".into()), parse_te(r#""(foo)""#)?);
        assert_eq!(TagExpression::Tag("foo bar".into()), parse_te(r#""foo bar""#)?);
        assert_eq!(TagExpression::Tag("foo  bar".into()), parse_te(r#""foo  bar""#)?);
        assert_eq!(
            TagExpression::And(
                Box::new(TagExpression::Tag("foo".into())),
                Box::new(TagExpression::Tag("bar".into()))
            ),
            parse_te("foo and bar")?
        );
        assert_eq!(
            TagExpression::Or(
                Box::new(TagExpression::Tag("foo".into())),
                Box::new(TagExpression::Tag("bar".into()))
            ),
            parse_te("foo or bar")?
        );
        assert_eq!(
            TagExpression::Or(
                Box::new(TagExpression::Tag("foo".into())),
                Box::new(TagExpression::And(
                    Box::new(TagExpression::Tag("bar".into())),
                    Box::new(TagExpression::Tag("baz".into()))
                ))
            ),
            parse_te("foo or (bar and baz)")?
        );
        assert_eq!(
            TagExpression::Or(
                Box::new(TagExpression::Tag("foo".into())),
                Box::new(TagExpression::And(
                    Box::new(TagExpression::Tag("bar".into())),
                    Box::new(TagExpression::Tag("baz".into()))
                ))
            ),
            parse_te("foo or bar and baz")?
        );
        assert_eq!(
            TagExpression::And(
                Box::new(TagExpression::Or(
                    Box::new(TagExpression::Tag("foo".into())),
                    Box::new(TagExpression::Tag("bar".into()))
                )),
                Box::new(TagExpression::Tag("baz".into()))
            ),
            parse_te("(foo or bar) and baz")?
        );
        assert_eq!(
            TagExpression::And(
                Box::new(TagExpression::Or(
                    Box::new(TagExpression::Tag("foo".into())),
                    Box::new(TagExpression::Tag("bar".into()))
                )),
                Box::new(TagExpression::Tag("baz".into()))
            ),
            parse_te("((foo or bar) and baz)")?
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn it_works() -> Result<()> {
        pretty_env_logger::init_timed();

        let mut conn = "sqlite::memory:".parse::<SqliteConnectOptions>()?.connect().await?;

        for statement in schema::DDL_STATEMENTS {
            sqlx::query(statement).execute(&mut conn).await?;
        }

        let user = "Jabberwocky";
        let password = "Bandersnatch";

        {
            let hash = hash_password(user.as_bytes(), password.as_bytes());

            sqlx::query!("INSERT INTO users (name, password_hash) VALUES (?1, ?2)", user, hash,)
                .execute(&mut conn)
                .await?;
        }

        let conn = Arc::new(AsyncMutex::new(conn));

        let tmp_dir = TempDir::new()?;
        let image_directory = tmp_dir.path().to_str().ok_or_else(|| anyhow!("invalid UTF-8"))?;

        let routes = routes(
            &conn,
            &Arc::new(Options {
                address: "0.0.0.0:0".parse()?,
                image_directory: image_directory.to_owned(),
                state_file: "does-not-exist-2a1dad1c-e044-4b95-be08-3a3f72d5ac0a".to_string(),
                public_directory: "does-not-exist-2a1dad1c-e044-4b95-be08-3a3f72d5ac0a".to_string(),
                cert_file: None,
                key_file: None,
            }),
            Duration::from_secs(0),
        );

        let response = warp::test::request()
            .method("POST")
            .path("/token")
            .body("grant_type=password&username=invalid+user&password=invalid+password")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        serde_json::from_slice::<TokenError>(response.body())?;

        let response = warp::test::request()
            .method("POST")
            .path("/token")
            .body(&format!(
                "grant_type=password&username={}&password=invalid+password",
                user
            ))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        serde_json::from_slice::<TokenError>(response.body())?;

        let response = warp::test::request()
            .method("POST")
            .path("/token")
            .body(&format!("grant_type=password&username={}&password={}", user, password))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let token = serde_json::from_slice::<TokenSuccess>(response.body())?.access_token;

        let response = warp::test::request().method("GET").path("/state").reply(&routes).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = warp::test::request()
            .method("GET")
            .path("/state")
            .header("authorization", "Bearer invalid")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = warp::test::request()
            .method("GET")
            .path("/state")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(serde_json::from_slice::<HashMap<String, ImageState>>(response.body())?.is_empty());

        let image_count = 10;
        let image_width = 320;
        let image_height = 240;
        let mut random = StdRng::seed_from_u64(42);

        for number in 1..=image_count {
            let mut path = tmp_dir.path().to_owned();
            path.push(format!("{}.jpg", number));

            task::block_in_place(|| {
                ImageBuffer::from_pixel(
                    image_width,
                    image_height,
                    image::Rgb([random.gen::<u8>(), random.gen(), random.gen()]),
                )
                .save(&path)?;

                let metadata = Metadata::new_from_path(&path)?;
                metadata.set_tag_string(
                    "Exif.Image.DateTimeOriginal",
                    &format!("2021:05:{:02} 00:00:00", number),
                )?;
                metadata.save_to_file(&path)?;

                Ok::<_, Error>(())
            })?;
        }

        sync(&conn, image_directory).await?;

        let response = warp::test::request()
            .method("GET")
            .path("/state")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        let state_response = &response;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<HashMap<String, ImageState>>(response.body())?
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            (1..=image_count)
                .map(|number| Ok((format!("2021-05-{:02}T00:00:00Z", number).parse()?, Vec::new())))
                .collect::<Result<_>>()?
        );

        let response = warp::test::request()
            .method("GET")
            .path("/state?limit=2")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        // Note that the server should give us three results back even though we said "limit=2" -- the third one
        // tells us there are more available and what to specify as the "start" if we want to retrieve them.
        assert_eq!(
            serde_json::from_slice::<HashMap<String, ImageState>>(response.body())?
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            (1..=3)
                .map(|number| Ok((format!("2021-05-{:02}T00:00:00Z", number).parse()?, Vec::new())))
                .collect::<Result<_>>()?
        );

        let response = warp::test::request()
            .method("GET")
            .path("/state?start=2021-05-03T00:00:00Z&limit=2")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<HashMap<String, ImageState>>(response.body())?
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            (3..=5)
                .map(|number| Ok((format!("2021-05-{:02}T00:00:00Z", number).parse()?, Vec::new())))
                .collect::<Result<_>>()?
        );

        let patch = Patch {
            hash: serde_json::from_slice::<HashMap<String, ImageState>>(state_response.body())?
                .into_iter()
                .find(|(_, state)| state.datetime == "2021-05-03T00:00:00Z".parse::<DateTime<Utc>>().unwrap())
                .unwrap()
                .0,
            tag: "foo".into(),
            action: Action::Add,
        };

        let response = warp::test::request()
            .method("PATCH")
            .path("/tags")
            .json(&patch)
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = warp::test::request()
            .method("PATCH")
            .path("/tags")
            .header("authorization", format!("Bearer {}", token))
            .json(&patch)
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = warp::test::request()
            .method("GET")
            .path("/state")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<HashMap<String, ImageState>>(response.body())?
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            (1..=image_count)
                .map(|number| Ok((
                    format!("2021-05-{:02}T00:00:00Z", number).parse()?,
                    if number == 3 { vec!["foo".into()] } else { Vec::new() }
                )))
                .collect::<Result<_>>()?
        );

        let response = warp::test::request()
            .method("GET")
            .path("/state?tags=foo")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<HashMap<String, ImageState>>(response.body())?
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            iter::once(3)
                .map(|number| Ok((format!("2021-05-{:02}T00:00:00Z", number).parse()?, vec!["foo".into()])))
                .collect::<Result<_>>()?
        );

        let patch = Patch {
            hash: serde_json::from_slice::<HashMap<String, ImageState>>(state_response.body())?
                .into_iter()
                .find(|(_, state)| state.datetime == "2021-05-02T00:00:00Z".parse::<DateTime<Utc>>().unwrap())
                .unwrap()
                .0,
            tag: "foo".into(),
            action: Action::Add,
        };

        let response = warp::test::request()
            .method("PATCH")
            .path("/tags")
            .header("authorization", format!("Bearer {}", token))
            .json(&patch)
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let patch = Patch {
            hash: serde_json::from_slice::<HashMap<String, ImageState>>(state_response.body())?
                .into_iter()
                .find(|(_, state)| state.datetime == "2021-05-03T00:00:00Z".parse::<DateTime<Utc>>().unwrap())
                .unwrap()
                .0,
            tag: "bar".into(),
            action: Action::Add,
        };

        let response = warp::test::request()
            .method("PATCH")
            .path("/tags")
            .header("authorization", format!("Bearer {}", token))
            .json(&patch)
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = warp::test::request()
            .method("GET")
            .path("/state?tags=foo")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<HashMap<String, ImageState>>(response.body())?
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            (2..=3)
                .map(|number| Ok((
                    format!("2021-05-{:02}T00:00:00Z", number).parse()?,
                    if number == 3 {
                        vec!["foo".into(), "bar".into()]
                    } else {
                        vec!["foo".into()]
                    }
                )))
                .collect::<Result<_>>()?
        );

        let response = warp::test::request()
            .method("GET")
            .path("/state?tags=foo and bar")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<HashMap<String, ImageState>>(response.body())?
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            iter::once(3)
                .map(|number| Ok((
                    format!("2021-05-{:02}T00:00:00Z", number).parse()?,
                    vec!["foo".into(), "bar".into()]
                )))
                .collect::<Result<_>>()?
        );

        // todo: test more scenarios and features

        Ok(())
    }
}
