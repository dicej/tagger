#![deny(warnings)]

use anyhow::{anyhow, Error, Result};
use chrono::{DateTime, Datelike, Utc};
use futures::{
    future::{BoxFuture, FutureExt, TryFutureExt},
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
use lazy_static::lazy_static;
use rand::Rng;
use regex::Regex;
use rexiv2::Metadata;
use serde_derive::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{
    query::Query,
    sqlite::{SqliteArguments, SqliteConnectOptions},
    ConnectOptions, Connection, Row, Sqlite, SqliteConnection,
};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    fmt::Write as _,
    io::{Read, Seek, SeekFrom, Write},
    net::SocketAddrV4,
    num::NonZeroU32,
    ops::DerefMut,
    panic::{self, AssertUnwindSafe},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use structopt::StructOpt;
use tagger_shared::{
    tag_expression::{Tag, TagExpression},
    Action, ImageData, ImageQuery, ImagesQuery, ImagesResponse, Patch, TagsQuery, TagsResponse,
    ThumbnailSize, TokenError, TokenErrorType, TokenRequest, TokenSuccess, TokenType,
};
use tempfile::NamedTempFile;
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex as AsyncMutex,
    task, time,
};
use tracing::{info, warn};
use warp::{Filter, Rejection, Reply};
use warp_util::HttpError;

mod warp_util;

const SMALL_BOUNDS: (u32, u32) = (480, 320);

const LARGE_BOUNDS: (u32, u32) = (1920, 1280);

const JPEG_QUALITY: u8 = 90;

const INVALID_CREDENTIAL_DELAY_SECS: u64 = 5;

const TOKEN_EXPIRATION_SECS: u64 = 24 * 60 * 60;

const DEFAULT_LIMIT: u32 = 1000;

pub async fn open(state_file: &str) -> Result<SqliteConnection> {
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

async fn write<P: AsRef<Path>>(path: P, buffer: &[u8]) -> Result<()> {
    File::create(path.as_ref())
        .await?
        .write_all(&buffer)
        .await?;

    Ok(())
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

#[derive(Debug)]
struct ExifData {
    datetime: DateTime<Utc>,
    mp4_offset: Option<i64>,
}

fn exif_data(image: &[u8]) -> Result<ExifData> {
    let metadata = Metadata::new_from_buffer(image)?;

    let datetime = metadata
        .get_tag_string("Exif.Image.DateTimeOriginal")
        .or_else(|_| metadata.get_tag_string("Exif.Image.DateTime"))?;

    lazy_static! {
        static ref DATE_TIME_PATTERN: Regex =
            Regex::new(r"(\d{4}):(\d{2}):(\d{2}) (\d{2}):(\d{2}):(\d{2})").unwrap();
    };

    Ok(ExifData {
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

        mp4_offset: if metadata
            .get_tag_string("Xmp.Container.Directory[2]/Container:Item/Item:Mime")
            .ok()
            .as_deref()
            == Some("video/mp4")
        {
            metadata
                .get_tag_string("Xmp.Container.Directory[2]/Container:Item/Item:Length")
                .ok()
                .and_then(|offset| offset.parse().ok())
        } else {
            None
        },
    })
}

fn find_new<'a>(
    conn: &'a AsyncMutex<SqliteConnection>,
    root: &'a str,
    result: &'a mut Vec<(String, ExifData)>,
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

                    if lowercase.ends_with(".jpg") || lowercase.ends_with(".jpeg") {
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
                            match exif_data(&content(&path).await?) {
                                Ok(data) => result.push((stripped.to_string(), data)),
                                Err(e) => {
                                    warn!("unable to get metadata for {}: {:?}", lowercase, e)
                                }
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

pub async fn sync(conn: &AsyncMutex<SqliteConnection>, image_dir: &str) -> Result<()> {
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

    for (path, data) in new {
        let hash = hash(&content([image_dir, &path].iter().collect::<PathBuf>()).await?);

        info!("insert {} (hash {}; data {:?})", path, hash, data);

        conn.lock()
            .await
            .transaction(|conn| {
                async move {
                    sqlx::query!("INSERT INTO paths (path, hash) VALUES (?1, ?2)", path, hash)
                        .execute(&mut *conn)
                        .await?;

                    let year = data.datetime.year();
                    let month = data.datetime.month();
                    let datetime = data.datetime.to_string();
                    let mp4_offset = data.mp4_offset;

                    sqlx::query!(
                        "INSERT OR IGNORE INTO images (hash, datetime, mp4_offset) VALUES (?1, ?2, ?3)",
                        hash,
                        datetime,
                        mp4_offset
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

                        if sqlx::query!("SELECT 1 as x FROM paths WHERE hash = ?1", row.hash)
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

fn append_filter_clause(buffer: &mut String, expression: &TagExpression) {
    match expression {
        TagExpression::Tag(tag) => buffer.push_str(if tag.category.is_some() {
            "EXISTS (SELECT * FROM tags WHERE hash = i.hash AND category = ? AND tag = ?)"
        } else {
            "EXISTS (SELECT * FROM tags WHERE hash = i.hash AND category IS NULL AND tag = ?)"
        }),
        TagExpression::And(a, b) => {
            buffer.push('(');
            append_filter_clause(buffer, a);
            buffer.push_str(" AND ");
            append_filter_clause(buffer, b);
            buffer.push(')');
        }
        TagExpression::Or(a, b) => {
            buffer.push('(');
            append_filter_clause(buffer, a);
            buffer.push_str(" OR ");
            append_filter_clause(buffer, b);
            buffer.push(')');
        }
    }
}

fn bind_filter_clause<'a>(
    expression: &TagExpression,
    select: Query<'a, Sqlite, SqliteArguments<'a>>,
) -> Query<'a, Sqlite, SqliteArguments<'a>> {
    expression.fold_tags(select, |mut select, category, tag| {
        if let Some(category) = category {
            select = select.bind(category.to_owned())
        }
        select.bind(tag.to_owned())
    })
}

fn build_images_query<'a>(
    buffer: &'a mut String,
    count: bool,
    query: &ImagesQuery,
    limit: u32,
) -> Query<'a, Sqlite, SqliteArguments<'a>> {
    write!(
        buffer,
        "SELECT {} FROM images i WHERE {}{}{}",
        if count {
            if query.start.is_some() {
                "sum(CASE WHEN datetime >= ? THEN 1 ELSE 0 END), count(*)"
            } else {
                "0, count(*)"
            }
        } else {
            "hash, datetime, (SELECT group_concat(CASE WHEN category IS NULL THEN tag ELSE category || ':' || tag END)
             FROM tags WHERE hash = i.hash)"
        },
        if let Some(filter) = &query.filter {
            let mut buffer = String::new();
            append_filter_clause(&mut buffer, filter);
            buffer
        } else {
            "1".into()
        },
        if query.start.is_some() && !count {
            " AND datetime < ?"
        } else {
            ""
        },
        if count { "" } else { " ORDER BY datetime DESC LIMIT ?" }
    )
    .unwrap();

    let mut select = sqlx::query(buffer);

    if count {
        if let Some(start) = &query.start {
            select = select.bind(start.to_string());
        }
    }

    if let Some(filter) = &query.filter {
        select = bind_filter_clause(filter, select);
    }

    if count {
        select
    } else {
        if let Some(start) = &query.start {
            select = select.bind(start.to_string());
        }
        select.bind(limit)
    }
}

async fn images(conn: &mut SqliteConnection, query: &ImagesQuery) -> Result<ImagesResponse> {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);

    let mut images = HashMap::new();

    {
        let mut buffer = String::new();
        let mut rows = build_images_query(&mut buffer, false, query, limit).fetch(&mut *conn);

        while let Some(row) = rows.try_next().await? {
            images.insert(
                row.get(0),
                ImageData {
                    datetime: row.get::<&str, _>(1).parse()?,
                    tags: row
                        .get::<&str, _>(2)
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(Tag::from_str)
                        .collect::<Result<HashSet<_>>>()?,
                },
            );
        }
    }

    let (start, total) = {
        let mut buffer = String::new();
        let row = build_images_query(&mut buffer, true, query, limit)
            .fetch_one(conn)
            .await?;

        (row.get::<u32, _>(0), row.get::<u32, _>(1))
    };

    Ok(ImagesResponse {
        start,
        total,
        images,
    })
}

async fn apply(
    auth: Option<&Authorization>,
    conn: &mut SqliteConnection,
    patches: &[Patch],
) -> Result<Response<Body>> {
    if auth.is_none() {
        return Ok(response()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::empty())?);
    }

    for patch in patches {
        if let Some(category) = &patch.tag.category {
            if let Some(row) =
                sqlx::query!("SELECT immutable FROM categories WHERE name = ?1", category)
                    .fetch_optional(&mut *conn)
                    .await?
            {
                if row.immutable != 0 {
                    return Ok(response()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Body::empty())?);
                }
            }
        }

        match patch.action {
            Action::Add => {
                sqlx::query!(
                    "INSERT INTO tags (hash, tag, category) VALUES (?1, ?2, ?3)",
                    patch.hash,
                    patch.tag.value,
                    patch.tag.category
                )
                .execute(&mut *conn)
                .await?;
            }
            Action::Remove => {
                if let Some(category) = &patch.tag.category {
                    sqlx::query!(
                        "DELETE FROM tags WHERE hash = ?1 AND tag = ?2 AND category = ?3",
                        patch.hash,
                        patch.tag.value,
                        category
                    )
                    .execute(&mut *conn)
                    .await?;
                } else {
                    sqlx::query!(
                        "DELETE FROM tags WHERE hash = ?1 AND tag = ?2 AND category IS NULL",
                        patch.hash,
                        patch.tag.value
                    )
                    .execute(&mut *conn)
                    .await?;
                }
            }
        }
    }

    Ok(response().body(Body::empty())?)
}

async fn full_size_image(
    conn: &mut SqliteConnection,
    image_dir: &str,
    path: &str,
) -> Result<Vec<u8>> {
    if let Some(row) = sqlx::query!("SELECT path FROM paths WHERE hash = ?1 LIMIT 1", path)
        .fetch_optional(conn)
        .await?
    {
        content([image_dir, &row.path].iter().collect::<PathBuf>()).await
    } else {
        Err(HttpError::from_slice(StatusCode::NOT_FOUND, "not found").into())
    }
}

fn bound(
    (native_width, native_height): (u32, u32),
    (bound_width, bound_height): (u32, u32),
) -> (u32, u32) {
    if native_width * bound_height > bound_width * native_height {
        (bound_width, (native_height * bound_width) / native_width)
    } else {
        ((native_width * bound_height) / native_height, bound_height)
    }
}

async fn thumbnail(
    conn: &AsyncMutex<SqliteConnection>,
    image_dir: &str,
    thumbnail_dir: &str,
    size: ThumbnailSize,
    path: &str,
) -> Result<Vec<u8>> {
    let filename = format!("{}/{}/{}.jpg", thumbnail_dir, size, path);

    let result = content(&filename).await;

    if let Ok(result) = result {
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

            let metadata = Metadata::new_from_buffer(&image)
                .map(|metadata| {
                    let orientation = metadata.get_orientation();
                    metadata.clear();
                    metadata.set_orientation(orientation);
                    metadata
                })
                .ok();

            if let Some(metadata) = &metadata {
                task::block_in_place(|| {
                    let mut file = NamedTempFile::new()?;

                    file.write_all(&encoded)?;

                    metadata.save_to_file(file.path())?;

                    file.seek(SeekFrom::Start(0))?;

                    encoded.clear();

                    file.read_to_end(&mut encoded)?;

                    Ok::<_, Error>(())
                })?;
            }

            Ok::<_, Error>(encoded)
        };

        let resized = resize(match size {
            ThumbnailSize::Small => SMALL_BOUNDS,
            ThumbnailSize::Large => LARGE_BOUNDS,
        })?;

        if let Some(parent) = Path::new(&filename).parent() {
            let _ = fs::create_dir(parent).await;
        }

        write(&filename, &resized).await?;

        Ok(resized)
    }
}

async fn image(
    conn: &AsyncMutex<SqliteConnection>,
    image_dir: &str,
    thumbnail_dir: &str,
    path: &str,
    query: &ImageQuery,
) -> Result<Response<Body>> {
    let image = if let Some(size) = query.size {
        thumbnail(conn, image_dir, thumbnail_dir, size, path).await
    } else {
        full_size_image(conn.lock().await.deref_mut(), image_dir, path).await
    }?;

    Ok(response()
        .header(header::CONTENT_LENGTH, image.len())
        .header(header::CONTENT_TYPE, "image/jpeg")
        .body(Body::from(image))?)
}

fn entry<'a>(
    response: &'a mut TagsResponse,
    parents: &HashMap<String, String>,
    category: &str,
) -> &'a mut TagsResponse {
    if let Some(parent) = parents.get(category) {
        entry(response, parents, parent)
    } else {
        response
    }
    .categories
    .entry(category.to_owned())
    .or_insert_with(TagsResponse::default)
}

async fn tags(conn: &mut SqliteConnection, query: &TagsQuery) -> Result<TagsResponse> {
    let select = format!(
        "SELECT (SELECT parent from categories where name = t.category), \
                (SELECT immutable from categories where name = t.category), \
                t.category, \
                t.tag, \
                count(i.hash) \
         FROM images i \
         LEFT JOIN tags t \
         ON i.hash = t.hash \
         WHERE {} AND t.hash IS NOT NULL \
         GROUP BY t.category, t.tag",
        if let Some(filter) = &query.filter {
            let mut buffer = String::new();
            append_filter_clause(&mut buffer, filter);
            buffer
        } else {
            "1".into()
        }
    );

    let mut select = sqlx::query(&select);

    if let Some(filter) = &query.filter {
        select = bind_filter_clause(filter, select);
    }

    let mut parents = HashMap::new();
    let mut category_tags = HashMap::new();
    let mut category_immutable = HashMap::new();
    let mut tags = HashMap::new();

    let mut rows = select.fetch(&mut *conn);

    while let Some(row) = rows.try_next().await? {
        let tag = row.get(3);
        let count = row.get(4);

        if let Some(category) = row.get::<Option<String>, _>(2) {
            if let Some(immutable) = row.get::<Option<bool>, _>(1) {
                category_immutable.insert(category.clone(), immutable);
            }

            if let Some(parent) = row.get::<Option<String>, _>(0) {
                parents.insert(category.clone(), parent);
            }

            category_tags
                .entry(category)
                .or_insert_with(HashMap::new)
                .insert(tag, count);
        } else {
            tags.insert(tag, count);
        }
    }

    let mut response = TagsResponse {
        immutable: None,
        categories: HashMap::new(),
        tags,
    };

    for (category, tags) in category_tags {
        let entry = entry(&mut response, &parents, &category);

        entry.tags = tags;
        entry.immutable = category_immutable.get(&category).cloned();
    }

    Ok(response)
}

pub fn hash_password(salt: &[u8], secret: &[u8]) -> String {
    let iterations = NonZeroU32::new(100_000).unwrap();
    const SIZE: usize = ring::digest::SHA256_OUTPUT_LEN;
    let mut hash: [u8; SIZE] = [0u8; SIZE];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        secret,
        &mut hash,
    );
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

    let found = sqlx::query!(
        "SELECT 1 as x FROM users WHERE name = ?1 AND password_hash = ?2",
        request.username,
        hash
    )
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

fn authorize(token: &str, key: &[u8]) -> Result<Arc<Authorization>, HttpError> {
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

fn maybe_wrap_filter(filter: &mut Option<TagExpression>, auth: &Option<Arc<Authorization>>) {
    if auth.is_none() {
        let tag = TagExpression::Tag(Tag {
            category: None,
            value: "public".into(),
        });

        if let Some(inner) = filter.take() {
            *filter = Some(TagExpression::And(Box::new(inner), Box::new(tag)));
        } else {
            *filter = Some(tag);
        }
    }
}

fn response() -> response::Builder {
    Response::builder()
}

fn routes(
    conn: &Arc<AsyncMutex<SqliteConnection>>,
    options: &Arc<Options>,
    invalid_credential_delay: Duration,
) -> impl Filter<Extract = (impl Reply,), Error = Infallible> + Clone {
    let mut auth_key = [0u8; 32];
    rand::thread_rng().fill(&mut auth_key);

    let auth_mutex = Arc::new(AsyncMutex::new(()));

    let auth = warp::header::optional::<Bearer>("authorization").and_then(
        move |header: Option<Bearer>| async move {
            Ok::<_, Rejection>(if let Some(token) = header.map(|h| h.body) {
                Some(authorize(&token, &auth_key)?)
            } else {
                None
            })
        },
    );

    warp::post()
        .and(warp::path("token"))
        .and(warp::body::form::<TokenRequest>())
        .and_then({
            let conn = conn.clone();

            move |body| {
                let conn = conn.clone();
                let auth_mutex = auth_mutex.clone();

                async move {
                    authenticate(
                        &conn,
                        &body,
                        &auth_key,
                        &auth_mutex,
                        invalid_credential_delay,
                    )
                    .await
                }
                .map_err(|e| {
                    warn!("error authorizing: {:?}", e);

                    Rejection::from(HttpError::from(e))
                })
            }
        })
        .or(warp::get()
            .and(
                warp::path("images")
                    .and(auth)
                    .and(warp::query::<ImagesQuery>())
                    .and_then({
                        let conn = conn.clone();

                        move |auth, mut query: ImagesQuery| {
                            maybe_wrap_filter(&mut query.filter, &auth);

                            let conn = conn.clone();

                            async move {
                                let state = serde_json::to_vec(
                                    &images(conn.lock().await.deref_mut(), &query).await?,
                                )?;

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
                    .or(warp::path("tags")
                        .and(auth)
                        .and(warp::query::<TagsQuery>())
                        .and_then({
                            let conn = conn.clone();

                            move |auth, mut query: TagsQuery| {
                                maybe_wrap_filter(&mut query.filter, &auth);

                                let conn = conn.clone();

                                async move {
                                    let tags = serde_json::to_vec(
                                        &tags(conn.lock().await.deref_mut(), &query).await?,
                                    )?;

                                    Ok(response()
                                        .header(header::CONTENT_LENGTH, tags.len())
                                        .header(header::CONTENT_TYPE, "application/json")
                                        .body(Body::from(tags))?)
                                }
                                .map_err(move |e| {
                                    warn!(?auth, "error retrieving tags: {:?}", e);

                                    Rejection::from(HttpError::from(e))
                                })
                            }
                        }))
                    .or(warp::path!("image" / String)
                        .and(auth)
                        .and(warp::query::<ImageQuery>())
                        .and_then({
                            let conn = conn.clone();
                            let options = options.clone();

                            move |hash: String, auth: Option<Arc<_>>, query| {
                                let hash = Arc::<str>::from(hash);

                                {
                                    let hash = hash.clone();
                                    let conn = conn.clone();
                                    let options = options.clone();

                                    async move {
                                        image(
                                            &conn,
                                            &options.image_directory,
                                            &options.thumbnail_directory,
                                            &hash,
                                            &query,
                                        )
                                        .await
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
            .or(warp::patch().and(
                warp::path("tags")
                    .and(auth)
                    .and(warp::body::json())
                    .and_then({
                        let conn = conn.clone();
                        move |auth: Option<Arc<_>>, patches: Vec<Patch>| {
                            let patches = Arc::new(patches);

                            {
                                let auth = auth.clone();
                                let patches = patches.clone();
                                let conn = conn.clone();

                                async move {
                                    apply(auth.as_deref(), conn.lock().await.deref_mut(), &patches)
                                        .await
                                }
                            }
                            .map_err(move |e| {
                                warn!(
                                    ?auth,
                                    "error applying patch {}: {:?}",
                                    serde_json::to_string(patches.as_ref()).unwrap_or_else(|_| {
                                        "(unable to serialize patches)".to_string()
                                    }),
                                    e
                                );

                                Rejection::from(HttpError::from(e))
                            })
                        }
                    }),
            )))
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

pub async fn serve(conn: &Arc<AsyncMutex<SqliteConnection>>, options: &Arc<Options>) -> Result<()> {
    let routes = routes(
        conn,
        options,
        Duration::from_secs(INVALID_CREDENTIAL_DELAY_SECS),
    );

    let (address, future) = if let (Some(cert), Some(key)) = (&options.cert_file, &options.key_file)
    {
        let server = warp::serve(routes).tls().cert_path(cert).key_path(key);

        // As of this writing, warp::TlsServer does not have a try_bind_ephemeral method, so we must catch panics
        // explicitly.
        let (address, future) = catch_unwind(AssertUnwindSafe(move || {
            server.bind_ephemeral(options.address)
        }))?;

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
pub struct Options {
    /// Address to which to bind
    #[structopt(long)]
    pub address: SocketAddrV4,

    /// Directory containing image files
    #[structopt(long)]
    pub image_directory: String,

    /// Directory in which to cache generated thumbnail images
    #[structopt(long)]
    pub thumbnail_directory: String,

    /// SQLite database to create or reuse
    #[structopt(long)]
    pub state_file: String,

    /// Directory containing static resources
    #[structopt(long)]
    pub public_directory: String,

    /// File containing TLS certificate to use
    #[structopt(long)]
    pub cert_file: Option<String>,

    /// File containing TLS key to use
    #[structopt(long)]
    pub key_file: Option<String>,
}

#[cfg(test)]
mod test {
    use super::*;
    use image::{ImageBuffer, Rgb};
    use maplit::{hashmap, hashset};
    use rand::{rngs::StdRng, SeedableRng};
    use std::iter;
    use tempfile::TempDir;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn it_works() -> Result<()> {
        pretty_env_logger::init_timed();

        let mut conn = "sqlite::memory:"
            .parse::<SqliteConnectOptions>()?
            .connect()
            .await?;

        for statement in schema::DDL_STATEMENTS {
            sqlx::query(statement).execute(&mut conn).await?;
        }

        let user = "Jabberwocky";
        let password = "Bandersnatch";

        {
            let hash = hash_password(user.as_bytes(), password.as_bytes());

            sqlx::query!(
                "INSERT INTO users (name, password_hash) VALUES (?1, ?2)",
                user,
                hash,
            )
            .execute(&mut conn)
            .await?;
        }

        let conn = Arc::new(AsyncMutex::new(conn));

        let image_tmp_dir = TempDir::new()?;
        let image_dir = image_tmp_dir
            .path()
            .to_str()
            .ok_or_else(|| anyhow!("invalid UTF-8"))?;

        let thumbnail_tmp_dir = TempDir::new()?;
        let thumbnail_dir = thumbnail_tmp_dir
            .path()
            .to_str()
            .ok_or_else(|| anyhow!("invalid UTF-8"))?;

        let routes = routes(
            &conn,
            &Arc::new(Options {
                address: "0.0.0.0:0".parse()?,
                image_directory: image_dir.to_owned(),
                thumbnail_directory: thumbnail_dir.to_owned(),
                state_file: "does-not-exist-2a1dad1c-e044-4b95-be08-3a3f72d5ac0a".to_string(),
                public_directory: "does-not-exist-2a1dad1c-e044-4b95-be08-3a3f72d5ac0a".to_string(),
                cert_file: None,
                key_file: None,
            }),
            Duration::from_secs(0),
        );

        // Invalid user and password should yield `UNAUTHORIZED` from /token.

        let response = warp::test::request()
            .method("POST")
            .path("/token")
            .body("grant_type=password&username=invalid+user&password=invalid+password")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        serde_json::from_slice::<TokenError>(response.body())?;

        // Valid user and invalid password should yield `UNAUTHORIZED` from /token.

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

        // Valid user and password should yield `OK` from /token.

        let response = warp::test::request()
            .method("POST")
            .path("/token")
            .body(&format!(
                "grant_type=password&username={}&password={}",
                user, password
            ))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let token = serde_json::from_slice::<TokenSuccess>(response.body())?.access_token;

        // Invalid token should yield `UNAUTHORIZED` from /images.

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .header("authorization", "Bearer invalid")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Valid token should yield `OK` from /images.

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        // The response from /images should be empty at this point since we haven't added any images yet.

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 0);
        assert!(response.images.is_empty());

        // Let's add some images to `image_tmp_dir` and call `sync` to add them to the database.

        let image_count = 10_u32;
        let image_width = 480;
        let image_height = 320;
        let mut random = StdRng::seed_from_u64(42);
        let colors = (1..=image_count)
            .map(|number| {
                (
                    number,
                    Rgb([random.gen::<u8>(), random.gen(), random.gen()]),
                )
            })
            .collect::<HashMap<_, _>>();

        for (&number, &color) in &colors {
            let mut path = image_tmp_dir.path().to_owned();
            path.push(format!("{}.jpg", number));

            task::block_in_place(|| {
                ImageBuffer::from_pixel(image_width, image_height, color).save(&path)?;

                let metadata = Metadata::new_from_path(&path)?;
                metadata.set_tag_string(
                    "Exif.Image.DateTimeOriginal",
                    &format!("2021:{:02}:01 00:00:00", number),
                )?;
                metadata.save_to_file(&path)?;

                Ok::<_, Error>(())
            })?;
        }

        sync(&conn, image_dir).await?;

        // GET /images with no authorization header should yield `OK` with an empty body since no images have been
        // tagged "public" yet.

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 0);
        assert_eq!(response.images.len(), 0);

        // GET /images with no query parameters should yield all the images.

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, image_count);

        let hashes = response
            .images
            .iter()
            .map(|(hash, state)| (state.datetime, hash.clone()))
            .collect::<HashMap<_, _>>();

        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            (1..=image_count)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    hashset!["year:2021".parse()?, format!("month:{}", number).parse()?]
                )))
                .collect::<Result<_>>()?
        );

        // GET /images with a "limit" parameter should yield the most recent images.

        let response = warp::test::request()
            .method("GET")
            .path("/images?limit=2")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, image_count);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            ((image_count - 1)..=image_count)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    hashset!["year:2021".parse()?, format!("month:{}", number).parse()?]
                )))
                .collect::<Result<_>>()?
        );

        // GET /images with "start" and "limit" parameters should yield images from the specified interval.

        let response = warp::test::request()
            .method("GET")
            .path("/images?start=2021-04-01T00:00:00Z&limit=2")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 7);
        assert_eq!(response.total, image_count);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            (2..=3)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    hashset!["year:2021".parse()?, format!("month:{}", number).parse()?]
                )))
                .collect::<Result<_>>()?
        );

        // Let's add the "foo" tag to the third image.

        let patches = vec![Patch {
            hash: hashes
                .get(&"2021-03-01T00:00:00Z".parse()?)
                .unwrap()
                .clone(),
            tag: "foo".parse()?,
            action: Action::Add,
        }];

        // PATCH /tags with no authorization header should yield `UNAUTHORIZED`

        let response = warp::test::request()
            .method("PATCH")
            .path("/tags")
            .json(&patches)
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // A PATCH /tags with an invalid authorization header should yield `UNAUTHORIZED`

        let response = warp::test::request()
            .method("PATCH")
            .path("/tags")
            .header("authorization", "Bearer invalid")
            .json(&patches)
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // PATCH /tags referencing an immutable category should yield `UNAUTHORIZED`

        for &(category, tag, action) in &[
            ("year", "2021", Action::Remove),
            ("year", "2022", Action::Add),
            ("month", "3", Action::Remove),
            ("month", "4", Action::Add),
        ] {
            let response = warp::test::request()
                .method("PATCH")
                .path("/tags")
                .header("authorization", format!("Bearer {}", token))
                .json(&vec![Patch {
                    hash: hashes
                        .get(&"2021-03-01T00:00:00Z".parse()?)
                        .unwrap()
                        .clone(),
                    tag: Tag {
                        value: tag.into(),
                        category: Some(category.into()),
                    },
                    action,
                }])
                .reply(&routes)
                .await;

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        // PATCH /tags with a valid authorization header should yield `OK`

        let response = warp::test::request()
            .method("PATCH")
            .path("/tags")
            .header("authorization", format!("Bearer {}", token))
            .json(&patches)
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        // Now GET /images should report the tag we added via the above patch.

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, image_count);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            (1..=image_count)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    if number == 3 {
                        hashset![
                            "year:2021".parse()?,
                            format!("month:{}", number).parse()?,
                            "foo".parse()?
                        ]
                    } else {
                        hashset!["year:2021".parse()?, format!("month:{}", number).parse()?]
                    }
                )))
                .collect::<Result<_>>()?
        );

        // GET /tags with no authorization header should yield no tags since no images have been tagged "public"
        // yet.

        let response = warp::test::request()
            .method("GET")
            .path("/tags")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<TagsResponse>(response.body())?,
            TagsResponse::default()
        );

        // GET /tags should yield the new tag with an image count of one.

        let response = warp::test::request()
            .method("GET")
            .path("/tags")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<TagsResponse>(response.body())?,
            TagsResponse {
                immutable: None,
                categories: hashmap![
                    "year".into() => TagsResponse {
                        immutable: Some(true),
                        categories: hashmap![
                            "month".into() => TagsResponse {
                                immutable: Some(true),
                                categories: HashMap::new(),
                                tags: (1..=image_count).map(|n| (format!("{}", n), 1)).collect()
                            }
                        ],
                        tags: hashmap![
                            "2021".into() => 10
                        ]
                    }
                ],
                tags: hashmap![
                    "foo".into() => 1
                ]
            }
        );

        // GET /images with a "filter" parameter should yield only the image(s) matching that expression.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=foo")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 1);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            iter::once(3)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    hashset![
                        "year:2021".parse()?,
                        format!("month:{}", number).parse()?,
                        "foo".parse()?
                    ]
                )))
                .collect::<Result<_>>()?
        );

        // Let's add the "foo" tag to the second image.

        let patches = vec![Patch {
            hash: hashes
                .get(&"2021-02-01T00:00:00Z".parse()?)
                .unwrap()
                .clone(),
            tag: "foo".parse()?,
            action: Action::Add,
        }];

        let response = warp::test::request()
            .method("PATCH")
            .path("/tags")
            .header("authorization", format!("Bearer {}", token))
            .json(&patches)
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        // Let's add the "bar" tag to the third and fourth images.

        let response = warp::test::request()
            .method("PATCH")
            .path("/tags")
            .header("authorization", format!("Bearer {}", token))
            .json(
                &(3..=4)
                    .map(|number| {
                        Ok(Patch {
                            hash: hashes
                                .get(&format!("2021-{:02}-01T00:00:00Z", number).parse()?)
                                .unwrap()
                                .clone(),
                            tag: "bar".parse()?,
                            action: Action::Add,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            )
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        // GET /tags should yield the newly-applied tags.

        let response = warp::test::request()
            .method("GET")
            .path("/tags")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<TagsResponse>(response.body())?,
            TagsResponse {
                immutable: None,
                categories: hashmap![
                    "year".into() => TagsResponse {
                        immutable: Some(true),
                        categories: hashmap![
                            "month".into() => TagsResponse {
                                immutable: Some(true),
                                categories: HashMap::new(),
                                tags: (1..=image_count).map(|n| (format!("{}", n), 1)).collect()
                            }
                        ],
                        tags: hashmap![
                            "2021".into() => 10
                        ]
                    }
                ],
                tags: hashmap![
                    "foo".into() => 2,
                    "bar".into() => 2,
                ]
            }
        );

        // GET /images?filter=foo should yield all images with that tag.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=foo")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 2);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            (2..=3)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    if number == 3 {
                        hashset![
                            "year:2021".parse()?,
                            format!("month:{}", number).parse()?,
                            "foo".parse()?,
                            "bar".parse()?
                        ]
                    } else {
                        hashset![
                            "year:2021".parse()?,
                            format!("month:{}", number).parse()?,
                            "foo".parse()?
                        ]
                    }
                )))
                .collect::<Result<_>>()?
        );

        // GET /tags?filter=foo should yield the tags and counts applied to images with that tag.

        let response = warp::test::request()
            .method("GET")
            .path("/tags?filter=foo")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<TagsResponse>(response.body())?,
            TagsResponse {
                immutable: None,
                categories: hashmap![
                    "year".into() => TagsResponse {
                        immutable: Some(true),
                        categories: hashmap![
                            "month".into() => TagsResponse {
                                immutable: Some(true),
                                categories: HashMap::new(),
                                tags: (2..=3).map(|n| (format!("{}", n), 1)).collect()
                            }
                        ],
                        tags: hashmap![
                            "2021".into() => 2
                        ]
                    }
                ],
                tags: hashmap![
                    "foo".into() => 2,
                    "bar".into() => 1,
                ]
            }
        );

        // GET /images?filter=bar should yield all images with that tag.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=bar")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 2);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            (3..=4)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    if number == 3 {
                        hashset![
                            "year:2021".parse()?,
                            format!("month:{}", number).parse()?,
                            "foo".parse()?,
                            "bar".parse()?
                        ]
                    } else {
                        hashset![
                            "year:2021".parse()?,
                            format!("month:{}", number).parse()?,
                            "bar".parse()?
                        ]
                    }
                )))
                .collect::<Result<_>>()?
        );

        // GET /tags?filter=bar should yield the tags and counts applied to images with that tag.

        let response = warp::test::request()
            .method("GET")
            .path("/tags?filter=bar")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<TagsResponse>(response.body())?,
            TagsResponse {
                immutable: None,
                categories: hashmap![
                    "year".into() => TagsResponse {
                        immutable: Some(true),
                        categories: hashmap![
                            "month".into() => TagsResponse {
                                immutable: Some(true),
                                categories: HashMap::new(),
                                tags: (3..=4).map(|n| (format!("{}", n), 1)).collect()
                            }
                        ],
                        tags: hashmap![
                            "2021".into() => 2
                        ]
                    }
                ],
                tags: hashmap![
                    "foo".into() => 1,
                    "bar".into() => 2,
                ]
            }
        );

        // GET "/images?filter=foo and bar" should yield only the image that has both tags.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=foo%20and%20bar")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 1);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            iter::once(3)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    hashset![
                        "year:2021".parse()?,
                        format!("month:{}", number).parse()?,
                        "foo".parse()?,
                        "bar".parse()?
                    ]
                )))
                .collect::<Result<_>>()?
        );

        // GET "/tags?filter=foo and bar" should yield the tags and counts applied to images with both tags.

        let response = warp::test::request()
            .method("GET")
            .path("/tags?filter=foo%20and%20bar")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<TagsResponse>(response.body())?,
            TagsResponse {
                immutable: None,
                categories: hashmap![
                    "year".into() => TagsResponse {
                        immutable: Some(true),
                        categories: hashmap![
                            "month".into() => TagsResponse {
                                immutable: Some(true),
                                categories: HashMap::new(),
                                tags: hashmap![
                                    "3".into() => 1
                                ]
                            }
                        ],
                        tags: hashmap![
                            "2021".into() => 1
                        ]
                    }
                ],
                tags: hashmap![
                    "foo".into() => 1,
                    "bar".into() => 1
                ]
            }
        );

        // GET "/images?filter=foo or bar" should yield the images with either tag.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=foo%20or%20bar")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 3);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            (2..=4)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    match number {
                        4 => hashset![
                            "year:2021".parse()?,
                            format!("month:{}", number).parse()?,
                            "bar".parse()?
                        ],
                        3 => hashset![
                            "year:2021".parse()?,
                            format!("month:{}", number).parse()?,
                            "foo".parse()?,
                            "bar".parse()?
                        ],
                        2 => hashset![
                            "year:2021".parse()?,
                            format!("month:{}", number).parse()?,
                            "foo".parse()?
                        ],
                        _ => unreachable!(),
                    }
                )))
                .collect::<Result<_>>()?
        );

        // GET /tags?filter=foo or bar should yield the tags and counts applied to images with either tag.

        let response = warp::test::request()
            .method("GET")
            .path("/tags?filter=foo%20or%20bar")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<TagsResponse>(response.body())?,
            TagsResponse {
                immutable: None,
                categories: hashmap![
                    "year".into() => TagsResponse {
                        immutable: Some(true),
                        categories: hashmap![
                            "month".into() => TagsResponse {
                                immutable: Some(true),
                                categories: HashMap::new(),
                                tags: (2..=4).map(|n| (format!("{}", n), 1)).collect()
                            }
                        ],
                        tags: hashmap![
                            "2021".into() => 3
                        ]
                    }
                ],
                tags: hashmap![
                    "foo".into() => 2,
                    "bar".into() => 2
                ]
            }
        );

        // A GET /images with a "limit" parameter should still give us the same most recent images, including the
        // tags we've added.

        let response = warp::test::request()
            .method("GET")
            .path(&format!("/images?limit={}", image_count - 1))
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, image_count);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            (2..=image_count)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    match number {
                        4 => hashset![
                            "year:2021".parse()?,
                            format!("month:{}", number).parse()?,
                            "bar".parse()?
                        ],
                        3 => hashset![
                            "year:2021".parse()?,
                            format!("month:{}", number).parse()?,
                            "foo".parse()?,
                            "bar".parse()?
                        ],
                        2 => hashset![
                            "year:2021".parse()?,
                            format!("month:{}", number).parse()?,
                            "foo".parse()?
                        ],
                        _ => hashset!["year:2021".parse()?, format!("month:{}", number).parse()?],
                    }
                )))
                .collect::<Result<_>>()?
        );

        // Let's add the "baz" tag to the fourth image.

        let patches = vec![Patch {
            hash: hashes
                .get(&"2021-04-01T00:00:00Z".parse()?)
                .unwrap()
                .clone(),
            tag: "baz".parse()?,
            action: Action::Add,
        }];

        let response = warp::test::request()
            .method("PATCH")
            .path("/tags")
            .header("authorization", format!("Bearer {}", token))
            .json(&patches)
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        // GET "/images?filter=bar and (foo or baz)" should yield the images which match that expression.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=bar%20and%20%28foo%20or%20baz%29")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 2);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            (3..=4)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    match number {
                        4 => hashset![
                            "year:2021".parse()?,
                            format!("month:{}", number).parse()?,
                            "bar".parse()?,
                            "baz".parse()?
                        ],
                        3 => hashset![
                            "year:2021".parse()?,
                            format!("month:{}", number).parse()?,
                            "foo".parse()?,
                            "bar".parse()?
                        ],
                        _ => unreachable!(),
                    }
                )))
                .collect::<Result<_>>()?
        );

        // GET "/tags?filter=bar and (foo or baz)" should yield the tags and counts applied to images which match
        // that expression.

        let response = warp::test::request()
            .method("GET")
            .path("/tags?filter=bar%20and%20%28foo%20or%20baz%29")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<TagsResponse>(response.body())?,
            TagsResponse {
                immutable: None,
                categories: hashmap![
                    "year".into() => TagsResponse {
                        immutable: Some(true),
                        categories: hashmap![
                            "month".into() => TagsResponse {
                                immutable: Some(true),
                                categories: HashMap::new(),
                                tags: (3..=4).map(|n| (format!("{}", n), 1)).collect()
                            }
                        ],
                        tags: hashmap![
                            "2021".into() => 2
                        ]
                    }
                ],
                tags: hashmap![
                    "foo".into() => 1,
                    "bar".into() => 2,
                    "baz".into() => 1
                ]
            }
        );

        // GET "/images?filter=bar and (foo or baz)&limit=1" should yield just the fourth image.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=bar%20and%20%28foo%20or%20baz%29&limit=1")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 2);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            iter::once(4)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    hashset![
                        "year:2021".parse()?,
                        format!("month:{}", number).parse()?,
                        "bar".parse()?,
                        "baz".parse()?
                    ]
                )))
                .collect::<Result<_>>()?
        );

        // GET "/images?filter=foo or bar&start=2021-04-01T00:00:00Z&limit=1" should yield just the third image.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=foo%20or%20bar&start=2021-04-01T00:00:00Z&limit=1")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 1);
        assert_eq!(response.total, 3);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            iter::once(3)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    hashset![
                        "year:2021".parse()?,
                        format!("month:{}", number).parse()?,
                        "foo".parse()?,
                        "bar".parse()?
                    ]
                )))
                .collect::<Result<_>>()?
        );

        // Let's remove the "bar" tag from the third image.

        let patches = vec![Patch {
            hash: hashes
                .get(&"2021-03-01T00:00:00Z".parse()?)
                .unwrap()
                .clone(),
            tag: "bar".parse()?,

            action: Action::Remove,
        }];

        let response = warp::test::request()
            .method("PATCH")
            .path("/tags")
            .header("authorization", format!("Bearer {}", token))
            .json(&patches)
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        // GET /images?filter=bar should yield just the fourth image now.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=bar")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 1);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            iter::once(4)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    hashset![
                        "year:2021".parse()?,
                        format!("month:{}", number).parse()?,
                        "bar".parse()?,
                        "baz".parse()?
                    ]
                )))
                .collect::<Result<_>>()?
        );

        // GET "/images?filter=year:2021" should yield all images.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=year:2021")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, image_count);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            (1..=image_count)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    match number {
                        4 => hashset![
                            "year:2021".parse()?,
                            format!("month:{}", number).parse()?,
                            "bar".parse()?,
                            "baz".parse()?
                        ],
                        3 | 2 => hashset![
                            "year:2021".parse()?,
                            format!("month:{}", number).parse()?,
                            "foo".parse()?
                        ],
                        _ => hashset!["year:2021".parse()?, format!("month:{}", number).parse()?],
                    }
                )))
                .collect::<Result<_>>()?
        );

        // GET "/images?filter=year:2021 and month:7" should yield only the seventh image.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=year:2021%20and%20month:7")
            .header("authorization", format!("Bearer {}", token))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 1);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            iter::once(7)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    hashset!["year:2021".parse()?, format!("month:{}", number).parse()?]
                )))
                .collect::<Result<_>>()?
        );

        // A PATCH /tags that tries to change the year or month should yield `UNAUTHORIZED`

        for &category in &["year", "month"] {
            for &action in &[Action::Add, Action::Remove] {
                let response = warp::test::request()
                    .method("PATCH")
                    .path("/tags")
                    .header("authorization", format!("Bearer {}", token))
                    .json(&vec![Patch {
                        hash: hashes
                            .get(&"2021-04-01T00:00:00Z".parse()?)
                            .unwrap()
                            .clone(),
                        tag: Tag {
                            value: "baz".into(),
                            category: Some(category.into()),
                        },
                        action,
                    }])
                    .reply(&routes)
                    .await;

                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            }
        }

        // Let's add the "public" tag to the fourth image.

        let patches = vec![Patch {
            hash: hashes
                .get(&"2021-04-01T00:00:00Z".parse()?)
                .unwrap()
                .clone(),
            tag: "public".parse()?,
            action: Action::Add,
        }];

        let response = warp::test::request()
            .method("PATCH")
            .path("/tags")
            .header("authorization", format!("Bearer {}", token))
            .json(&patches)
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        // GET /images with no authorization header should yield any images tagged "public".

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 1);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|(_, state)| (state.datetime, state.tags))
                .collect::<HashMap<_, _>>(),
            iter::once(4)
                .map(|number| Ok((
                    format!("2021-{:02}-01T00:00:00Z", number).parse()?,
                    hashset![
                        "year:2021".parse()?,
                        format!("month:{}", number).parse()?,
                        "bar".parse()?,
                        "baz".parse()?,
                        "public".parse()?
                    ]
                )))
                .collect::<Result<_>>()?
        );

        // GET /tags with no authorization header should yield the tags applied to any images tagged "public".

        let response = warp::test::request()
            .method("GET")
            .path("/tags")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<TagsResponse>(response.body())?,
            TagsResponse {
                immutable: None,
                categories: hashmap![
                    "year".into() => TagsResponse {
                        immutable: Some(true),
                        categories: hashmap![
                            "month".into() => TagsResponse {
                                immutable: Some(true),
                                categories: HashMap::new(),
                                tags: hashmap![
                                    "4".into() => 1
                                ]
                            }
                        ],
                        tags: hashmap![
                            "2021".into() => 1
                        ]
                    }
                ],
                tags: hashmap![
                    "bar".into() => 1,
                    "baz".into() => 1,
                    "public".into() => 1
                ]
            }
        );

        // The images and thumbnails should contain the colors we specified above.

        enum Size {
            Small,
            Large,
            Original,
        }

        fn close_enough(a: Rgb<u8>, b: Rgb<u8>) -> bool {
            const EPSILON: i32 = 5;

            a.0.iter()
                .zip(b.0.iter())
                .all(|(&a, &b)| ((a as i32) - (b as i32)).abs() < EPSILON)
        }

        for (&number, &color) in &colors {
            for size in &[Size::Small, Size::Large, Size::Original] {
                let response = warp::test::request()
                    .method("GET")
                    .header("authorization", format!("Bearer {}", token))
                    .path(&format!(
                        "/image/{}{}",
                        hashes
                            .get(&format!("2021-{:02}-01T00:00:00Z", number).parse()?)
                            .unwrap(),
                        match size {
                            Size::Small => "?size=small",
                            Size::Large => "?size=large",
                            Size::Original => "",
                        }
                    ))
                    .reply(&routes)
                    .await;

                assert_eq!(response.status(), StatusCode::OK);

                let image =
                    image::load_from_memory_with_format(response.body(), ImageFormat::Jpeg)?
                        .to_rgb8();

                assert_eq!(
                    (image.width(), image.height()),
                    match size {
                        Size::Small => SMALL_BOUNDS,
                        Size::Large => LARGE_BOUNDS,
                        Size::Original => (image_width, image_height),
                    }
                );

                for _ in 0..10 {
                    assert!(close_enough(
                        *image.get_pixel(
                            random.gen_range(0..image.width()),
                            random.gen_range(0..image.height())
                        ),
                        color
                    ));
                }
            }
        }

        Ok(())
    }
}
