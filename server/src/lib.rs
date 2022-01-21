//! Tagger server
//!
//! This crate contains the Tagger server, which is responsible for:
//!
//! * Authenticating and authorizing client HTTPS requests: [auth]
//!
//! * Handling tag queries and updates: [tags]
//!
//! * Handling media item metadata queries based on tag expressions: [images]
//!
//! * Periodically syncing the media database with the filesystem: [sync]
//!
//! * Generating and caching preview images and video clips: [media]
//!
//! * Detecting duplicate media items: [media] and [sync::deduplicate]
//!
//! * Handling media item content requests: [media::image]
//!
//! This top-level module ties all of the above together and hosts the [Warp](https://crates.io/crates/warp)
//! routing rules, configuration options, tests, et cetera.

#![deny(warnings)]

use {
    crate::warp_util::{Bearer, HttpDate, HttpError, Ranges},
    anyhow::{anyhow, Error, Result},
    futures::future::{self, FutureExt, TryFutureExt},
    http::{
        header,
        response::{self, Response},
        status::StatusCode,
        Uri,
    },
    hyper::Body,
    sqlx::{
        query::Query,
        sqlite::{SqliteArguments, SqliteConnectOptions},
        ConnectOptions, Sqlite, SqliteConnection,
    },
    std::{
        convert::Infallible,
        fmt::{self, Display},
        net::SocketAddrV4,
        ops::DerefMut,
        panic::{self, AssertUnwindSafe},
        str::FromStr,
        sync::Arc,
        time::Duration,
    },
    structopt::StructOpt,
    tagger_shared::{
        tag_expression::TagExpression, Authorization, ImagesQuery, Patch, TagsQuery, TokenRequest,
        Variant,
    },
    tokio::{
        fs::File as AsyncFile,
        io::AsyncReadExt,
        sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock},
    },
    tracing::{info, warn},
    warp::{host::Authority, path::FullPath, Filter, Rejection, Reply},
};

pub use {
    auth::hash_password,
    media::{
        deduplicate, perceptual_ordinal, preload_cache, preload_cache_all, FileData, Item,
        ItemData, Ordinal,
    },
    sync::sync,
};

mod auth;
mod images;
mod media;
mod sync;
mod tags;
mod warp_util;

/// Minimum delay added to responses to invalid authentication requests
///
/// Note that these delays will stack up if invalid requests are received more often than once per this interval,
/// so the actual delay experienced by a given request may be much longer, e.g. during a brute force attack.
const INVALID_CREDENTIAL_DELAY_SECS: u64 = 5;

/// Size of buffer (in bytes) to use when copying or hashing files
const BUFFER_SIZE: usize = 16 * 1024;

/// Determines which media items to generate thumbnails and previews for, if any
#[derive(Debug)]
pub enum PreloadPolicy {
    /// Never pre-generate thumbnails
    None,

    /// Pre-generate thumbnails for newly-discovered items only
    New,

    /// Pre-generate thumbnails for both existing and newly-discovered items
    All,
}

impl Default for PreloadPolicy {
    /// Return `Self::None`
    fn default() -> Self {
        Self::None
    }
}

impl Display for PreloadPolicy {
    /// Convert a `PreloadPolicy` to a string, e.g. "none", "new", or "all"
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::None => "none",
                Self::New => "new",
                Self::All => "all",
            }
        )
    }
}

impl FromStr for PreloadPolicy {
    type Err = Error;

    /// Parse a `PreloadPolicy` from a string, e.g. "none", "new", or "all"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "none" => Self::None,
            "new" => Self::New,
            "all" => Self::All,
            _ => return Err(anyhow!("unknown preload policy: {s}")),
        })
    }
}

/// Configuration options for the Tagger server
#[derive(StructOpt, Debug)]
#[structopt(name = "tagger-server", about = "Media tagging web application server")]
pub struct Options {
    /// Address on which to listen for HTTP requests
    #[structopt(long)]
    pub http_address: Option<SocketAddrV4>,

    /// Address on which to listen for HTTPS requests
    ///
    /// If both `http_address` and `https_address` are set, all HTTP requests will be redirected to HTTPS.
    #[structopt(long)]
    pub https_address: Option<SocketAddrV4>,

    /// Directory containing source image and video files
    #[structopt(long)]
    pub image_directory: String,

    /// Directory in which to cache lazily generated image and video variants
    #[structopt(long)]
    pub cache_directory: String,

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

    /// File containing HS256 key for signing and verifying JWTs
    #[structopt(long)]
    pub auth_key_file: Option<String>,

    /// Specify whether to pre-generate thumbnails and stills
    #[structopt(long, default_value)]
    pub preload_policy: PreloadPolicy,

    /// Specify whether to identify inexact duplicates (e.g. resampled images and videos)
    ///
    /// Note that exact duplicates (files which match byte-for-byte) are always automatically deduplicated.
    #[structopt(long)]
    pub deduplicate: bool,
}

/// Open or create an SQLite database using the specified filename.
pub async fn open(state_file: &str) -> Result<SqliteConnection> {
    let mut conn = format!("sqlite://{state_file}")
        .parse::<SqliteConnectOptions>()?
        .create_if_missing(true)
        .connect()
        .await?;

    for statement in schema::DDL_STATEMENTS {
        sqlx::query(statement).execute(&mut conn).await?;
    }

    Ok(conn)
}

/// Convert the specified `expression` to an SQL expression, appending the result to the specified `buffer`.
///
/// The resulting SQL fragment will include one or more subselects which reference the "tags" table as well as the
/// table alias "i", which refers to the "images" table named in the outer query.
///
/// See also [bind_filter_clause].
fn append_filter_clause(buffer: &mut String, expression: &TagExpression) {
    match expression {
        TagExpression::Tag(tag) => buffer.push_str(if tag.category.is_some() {
            "EXISTS (SELECT * FROM tags WHERE hash = i.hash AND category = ? AND tag = ?)"
        } else {
            "EXISTS (SELECT * FROM tags WHERE hash = i.hash AND category IS NULL AND tag = ?)"
        }),
        TagExpression::Not(a) => {
            buffer.push_str("(NOT ");
            append_filter_clause(buffer, a);
            buffer.push(')');
        }
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

/// Bind the specified arguments to the placeholder category and tag parameters used by [append_filter_clause].
fn bind_filter_clause<'a>(
    expression: &TagExpression,
    select: Query<'a, Sqlite, SqliteArguments<'a>>,
) -> Query<'a, Sqlite, SqliteArguments<'a>> {
    // Note that we rely on `TagExpression::fold_tags` to visit tags in the same order that [append_filter_clause]
    // does.
    //
    // TODO: Can we refactor [append_filter_clause] and/or `TagExpression::fold_tags` so that the former can use
    // the latter so they don't get out of sync?
    expression.fold_tags(select, |mut select, category, tag| {
        if let Some(category) = category {
            select = select.bind(category.to_owned())
        }
        select.bind(tag.to_owned())
    })
}

/// If the specified `auth` claims include a non-empty `Authorization::filter` field, modify the supplied `filter`
/// in place, either replacing it with the one from `auth` if the former is empty, or combining them together using
/// the AND operator.
///
/// This ensures that whatever filter was provided by the user is constrained to what that user has permission to
/// access.
fn maybe_wrap_filter(filter: &mut Option<TagExpression>, auth: &Authorization) {
    if let Some(user_filter) = &auth.filter {
        if let Some(inner) = filter.take() {
            *filter = Some(TagExpression::And(
                Box::new(inner),
                Box::new(user_filter.clone()),
            ));
        } else {
            *filter = Some(user_filter.clone());
        }
    }
}

/// Abbreviation for `Response::builder()`
fn response() -> response::Builder {
    Response::builder()
}

/// Build a Warp routing filter based on the specified configuration.
///
/// * `conn`: used to access the Tagger database
///
/// * `image_lock`: used to control concurrent access to the cache directory, e.g. to avoid simultaneous reads and
/// writes to cache files
///
/// * `options`: server configuration -- see [Options] for details
///
/// * `default_auth_key`: key used to sign access tokens if `options.auth_key_file` is `None`
///
/// * `invalid_credentail_delay`: minimum interval to wait before responding to an invalid authentication request
async fn routes(
    conn: &Arc<AsyncMutex<SqliteConnection>>,
    image_lock: &Arc<AsyncRwLock<()>>,
    options: &Arc<Options>,
    default_auth_key: [u8; 32],
    invalid_credential_delay: Duration,
) -> Result<impl Filter<Extract = (impl Reply,), Error = Infallible> + Clone> {
    // Check if the database contains an anonymous user account and, if so, construct a token representing that
    // account to use whenever we receive a request that doesn't have a token.
    let default_auth = if let Some(row) = sqlx::query!(
        "SELECT filter, may_patch FROM users WHERE name IS NULL AND password_hash IS NULL"
    )
    .fetch_optional(conn.lock().await.deref_mut())
    .await?
    {
        Some(Arc::new(Authorization {
            expiration: None,
            subject: Some("(default)".into()),
            filter: row.filter.map(|s| s.parse()).transpose()?,
            may_patch: row.may_patch != 0,
        }))
    } else {
        None
    };

    let auth_key = if let Some(auth_key_file) = &options.auth_key_file {
        let mut key = [0u8; 32];

        AsyncFile::open(auth_key_file)
            .await?
            .read_exact(&mut key)
            .await?;

        key
    } else {
        default_auth_key
    };

    // All authentication requests are bottlenecked by this mutex to mitigate parallel brute force attacks:
    let auth_mutex = Arc::new(AsyncMutex::new(()));

    let auth = warp::header::optional::<Bearer>("authorization").and_then(
        move |authorization: Option<Bearer>| {
            let default_auth = default_auth.clone();

            async move {
                if let Some(token) = authorization.as_ref().map(|h| &h.body) {
                    Ok(auth::authorize(token, &auth_key)?)
                } else if let Some(default_auth) = &default_auth {
                    Ok(default_auth.clone())
                } else {
                    Err(Rejection::from(HttpError::from_slice(
                        StatusCode::UNAUTHORIZED,
                        "missing token",
                    )))
                }
            }
        },
    );

    Ok(warp::post()
        .and(warp::path("token"))
        .and(warp::body::form::<TokenRequest>())
        .and_then({
            let conn = conn.clone();

            move |body| {
                let conn = conn.clone();
                let auth_mutex = auth_mutex.clone();

                async move {
                    auth::authenticate(
                        &conn,
                        &body,
                        &auth_key,
                        &auth_mutex,
                        invalid_credential_delay,
                    )
                    .await
                }
                .map_err(|e| {
                    warn!("error authorizing: {e:?}");

                    Rejection::from(HttpError::from(e))
                })
            }
        })
        .or(warp::get()
            .and(
                warp::path("images")
                    .and(auth.clone())
                    .and(warp::query::<ImagesQuery>())
                    .and_then({
                        let conn = conn.clone();

                        move |auth: Arc<Authorization>, mut query: ImagesQuery| {
                            maybe_wrap_filter(&mut query.filter, &auth);

                            let conn = conn.clone();

                            async move {
                                let state = serde_json::to_vec(
                                    &images::images(conn.lock().await.deref_mut(), &query).await?,
                                )?;

                                Ok(response()
                                    .header(header::CONTENT_LENGTH, state.len())
                                    .header(header::CONTENT_TYPE, "application/json")
                                    .body(Body::from(state))?)
                            }
                            .map_err(move |e| {
                                warn!(?auth, "error retrieving state: {e:?}");

                                Rejection::from(HttpError::from(e))
                            })
                        }
                    })
                    .or(warp::path("tags")
                        .and(auth.clone())
                        .and(warp::query::<TagsQuery>())
                        .and_then({
                            let conn = conn.clone();

                            move |auth: Arc<Authorization>, mut query: TagsQuery| {
                                maybe_wrap_filter(&mut query.filter, &auth);

                                let conn = conn.clone();

                                async move {
                                    let tags = serde_json::to_vec(
                                        &tags::tags(conn.lock().await.deref_mut(), &query).await?,
                                    )?;

                                    Ok(response()
                                        .header(header::CONTENT_LENGTH, tags.len())
                                        .header(header::CONTENT_TYPE, "application/json")
                                        .body(Body::from(tags))?)
                                }
                                .map_err(move |e| {
                                    warn!(?auth, "error retrieving tags: {e:?}");

                                    Rejection::from(HttpError::from(e))
                                })
                            }
                        }))
                    .or(warp::path!("image" / Variant / String)
                        .and(warp::header::optional::<HttpDate>("if-modified-since"))
                        .and(warp::header::optional::<Ranges>("range"))
                        .and_then({
                            let conn = conn.clone();
                            let options = options.clone();
                            let image_lock = image_lock.clone();

                            move |variant: Variant,
                                  hash: String,
                                  if_modified_since: Option<HttpDate>,
                                  ranges: Option<Ranges>| {
                                let hash = Arc::<str>::from(hash);

                                {
                                    let hash = hash.clone();
                                    let conn = conn.clone();
                                    let options = options.clone();
                                    let image_lock = image_lock.clone();

                                    async move {
                                        media::image(
                                            &conn,
                                            &image_lock,
                                            &options.image_directory,
                                            &options.cache_directory,
                                            &hash,
                                            variant,
                                            if_modified_since,
                                            ranges.as_ref(),
                                        )
                                        .await
                                    }
                                }
                                .map_err(move |e| {
                                    warn!("error retrieving image {hash}: {e:?}");

                                    Rejection::from(HttpError::from(e))
                                })
                            }
                        }))
                    .or(warp::path("token").and_then({
                        let conn = conn.clone();

                        move || {
                            let conn = conn.clone();

                            async move { auth::authenticate_anonymous(&conn, &auth_key).await }
                                .map_err(|e| Rejection::from(HttpError::from(e)))
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
                        move |auth: Arc<Authorization>, patches: Vec<Patch>| {
                            let patches = Arc::new(patches);

                            {
                                let auth = auth.clone();
                                let patches = patches.clone();
                                let conn = conn.clone();

                                async move {
                                    tags::apply(&auth, conn.lock().await.deref_mut(), &patches)
                                        .await
                                }
                            }
                            .map_err(move |e| {
                                warn!(
                                    ?auth,
                                    "error applying patch {}: {e:?}",
                                    serde_json::to_string(patches.as_ref()).unwrap_or_else(|_| {
                                        "(unable to serialize patches)".to_string()
                                    })
                                );

                                Rejection::from(HttpError::from(e))
                            })
                        }
                    }),
            )))
        .recover(warp_util::handle_rejection)
        .with(warp::log("tagger"))
        .map(|reply| warp::reply::with_header(reply, "Accept-Ranges", "bytes")))
}

/// Wrapper for `panic::catch_unwind` which converts the panic payload to a human-readable `anyhow::Error`
fn catch_unwind<T>(fun: impl panic::UnwindSafe + FnOnce() -> T) -> Result<T> {
    panic::catch_unwind(fun).map_err(|e| {
        if let Some(s) = e.downcast_ref::<&str>() {
            anyhow!("{s}")
        } else if let Some(s) = e.downcast_ref::<String>() {
            anyhow!("{s}")
        } else {
            anyhow!("caught panic")
        }
    })
}

/// Run a Warp server using a filter created by [routes], bound to the address(es) specified in `options`.
///
/// `conn`, `image_lock`, and `default_auth_key` are all passed directly to [routes].  See that function's
/// documentation for details.
pub async fn serve(
    conn: &Arc<AsyncMutex<SqliteConnection>>,
    image_lock: &Arc<AsyncRwLock<()>>,
    options: &Arc<Options>,
    default_auth_key: [u8; 32],
) -> Result<()> {
    let routes = routes(
        conn,
        image_lock,
        options,
        default_auth_key,
        Duration::from_secs(INVALID_CREDENTIAL_DELAY_SECS),
    )
    .await?;

    let (http_address, https_address, future) =
        if let (Some(cert), Some(key), Some(https_address)) =
            (&options.cert_file, &options.key_file, options.https_address)
        {
            let server = warp::serve(routes).tls().cert_path(cert).key_path(key);

            // As of this writing, warp::TlsServer does not have a try_bind_ephemeral method, so we must catch panics
            // explicitly.
            let (https_address, https_future) = catch_unwind(AssertUnwindSafe(move || {
                server.bind_ephemeral(https_address)
            }))?;

            if let Some(http_address) = options.http_address {
                let redirect_all = warp::path::full().and(warp::host::optional()).and_then(
                    |path: FullPath, authority: Option<Authority>| async move {
                        if let Some(authority) = authority {
                            Ok(warp::redirect(
                                Uri::builder()
                                    .scheme("https")
                                    .authority(authority.host())
                                    .path_and_query(path.as_str())
                                    .build()
                                    .map_err(move |e| {
                                        warn!(
                                            "error redirecting http://{}/{} to HTTPS: {e:?}",
                                            authority.host(),
                                            path.as_str()
                                        );

                                        Rejection::from(HttpError::from(e.into()))
                                    })?,
                            ))
                        } else {
                            Err(warp::reject::not_found())
                        }
                    },
                );

                let (http_address, http_future) =
                    warp::serve(redirect_all).try_bind_ephemeral(http_address)?;

                (
                    Some(http_address),
                    Some(https_address),
                    future::select(http_future, https_future)
                        .map(|result| result.factor_first().0)
                        .boxed(),
                )
            } else {
                (None, Some(https_address), https_future.boxed())
            }
        } else if let Some(http_address) = options.http_address {
            let (http_address, future) = warp::serve(routes).try_bind_ephemeral(http_address)?;

            (Some(http_address), None, future.boxed())
        } else {
            return Err(anyhow!(
                "either `http_address` or `https_address` must be specified"
            ));
        };

    if let Some(address) = http_address {
        info!("listening on http://{address}");
    }

    if let Some(address) = https_address {
        info!("listening on https://{address}");
    }

    future.await;

    Ok(())
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::media::TempFile,
        anyhow::Error,
        futures::{future, TryStreamExt},
        image::ImageFormat,
        image::{ImageBuffer, Rgb},
        jsonwebtoken::{self, Algorithm, EncodingKey, Header},
        lazy_static::lazy_static,
        maplit::{hashmap, hashset},
        rand::{rngs::StdRng, Rng, SeedableRng},
        rexiv2::Metadata as ExifMetadata,
        std::{
            collections::HashMap,
            io::Write,
            iter,
            ops::Deref,
            path::Path,
            sync::Once,
            time::{SystemTime, UNIX_EPOCH},
        },
        tagger_shared::{
            tag_expression::Tag, Action, ImagesResponse, Medium, Size, TagsResponse, TokenError,
            TokenSuccess,
        },
        tempfile::{NamedTempFile, TempDir},
        tokio::{fs, process::Command, sync::OnceCell, task},
    };

    const MEDIA_COUNT: u32 = 10;
    const DUPLICATE_IMAGE_COUNT: u32 = 3;
    const DUPLICATE_VIDEO_COUNT: u32 = 3;
    const BASE_IMAGE_WIDTH: u32 = 480;
    const BASE_IMAGE_HEIGHT: u32 = 320;

    #[derive(Copy, Clone)]
    enum TestMedium {
        Image,
        Video,
    }

    #[derive(Copy, Clone)]
    struct MediumInfo {
        medium: TestMedium,
        color: Rgb<u8>,
    }

    struct TestState<F> {
        conn: Arc<AsyncMutex<SqliteConnection>>,
        routes: F,
        auth_key: [u8; 32],
        image_lock: Arc<AsyncRwLock<()>>,
        image_dir: &'static str,
        cache_dir: &'static str,
        info: Arc<HashMap<u32, MediumInfo>>,
    }

    fn dimensions(number: u32) -> (u32, u32) {
        (
            BASE_IMAGE_WIDTH + ((BASE_IMAGE_WIDTH * number) / 40),
            BASE_IMAGE_HEIGHT + ((BASE_IMAGE_HEIGHT * number) / 40),
        )
    }

    async fn generate_media(image_dir: &Path, info: &HashMap<u32, MediumInfo>) -> Result<()> {
        for (&number, info) in info {
            let mut path = image_dir.to_owned();

            path.push(format!("{number}.jpg"));

            task::block_in_place(|| {
                let (width, height) = dimensions(number);

                ImageBuffer::from_pixel(width, height, info.color).save(&path)?;

                let metadata = ExifMetadata::new_from_path(&path)?;

                metadata.set_tag_string(
                    "Exif.Image.DateTimeOriginal",
                    &format!("2021:{number:02}:01 00:00:00"),
                )?;

                metadata.save_to_file(&path)?;

                Ok::<_, Error>(())
            })?;

            if let TestMedium::Video = info.medium {
                let mut video = image_dir.to_owned();

                video.push(format!("{number}.mp4"));

                let output = Command::new("ffmpeg")
                    .arg("-loop")
                    .arg("1")
                    .arg("-i")
                    .arg(&path)
                    .arg("-t")
                    .arg("10")
                    .arg("-timestamp")
                    .arg(format!("2021-{number:02}-01T00:00:00Z"))
                    .arg(&video)
                    .output()
                    .await?;

                fs::remove_file(&path).await?;

                if !output.status.success() {
                    let _ = fs::remove_file(&video).await;

                    return Err(anyhow!(
                        "error running ffmpeg: {}",
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
            }
        }

        Ok(())
    }

    async fn init(
    ) -> Result<TestState<impl Filter<Extract = (impl Reply,), Error = Infallible> + Clone>> {
        {
            static ONCE: Once = Once::new();

            ONCE.call_once(pretty_env_logger::init_timed);
        }

        let mut conn = "sqlite::memory:"
            .parse::<SqliteConnectOptions>()?
            .connect()
            .await?;

        for statement in schema::DDL_STATEMENTS {
            sqlx::query(statement).execute(&mut conn).await?;
        }

        fn info() -> HashMap<u32, MediumInfo> {
            let mut random = StdRng::seed_from_u64(42);

            let mut random_color = || Rgb([random.gen::<u8>(), random.gen(), random.gen()]);

            let duplicate_color = random_color();

            iter::repeat_with(random_color)
                .enumerate()
                .map(|(index, color)| MediumInfo {
                    medium: if index % 2 == 0 {
                        TestMedium::Image
                    } else {
                        TestMedium::Video
                    },
                    color,
                })
                .take(
                    (MEDIA_COUNT - (DUPLICATE_IMAGE_COUNT + DUPLICATE_VIDEO_COUNT))
                        .try_into()
                        .unwrap(),
                )
                .chain(
                    iter::repeat(MediumInfo {
                        medium: TestMedium::Image,
                        color: duplicate_color,
                    })
                    .take(DUPLICATE_IMAGE_COUNT.try_into().unwrap()),
                )
                .chain(
                    iter::repeat(MediumInfo {
                        medium: TestMedium::Video,
                        color: duplicate_color,
                    })
                    .take(DUPLICATE_VIDEO_COUNT.try_into().unwrap()),
                )
                .enumerate()
                .map(|(index, info)| ((index + 1).try_into().unwrap(), info))
                .collect()
        }

        lazy_static! {
            static ref IMAGE_LOCK: Arc<AsyncRwLock<()>> = Arc::new(AsyncRwLock::new(()));
            static ref IMAGE_DIR: TempDir = TempDir::new().unwrap();
            static ref CACHE_DIR: TempDir = TempDir::new().unwrap();
            static ref INFO: Arc<HashMap<u32, MediumInfo>> = Arc::new(info());
            static ref ONCE: OnceCell<Result<()>> = OnceCell::new();
        }

        ONCE.get_or_init(|| generate_media(IMAGE_DIR.path(), INFO.deref().deref()))
            .await
            .as_ref()
            .unwrap();

        let conn = Arc::new(AsyncMutex::new(conn));

        let image_dir = IMAGE_DIR
            .path()
            .to_str()
            .ok_or_else(|| anyhow!("invalid UTF-8"))?;

        let cache_dir = CACHE_DIR
            .path()
            .to_str()
            .ok_or_else(|| anyhow!("invalid UTF-8"))?;

        let mut auth_key = [0u8; 32];
        rand::thread_rng().fill(&mut auth_key);

        let routes = make_routes(&conn, IMAGE_LOCK.deref(), image_dir, cache_dir, auth_key).await?;

        Ok(TestState {
            conn,
            image_lock: IMAGE_LOCK.clone(),
            auth_key,
            routes,
            image_dir,
            cache_dir,
            info: INFO.clone(),
        })
    }

    async fn make_routes(
        conn: &Arc<AsyncMutex<SqliteConnection>>,
        image_lock: &Arc<AsyncRwLock<()>>,
        image_dir: &str,
        cache_dir: &str,
        auth_key: [u8; 32],
    ) -> Result<impl Filter<Extract = (impl Reply,), Error = Infallible> + Clone> {
        routes(
            conn,
            image_lock,
            &Arc::new(Options {
                http_address: Some("0.0.0.0:0".parse()?),
                https_address: None,
                image_directory: image_dir.to_owned(),
                cache_directory: cache_dir.to_owned(),
                state_file: "does-not-exist-2a1dad1c-e044-4b95-be08-3a3f72d5ac0a".to_string(),
                public_directory: "does-not-exist-2a1dad1c-e044-4b95-be08-3a3f72d5ac0a".to_string(),
                cert_file: None,
                key_file: None,
                auth_key_file: None,
                preload_policy: PreloadPolicy::None,
                deduplicate: false,
            }),
            auth_key,
            Duration::from_secs(0),
        )
        .await
    }

    fn make_token(auth_key: &[u8]) -> Result<String> {
        let expiration = (SystemTime::now() + Duration::from_secs(60 * 60))
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        Ok(jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &Authorization {
                expiration: Some(expiration),
                subject: Some("test".to_owned()),
                filter: None,
                may_patch: true,
            },
            &EncodingKey::from_secret(auth_key),
        )?)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn authentication() -> Result<()> {
        let TestState { conn, routes, .. } = init().await?;

        let user = "Jabberwocky";
        let password = "Bandersnatch";

        {
            let hash = auth::hash_password(user.as_bytes(), password.as_bytes());

            sqlx::query!(
                "INSERT INTO users (name, password_hash, may_patch) VALUES (?1, ?2, 1)",
                user,
                hash,
            )
            .execute(conn.lock().await.deref_mut())
            .await?;
        }

        // Anonymous request should yield `UNAUTHORIZED` from /token.

        let response = warp::test::request()
            .method("GET")
            .path("/token")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        serde_json::from_slice::<TokenError>(response.body())?;

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
                "grant_type=password&username={user}&password=invalid+password"
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
                "grant_type=password&username={user}&password={password}"
            ))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        serde_json::from_slice::<TokenSuccess>(response.body())?;

        // Let's add an anonymous user to to DB.

        sqlx::query!("INSERT INTO users (filter) VALUES ('public')")
            .execute(conn.lock().await.deref_mut())
            .await?;

        // Now that we've added an anonymous user to the DB, an anonymous request should yield `OK` from /token.

        let response = warp::test::request()
            .method("GET")
            .path("/token")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn get_images() -> Result<()> {
        let TestState {
            auth_key,
            conn,
            routes,
            image_lock,
            image_dir,
            cache_dir,
            ..
        } = init().await?;

        // Missing authorization header should yield `UNAUTHORIZED` from /images.

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Invalid token should yield `UNAUTHORIZED` from /images.

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .header("authorization", "Bearer invalid")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let token = make_token(&auth_key)?;

        // Valid token should yield `OK` from /images.

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        // The response from /images should be empty at this point since we haven't added any images yet.

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 0);
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
        assert!(response.images.is_empty());

        sync::sync(&conn, &image_lock, image_dir, cache_dir, false, false).await?;

        // Let's add an anonymous user to to DB.

        sqlx::query!("INSERT INTO users (filter) VALUES ('public')")
            .execute(conn.lock().await.deref_mut())
            .await?;

        // Re-generate routes since that's what checks the DB for an anonymous user.

        let routes = make_routes(&conn, &image_lock, image_dir, cache_dir, auth_key).await?;

        // Now that we've added an anonymous user to the DB, missing authorization header should `OK` yield from
        // /images, but with an empty response since no images have been tagged "public" yet.

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 0);
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
        assert_eq!(response.images.len(), 0);

        // GET /images with no query parameters and with a filter-less token should yield all the images.

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, MEDIA_COUNT);
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);

        let hashes = response
            .images
            .iter()
            .map(|data| (data.datetime, data.hash.clone()))
            .collect::<HashMap<_, _>>();

        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            (1..=MEDIA_COUNT)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    hashset!["year:2021".parse()?, format!("month:{number}").parse()?]
                )))
                .collect::<Result<_>>()?
        );

        // GET /images with a "limit" parameter should yield the most recent images.

        let response = warp::test::request()
            .method("GET")
            .path("/images?limit=2")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, MEDIA_COUNT);
        assert_eq!(response.later_start, None);
        assert_eq!(
            response.earliest_start.map(|key| key.datetime),
            Some("2021-03-01T00:00:00Z".parse()?)
        );
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            ((MEDIA_COUNT - 1)..=MEDIA_COUNT)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    hashset!["year:2021".parse()?, format!("month:{number}").parse()?]
                )))
                .collect::<Result<_>>()?
        );

        // GET /images with "start" and "limit" parameters should yield images from the specified interval.

        let response = warp::test::request()
            .method("GET")
            .path("/images?start=2021-04-01T00:00:00Z&limit=2")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 7);
        assert_eq!(response.total, MEDIA_COUNT);
        assert_eq!(
            response.later_start.map(|key| key.datetime),
            Some("2021-06-01T00:00:00Z".parse()?)
        );
        assert_eq!(
            response.earliest_start.map(|key| key.datetime),
            Some("2021-02-01T00:00:00Z".parse()?)
        );
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            (2..=3)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    hashset!["year:2021".parse()?, format!("month:{number}").parse()?]
                )))
                .collect::<Result<_>>()?
        );

        // Let's add the "foo" tag to the third image.

        {
            let hash = hashes
                .get(&"2021-03-01T00:00:00Z".parse()?)
                .unwrap()
                .to_string();

            sqlx::query!("INSERT INTO tags (hash, tag) VALUES (?1, 'foo')", hash)
                .execute(conn.lock().await.deref_mut())
                .await?;
        }

        // Now GET /images should report the tag we added via the above patch.

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, MEDIA_COUNT);
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            (1..=MEDIA_COUNT)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    if number == 3 {
                        hashset![
                            "year:2021".parse()?,
                            format!("month:{number}").parse()?,
                            "foo".parse()?
                        ]
                    } else {
                        hashset!["year:2021".parse()?, format!("month:{number}").parse()?]
                    }
                )))
                .collect::<Result<_>>()?
        );

        // GET /images with a "filter" parameter should yield only the image(s) matching that expression.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=foo")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 1);
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            iter::once(3)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    hashset![
                        "year:2021".parse()?,
                        format!("month:{number}").parse()?,
                        "foo".parse()?
                    ]
                )))
                .collect::<Result<_>>()?
        );

        // Let's add some more tags.

        {
            let second = hashes
                .get(&"2021-02-01T00:00:00Z".parse()?)
                .unwrap()
                .to_string();

            let third = hashes
                .get(&"2021-03-01T00:00:00Z".parse()?)
                .unwrap()
                .to_string();

            let fourth = hashes
                .get(&"2021-04-01T00:00:00Z".parse()?)
                .unwrap()
                .to_string();

            sqlx::query!(
                "INSERT INTO tags (hash, tag) VALUES (?1, 'foo'), (?2, 'bar'), (?3, 'bar')",
                second,
                third,
                fourth
            )
            .execute(conn.lock().await.deref_mut())
            .await?;
        }

        // GET /images?filter=foo should yield all images with that tag.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=foo")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 2);
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            (2..=3)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    if number == 3 {
                        hashset![
                            "year:2021".parse()?,
                            format!("month:{number}").parse()?,
                            "foo".parse()?,
                            "bar".parse()?
                        ]
                    } else {
                        hashset![
                            "year:2021".parse()?,
                            format!("month:{number}").parse()?,
                            "foo".parse()?
                        ]
                    }
                )))
                .collect::<Result<_>>()?
        );

        // GET /images?filter=bar should yield all images with that tag.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=bar")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 2);
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            (3..=4)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    if number == 3 {
                        hashset![
                            "year:2021".parse()?,
                            format!("month:{number}").parse()?,
                            "foo".parse()?,
                            "bar".parse()?
                        ]
                    } else {
                        hashset![
                            "year:2021".parse()?,
                            format!("month:{number}").parse()?,
                            "bar".parse()?
                        ]
                    }
                )))
                .collect::<Result<_>>()?
        );

        // GET "/images?filter=foo and bar" should yield only the image that has both tags.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=foo%20and%20bar")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 1);
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            iter::once(3)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    hashset![
                        "year:2021".parse()?,
                        format!("month:{number}").parse()?,
                        "foo".parse()?,
                        "bar".parse()?
                    ]
                )))
                .collect::<Result<_>>()?
        );

        // GET "/images?filter=foo or bar" should yield the images with either tag.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=foo%20or%20bar")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 3);
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            (2..=4)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    match number {
                        4 => hashset![
                            "year:2021".parse()?,
                            format!("month:{number}").parse()?,
                            "bar".parse()?
                        ],
                        3 => hashset![
                            "year:2021".parse()?,
                            format!("month:{number}").parse()?,
                            "foo".parse()?,
                            "bar".parse()?
                        ],
                        2 => hashset![
                            "year:2021".parse()?,
                            format!("month:{number}").parse()?,
                            "foo".parse()?
                        ],
                        _ => unreachable!(),
                    }
                )))
                .collect::<Result<_>>()?
        );

        // A GET /images with a "limit" parameter should still give us the same most recent images, including the
        // tags we've added.

        let response = warp::test::request()
            .method("GET")
            .path(&format!("/images?limit={}", MEDIA_COUNT - 1))
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, MEDIA_COUNT);
        assert_eq!(response.later_start, None);
        assert_eq!(
            response.earliest_start.map(|key| key.datetime),
            Some("2021-02-01T00:00:00Z".parse()?)
        );
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            (2..=MEDIA_COUNT)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    match number {
                        4 => hashset![
                            "year:2021".parse()?,
                            format!("month:{number}").parse()?,
                            "bar".parse()?
                        ],
                        3 => hashset![
                            "year:2021".parse()?,
                            format!("month:{number}").parse()?,
                            "foo".parse()?,
                            "bar".parse()?
                        ],
                        2 => hashset![
                            "year:2021".parse()?,
                            format!("month:{number}").parse()?,
                            "foo".parse()?
                        ],
                        _ => hashset!["year:2021".parse()?, format!("month:{number}").parse()?],
                    }
                )))
                .collect::<Result<_>>()?
        );

        // Let's add the "baz" tag to the fourth image.

        {
            let hash = hashes
                .get(&"2021-04-01T00:00:00Z".parse()?)
                .unwrap()
                .to_string();

            sqlx::query!("INSERT INTO tags (hash, tag) VALUES (?1, 'baz')", hash)
                .execute(conn.lock().await.deref_mut())
                .await?;
        }

        // GET "/images?filter=bar and (foo or baz)" should yield the images which match that expression.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=bar%20and%20%28foo%20or%20baz%29")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 2);
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            (3..=4)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    match number {
                        4 => hashset![
                            "year:2021".parse()?,
                            format!("month:{number}").parse()?,
                            "bar".parse()?,
                            "baz".parse()?
                        ],
                        3 => hashset![
                            "year:2021".parse()?,
                            format!("month:{number}").parse()?,
                            "foo".parse()?,
                            "bar".parse()?
                        ],
                        _ => unreachable!(),
                    }
                )))
                .collect::<Result<_>>()?
        );

        // GET "/images?filter=bar and (foo or baz)&limit=1" should yield just the fourth image.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=bar%20and%20%28foo%20or%20baz%29&limit=1")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 2);
        assert_eq!(response.later_start, None);
        assert_eq!(
            response.earliest_start.map(|key| key.datetime),
            Some("2021-04-01T00:00:00Z".parse()?)
        );
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            iter::once(4)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    hashset![
                        "year:2021".parse()?,
                        format!("month:{number}").parse()?,
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
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 1);
        assert_eq!(response.total, 3);
        assert_eq!(response.later_start, None);
        assert_eq!(
            response.earliest_start.map(|key| key.datetime),
            Some("2021-03-01T00:00:00Z".parse()?)
        );
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            iter::once(3)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    hashset![
                        "year:2021".parse()?,
                        format!("month:{number}").parse()?,
                        "foo".parse()?,
                        "bar".parse()?
                    ]
                )))
                .collect::<Result<_>>()?
        );

        // Let's remove the "bar" tag from the third image.

        {
            let hash = hashes
                .get(&"2021-03-01T00:00:00Z".parse()?)
                .unwrap()
                .to_string();

            sqlx::query!("DELETE FROM tags WHERE hash = ?1 AND tag = 'bar'", hash)
                .execute(conn.lock().await.deref_mut())
                .await?;
        }

        // GET /images?filter=bar should yield just the fourth image now.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=bar")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 1);
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            iter::once(4)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    hashset![
                        "year:2021".parse()?,
                        format!("month:{number}").parse()?,
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
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, MEDIA_COUNT);
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            (1..=MEDIA_COUNT)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    match number {
                        4 => hashset![
                            "year:2021".parse()?,
                            format!("month:{number}").parse()?,
                            "bar".parse()?,
                            "baz".parse()?
                        ],
                        3 | 2 => hashset![
                            "year:2021".parse()?,
                            format!("month:{number}").parse()?,
                            "foo".parse()?
                        ],
                        _ => hashset!["year:2021".parse()?, format!("month:{number}").parse()?],
                    }
                )))
                .collect::<Result<_>>()?
        );

        // GET "/images?filter=year:2021 and month:7" should yield only the seventh image.

        let response = warp::test::request()
            .method("GET")
            .path("/images?filter=year:2021%20and%20month:7")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, 1);
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            iter::once(7)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    hashset!["year:2021".parse()?, format!("month:{number}").parse()?]
                )))
                .collect::<Result<_>>()?
        );

        // Let's add the "public" tag to the fourth image.

        {
            let hash = hashes
                .get(&"2021-04-01T00:00:00Z".parse()?)
                .unwrap()
                .to_string();

            sqlx::query!("INSERT INTO tags (hash, tag) VALUES (?1, 'public')", hash)
                .execute(conn.lock().await.deref_mut())
                .await?;
        }

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
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
                .collect::<HashMap<_, _>>(),
            iter::once(4)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    hashset![
                        "year:2021".parse()?,
                        format!("month:{number}").parse()?,
                        "bar".parse()?,
                        "baz".parse()?,
                        "public".parse()?
                    ]
                )))
                .collect::<Result<_>>()?
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn get_images_deduplicated() -> Result<()> {
        let TestState {
            auth_key,
            conn,
            routes,
            image_lock,
            image_dir,
            cache_dir,
            ..
        } = init().await?;

        let token = make_token(&auth_key)?;

        // Sync with the filesystem, specifying `deduplicate = false`

        sync::sync(&conn, &image_lock, image_dir, cache_dir, false, false).await?;

        // GET /images with no query parameters and with a filter-less token should yield all the images, with no
        // images marked as duplicates

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(response.total, MEDIA_COUNT);
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);

        let hashes = response
            .images
            .iter()
            .map(|data| (data.datetime, data.hash.clone()))
            .collect::<HashMap<_, _>>();

        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, (data.tags, data.duplicates)))
                .collect::<HashMap<_, _>>(),
            (1..=MEDIA_COUNT)
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    (
                        hashset!["year:2021".parse()?, format!("month:{number}").parse()?],
                        Vec::new()
                    )
                )))
                .collect::<Result<_>>()?
        );

        // Sync with the filesystem again, specifying `deduplicate = true` this time

        sync::sync(&conn, &image_lock, image_dir, cache_dir, false, true).await?;

        // This time, GET /images should yield all the images, with the last `DUPLICATE_IMAGE_COUNT +
        // DUPLICATE_VIDEO_COUNT` items deduplicated (i.e. all duplicates with lower resolutions become subordinate
        // to the duplicate with the highest resolution).

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let response = serde_json::from_slice::<ImagesResponse>(response.body())?;

        assert_eq!(response.start, 0);
        assert_eq!(
            response.total,
            MEDIA_COUNT + 2 - (DUPLICATE_IMAGE_COUNT + DUPLICATE_VIDEO_COUNT)
        );
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);

        let primary_duplicate_image = MEDIA_COUNT - DUPLICATE_VIDEO_COUNT;
        let primary_duplicate_video = MEDIA_COUNT;

        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, (data.tags, data.duplicates)))
                .collect::<HashMap<_, _>>(),
            (1..=(MEDIA_COUNT - (DUPLICATE_IMAGE_COUNT + DUPLICATE_VIDEO_COUNT)))
                .map(|number| Ok((
                    format!("2021-{number:02}-01T00:00:00Z").parse()?,
                    (
                        hashset!["year:2021".parse()?, format!("month:{number}").parse()?],
                        Vec::new()
                    )
                )))
                .chain(iter::once(Ok((
                    format!("2021-{primary_duplicate_image:02}-01T00:00:00Z").parse()?,
                    (
                        hashset![
                            "year:2021".parse()?,
                            format!("month:{primary_duplicate_image}").parse()?
                        ],
                        vec![
                            hashes
                                .get(
                                    &format!(
                                        "2021-{:02}-01T00:00:00Z",
                                        primary_duplicate_image - 1
                                    )
                                    .parse()?
                                )
                                .unwrap()
                                .clone(),
                            hashes
                                .get(
                                    &format!(
                                        "2021-{:02}-01T00:00:00Z",
                                        primary_duplicate_image - 2
                                    )
                                    .parse()?
                                )
                                .unwrap()
                                .clone()
                        ]
                    )
                ))))
                .chain(iter::once(Ok((
                    format!("2021-{primary_duplicate_video:02}-01T00:00:00Z").parse()?,
                    (
                        hashset![
                            "year:2021".parse()?,
                            format!("month:{primary_duplicate_video}").parse()?
                        ],
                        vec![
                            hashes
                                .get(
                                    &format!(
                                        "2021-{:02}-01T00:00:00Z",
                                        primary_duplicate_video - 1
                                    )
                                    .parse()?
                                )
                                .unwrap()
                                .clone(),
                            hashes
                                .get(
                                    &format!(
                                        "2021-{:02}-01T00:00:00Z",
                                        primary_duplicate_video - 2
                                    )
                                    .parse()?
                                )
                                .unwrap()
                                .clone()
                        ]
                    )
                ))))
                .collect::<Result<_>>()?
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn patch_tags() -> Result<()> {
        let TestState {
            auth_key,
            conn,
            routes,
            image_lock,
            image_dir,
            cache_dir,
            ..
        } = init().await?;

        sync::sync(&conn, &image_lock, image_dir, cache_dir, false, false).await?;

        let token = make_token(&auth_key)?;

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let hashes = serde_json::from_slice::<ImagesResponse>(response.body())?
            .images
            .iter()
            .map(|data| (data.datetime, data.hash.clone()))
            .collect::<HashMap<_, _>>();

        // Let's add the "foo" tag to the third image.

        let patches = vec![Patch {
            hash: hashes
                .get(&"2021-03-01T00:00:00Z".parse()?)
                .unwrap()
                .to_string(),
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
                .header("authorization", format!("Bearer {token}"))
                .json(&vec![Patch {
                    hash: hashes
                        .get(&"2021-03-01T00:00:00Z".parse()?)
                        .unwrap()
                        .to_string(),
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
            .header("authorization", format!("Bearer {token}"))
            .json(&patches)
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        assert_eq!(
            vec![(
                hashes
                    .get(&"2021-03-01T00:00:00Z".parse()?)
                    .unwrap()
                    .to_string(),
                "foo".to_owned()
            )],
            sqlx::query!("SELECT hash, tag FROM tags WHERE category IS NULL")
                .fetch(conn.lock().await.deref_mut())
                .and_then(|row| future::ok((row.hash, row.tag)))
                .try_collect::<Vec<_>>()
                .await?
        );

        let response = warp::test::request()
            .method("PATCH")
            .path("/tags")
            .header("authorization", format!("Bearer {token}"))
            .json(&vec![Patch {
                hash: hashes
                    .get(&"2021-03-01T00:00:00Z".parse()?)
                    .unwrap()
                    .to_string(),
                tag: "foo".parse()?,
                action: Action::Remove,
            }])
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        assert!(
            sqlx::query!("SELECT hash, category, tag FROM tags WHERE category IS NULL")
                .fetch_optional(conn.lock().await.deref_mut())
                .await?
                .is_none()
        );

        // A PATCH /tags that tries to change the year or month should yield `UNAUTHORIZED`

        for &category in &["year", "month"] {
            for &action in &[Action::Add, Action::Remove] {
                let response = warp::test::request()
                    .method("PATCH")
                    .path("/tags")
                    .header("authorization", format!("Bearer {token}"))
                    .json(&vec![Patch {
                        hash: hashes
                            .get(&"2021-04-01T00:00:00Z".parse()?)
                            .unwrap()
                            .to_string(),
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

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn get_tags() -> Result<()> {
        let TestState {
            auth_key,
            conn,
            routes,
            image_lock,
            image_dir,
            cache_dir,
            ..
        } = init().await?;

        sync::sync(&conn, &image_lock, image_dir, cache_dir, false, false).await?;

        let token = make_token(&auth_key)?;

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let hashes = serde_json::from_slice::<ImagesResponse>(response.body())?
            .images
            .iter()
            .map(|data| (data.datetime, data.hash.clone()))
            .collect::<HashMap<_, _>>();

        // GET /tags with no authorization header should yield `UNAUTHORIZED`.

        let response = warp::test::request()
            .method("GET")
            .path("/tags")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Let's add the "foo" tag to the third image.

        {
            let hash = hashes
                .get(&"2021-03-01T00:00:00Z".parse()?)
                .unwrap()
                .to_string();
            sqlx::query!("INSERT INTO tags (hash, tag) VALUES (?1, 'foo')", hash)
                .execute(conn.lock().await.deref_mut())
                .await?;
        }

        // Let's add an anonymous user to to DB.

        sqlx::query!("INSERT INTO users (filter) VALUES ('public')")
            .execute(conn.lock().await.deref_mut())
            .await?;

        // Re-generate routes since that's what checks the DB for an anonymous user.

        let routes = make_routes(&conn, &image_lock, image_dir, cache_dir, auth_key).await?;

        // Now that we've added an anonymous user to the DB, GET /tags with no authorization header should yield
        // `OK` but no tags since no images have been tagged "public" yet.

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
            .header("authorization", format!("Bearer {token}"))
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
                                tags: (1..=MEDIA_COUNT).map(|n| (Arc::from(n.to_string()), 1)).collect()
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

        // Let's add some more tags.

        {
            let second = hashes
                .get(&"2021-02-01T00:00:00Z".parse()?)
                .unwrap()
                .to_string();

            let third = hashes
                .get(&"2021-03-01T00:00:00Z".parse()?)
                .unwrap()
                .to_string();

            let fourth = hashes
                .get(&"2021-04-01T00:00:00Z".parse()?)
                .unwrap()
                .to_string();

            sqlx::query!(
                "INSERT INTO tags (hash, tag) VALUES (?1, 'foo'), (?2, 'bar'), (?3, 'bar')",
                second,
                third,
                fourth
            )
            .execute(conn.lock().await.deref_mut())
            .await?;
        }

        // GET /tags should yield the newly-applied tags.

        let response = warp::test::request()
            .method("GET")
            .path("/tags")
            .header("authorization", format!("Bearer {token}"))
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
                                tags: (1..=MEDIA_COUNT).map(|n| (Arc::from(n.to_string()), 1)).collect()
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

        // GET /tags?filter=foo should yield the tags and counts applied to images with that tag.

        let response = warp::test::request()
            .method("GET")
            .path("/tags?filter=foo")
            .header("authorization", format!("Bearer {token}"))
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
                                tags: (2..=3).map(|n| (Arc::from(n.to_string()), 1)).collect()
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

        // GET /tags?filter=bar should yield the tags and counts applied to images with that tag.

        let response = warp::test::request()
            .method("GET")
            .path("/tags?filter=bar")
            .header("authorization", format!("Bearer {token}"))
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
                                tags: (3..=4).map(|n| (Arc::from(n.to_string()), 1)).collect()
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

        // GET "/tags?filter=foo and bar" should yield the tags and counts applied to images with both tags.

        let response = warp::test::request()
            .method("GET")
            .path("/tags?filter=foo%20and%20bar")
            .header("authorization", format!("Bearer {token}"))
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

        // GET /tags?filter=foo or bar should yield the tags and counts applied to images with either tag.

        let response = warp::test::request()
            .method("GET")
            .path("/tags?filter=foo%20or%20bar")
            .header("authorization", format!("Bearer {token}"))
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
                                tags: (2..=4).map(|n| (Arc::from(n.to_string()), 1)).collect()
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

        // Let's add the "baz" tag to the fourth image.

        {
            let hash = hashes
                .get(&"2021-04-01T00:00:00Z".parse()?)
                .unwrap()
                .to_string();

            sqlx::query!("INSERT INTO tags (hash, tag) VALUES (?1, 'baz')", hash)
                .execute(conn.lock().await.deref_mut())
                .await?;
        }

        // GET "/tags?filter=bar and (foo or baz)" should yield the tags and counts applied to images which match
        // that expression.

        let response = warp::test::request()
            .method("GET")
            .path("/tags?filter=bar%20and%20%28foo%20or%20baz%29")
            .header("authorization", format!("Bearer {token}"))
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
                                tags: (3..=4).map(|n| (Arc::from(n.to_string()), 1)).collect()
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

        // Let's add the "public" tag to the fourth image.

        {
            let hash = hashes
                .get(&"2021-04-01T00:00:00Z".parse()?)
                .unwrap()
                .to_string();

            sqlx::query!("INSERT INTO tags (hash, tag) VALUES (?1, 'public')", hash)
                .execute(conn.lock().await.deref_mut())
                .await?;
        }

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

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn get_image() -> Result<()> {
        let TestState {
            auth_key,
            conn,
            routes,
            image_lock,
            image_dir,
            cache_dir,
            info,
        } = init().await?;

        sync::sync(&conn, &image_lock, image_dir, cache_dir, false, false).await?;

        let token = make_token(&auth_key)?;

        let response = warp::test::request()
            .method("GET")
            .path("/images")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await;

        assert_eq!(response.status(), StatusCode::OK);

        let images = serde_json::from_slice::<ImagesResponse>(response.body())?
            .images
            .into_iter()
            .map(|data| (data.datetime, data))
            .collect::<HashMap<_, _>>();

        // The images and thumbnails should contain the colors we specified in `init`.

        fn close_enough(a: Rgb<u8>, b: Rgb<u8>) -> bool {
            const EPSILON: i32 = 10;

            a.0.iter()
                .zip(b.0.iter())
                .all(|(&a, &b)| ((a as i32) - (b as i32)).abs() < EPSILON)
        }

        let mut random = StdRng::seed_from_u64(7322);

        for (&number, info) in info.deref() {
            for variant in &[
                Variant::Still(Size::Small),
                Variant::Still(Size::Large),
                Variant::Video(Size::Small),
                Variant::Video(Size::Large),
                Variant::Original,
            ] {
                let data = images
                    .get(&format!("2021-{number:02}-01T00:00:00Z").parse()?)
                    .unwrap();

                if matches!(variant, Variant::Still(_) | Variant::Original)
                    || matches!(data.medium, Medium::ImageWithVideo | Medium::Video)
                {
                    let response = warp::test::request()
                        .method("GET")
                        .path(&format!("/image/{variant}/{}", data.hash))
                        .reply(&routes)
                        .await;

                    assert_eq!(response.status(), StatusCode::OK);

                    let image = if matches!(variant, Variant::Still(_))
                        || (matches!(variant, Variant::Original)
                            && matches!(data.medium, Medium::Image | Medium::ImageWithVideo))
                    {
                        if matches!(variant, Variant::Original) {
                            image::load_from_memory_with_format(response.body(), ImageFormat::Jpeg)
                                .map_err(Error::from)
                        } else {
                            webp::Decoder::new(response.body())
                                .decode()
                                .map(|image| image.to_image())
                                .ok_or_else(|| anyhow!("invalid WebP image"))
                        }
                    } else {
                        tracing::info!("body size is {}", response.body().len());

                        let mut tmp = TempFile(Some(task::block_in_place(NamedTempFile::new)?));

                        task::block_in_place(|| {
                            tmp.0.as_mut().unwrap().write_all(response.body())
                        })?;

                        let output = Command::new("ffmpeg")
                            .arg("-i")
                            .arg(tmp.0.as_ref().unwrap().path())
                            .arg("-ss")
                            .arg(format!("00:00:0{}", random.gen_range(0..4)))
                            .arg("-frames:v")
                            .arg("1")
                            .arg("-f")
                            .arg("singlejpeg")
                            .arg("-")
                            .output()
                            .await?;

                        if output.status.success() {
                            tracing::info!("ffmpeg result size is {}", output.stdout.len());

                            image::load_from_memory_with_format(&output.stdout, ImageFormat::Jpeg)
                                .map_err(Error::from)
                        } else {
                            return Err(anyhow!(
                                "error running ffmpeg: {}",
                                String::from_utf8_lossy(&output.stderr)
                            ));
                        }
                    }?
                    .to_rgb8();

                    assert_eq!(
                        (image.width(), image.height()),
                        match variant {
                            Variant::Still(Size::Small) | Variant::Video(Size::Small) =>
                                media::SMALL_BOUNDS,

                            Variant::Still(Size::Large) => media::LARGE_BOUNDS,

                            Variant::Original | Variant::Video(Size::Large) => dimensions(number),
                        }
                    );

                    for _ in 0..10 {
                        let x = random.gen_range(0..image.width());
                        let y = random.gen_range(0..image.height());

                        let pixel = *image.get_pixel(x, y);

                        assert!(
                            close_enough(pixel, info.color),
                            "expected {:?}; got {pixel:?} for {variant}/{} at ({x},{y})",
                            info.color,
                            data.hash,
                        );
                    }
                }
            }
        }

        Ok(())
    }
}
