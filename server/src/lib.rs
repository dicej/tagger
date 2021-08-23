#![deny(warnings)]

use {
    crate::warp_util::{Bearer, HttpDate, HttpError, Ranges},
    anyhow::{anyhow, Result},
    futures::future::{FutureExt, TryFutureExt},
    http::{
        header,
        response::{self, Response},
        status::StatusCode,
    },
    hyper::Body,
    sqlx::{
        query::Query,
        sqlite::{SqliteArguments, SqliteConnectOptions},
        ConnectOptions, Sqlite, SqliteConnection,
    },
    std::{
        convert::Infallible,
        net::SocketAddrV4,
        ops::DerefMut,
        panic::{self, AssertUnwindSafe},
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
    warp::{Filter, Rejection, Reply},
};

pub use {
    auth::hash_password,
    media::{preload_cache, FileData},
    sync::sync,
};

mod auth;
mod images;
mod media;
mod sync;
mod tags;
mod warp_util;

const INVALID_CREDENTIAL_DELAY_SECS: u64 = 5;

const BUFFER_SIZE: usize = 16 * 1024;

#[derive(StructOpt, Debug)]
#[structopt(name = "tagger-server", about = "Image tagging webapp backend")]
pub struct Options {
    /// Address to which to bind
    #[structopt(long)]
    pub address: SocketAddrV4,

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

    /// If set, pre-generate thumnail cache files for newly-discovered images and videos when syncing
    #[structopt(long)]
    pub preload_cache: bool,
}

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

fn response() -> response::Builder {
    Response::builder()
}

async fn routes(
    conn: &Arc<AsyncMutex<SqliteConnection>>,
    image_lock: &Arc<AsyncRwLock<()>>,
    options: &Arc<Options>,
    default_auth_key: [u8; 32],
    invalid_credential_delay: Duration,
) -> Result<impl Filter<Extract = (impl Reply,), Error = Infallible> + Clone> {
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
                    warn!("error authorizing: {:?}", e);

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
                                warn!(?auth, "error retrieving state: {:?}", e);

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
                                    warn!(?auth, "error retrieving tags: {:?}", e);

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
                                    warn!("error retrieving image {}: {:?}", hash, e);

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
        .map(|reply| warp::reply::with_header(reply, "Accept-Ranges", "bytes")))
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

#[cfg(test)]
mod test {
    use {
        super::*,
        anyhow::Error,
        image::ImageFormat,
        image::{ImageBuffer, Rgb},
        maplit::{hashmap, hashset},
        rand::{rngs::StdRng, Rng, SeedableRng},
        rexiv2::Metadata as ExifMetadata,
        std::{collections::HashMap, iter},
        tagger_shared::{
            tag_expression::Tag, Action, ImagesResponse, TagsResponse, TokenError, TokenSuccess,
        },
        tempfile::TempDir,
        tokio::task,
    };

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
            let hash = auth::hash_password(user.as_bytes(), password.as_bytes());

            sqlx::query!(
                "INSERT INTO users (name, password_hash, may_patch) VALUES (?1, ?2, 1)",
                user,
                hash,
            )
            .execute(&mut conn)
            .await?;
        }

        sqlx::query!("INSERT INTO users (filter) VALUES ('public')")
            .execute(&mut conn)
            .await?;

        let conn = Arc::new(AsyncMutex::new(conn));

        let image_tmp_dir = TempDir::new()?;
        let image_dir = image_tmp_dir
            .path()
            .to_str()
            .ok_or_else(|| anyhow!("invalid UTF-8"))?;

        let cache_tmp_dir = TempDir::new()?;
        let cache_dir = cache_tmp_dir
            .path()
            .to_str()
            .ok_or_else(|| anyhow!("invalid UTF-8"))?;

        let mut auth_key = [0u8; 32];
        rand::thread_rng().fill(&mut auth_key);

        let image_lock = Arc::new(AsyncRwLock::new(()));

        let routes = routes(
            &conn,
            &image_lock,
            &Arc::new(Options {
                address: "0.0.0.0:0".parse()?,
                image_directory: image_dir.to_owned(),
                cache_directory: cache_dir.to_owned(),
                state_file: "does-not-exist-2a1dad1c-e044-4b95-be08-3a3f72d5ac0a".to_string(),
                public_directory: "does-not-exist-2a1dad1c-e044-4b95-be08-3a3f72d5ac0a".to_string(),
                cert_file: None,
                key_file: None,
                auth_key_file: None,
                preload_cache: false,
            }),
            auth_key,
            Duration::from_secs(0),
        )
        .await?;

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
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
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

                let metadata = ExifMetadata::new_from_path(&path)?;

                metadata.set_tag_string(
                    "Exif.Image.DateTimeOriginal",
                    &format!("2021:{:02}:01 00:00:00", number),
                )?;

                metadata.save_to_file(&path)?;

                Ok::<_, Error>(())
            })?;
        }

        sync::sync(&conn, &image_lock, image_dir, cache_dir, false).await?;

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
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
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
                .header("authorization", format!("Bearer {}", token))
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
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
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
                                tags: (1..=image_count).map(|n| (Arc::from(n.to_string()), 1)).collect()
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
                .to_string(),
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
                                .to_string(),
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
                                tags: (1..=image_count).map(|n| (Arc::from(n.to_string()), 1)).collect()
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
                .to_string(),
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
                .to_string(),
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
        assert_eq!(response.later_start, None);
        assert_eq!(response.earliest_start, None);
        assert_eq!(
            response
                .images
                .into_iter()
                .map(|data| (data.datetime, data.tags))
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

        // Let's add the "public" tag to the fourth image.

        let patches = vec![Patch {
            hash: hashes
                .get(&"2021-04-01T00:00:00Z".parse()?)
                .unwrap()
                .to_string(),
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
                        "/image/{}/{}",
                        match size {
                            Size::Small => "small",
                            Size::Large => "large",
                            Size::Original => "original",
                        },
                        hashes
                            .get(&format!("2021-{:02}-01T00:00:00Z", number).parse()?)
                            .unwrap()
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
                        Size::Small => media::SMALL_BOUNDS,
                        Size::Large => media::LARGE_BOUNDS,
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
