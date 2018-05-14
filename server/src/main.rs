#![deny(warnings)]

extern crate chrono;
extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate hyper;
#[macro_use]
extern crate log;
extern crate mime;
extern crate regex;
extern crate rexiv2;
extern crate rusqlite;
#[macro_use]
extern crate serde_json;
extern crate image;
extern crate sha2;
extern crate unicase;

use chrono::Local;
use clap::{App, Arg};
use env_logger::LogBuilder;
use failure::Error;
use futures::future::{ok, result};
use futures::{Future, Stream};
use hyper::header::{AccessControlAllowHeaders, AccessControlAllowMethods,
                    AccessControlAllowOrigin, ContentLength, ContentType};
use hyper::server::{Http, Service};
use hyper::{Method, Request, Response, StatusCode};
use image::{load_from_memory_with_format, FilterType, GenericImage, ImageFormat, ImageOutputFormat};
use regex::Regex;
use rexiv2::Metadata;
use rusqlite::{Connection, DatabaseName};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::ffi::OsStr;
use std::fs::{read_dir, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::rc::Rc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{sleep, spawn};
use std::time::{Duration, Instant};
use unicase::Ascii;

const SMALL_BOUNDS: (u32, u32) = (320, 240);
const LARGE_BOUNDS: (u32, u32) = (1920, 1440);
const JPEG_QUALITY: u8 = 90;

// todo: upgrade to a new Tokio and use `blocking` API for anywhere we
// might block (e.g. filesystem, mutex, DB, image processing)

fn init_logger() -> Result<(), Error> {
    let mut builder = LogBuilder::new();
    builder.format(|record| {
        format!(
            "{} {} - {}",
            Local::now().format("%F %T"),
            record.level(),
            record.args()
        )
    });

    if let Ok(s) = env::var("RUST_LOG") {
        builder.parse(&s);
    }

    builder.init().map_err(Error::from)
}

fn open(state_file: &str) -> Result<Connection, Error> {
    let conn = Connection::open(state_file)?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS paths (
           path      TEXT NOT NULL PRIMARY KEY,
           hash      TEXT NOT NULL
         )",
        &[],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS images (
           hash      TEXT NOT NULL PRIMARY KEY,
           datetime  TEXT NOT NULL,
           small BLOB,
           large BLOB
         )",
        &[],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS tags (
           hash      TEXT NOT NULL,
           tag       TEXT NOT NULL,

           PRIMARY KEY (hash, tag),
           FOREIGN KEY (hash) REFERENCES images(hash) ON DELETE CASCADE
         )",
        &[],
    )?;

    Ok(conn)
}

fn content<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, Error> {
    let mut buffer = Vec::new();
    File::open(path)?.read_to_end(&mut buffer)?;
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

fn lock(conn: &Arc<Mutex<Connection>>) -> Result<MutexGuard<Connection>, Error> {
    conn.lock().map_err(|_| format_err!("poisoned lock"))
}

fn find_new<P: AsRef<Path>>(
    conn: &Arc<Mutex<Connection>>,
    root: &str,
    result: &mut Vec<(String, String)>,
    dir: P,
    pattern: &Regex,
) -> Result<(), Error> {
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
                    let stripped = path.strip_prefix(root)?
                        .to_str()
                        .ok_or_else(|| format_err!("bad utf8"))?;
                    let lock = lock(conn)?;
                    let mut stmt = lock.prepare("SELECT 1 FROM paths WHERE path = ?1")?;
                    if let None = stmt.query_map(&[&stripped], |_| ())?.next() {
                        if let Some(datetime) = Metadata::new_from_path(&path)
                            .and_then(|m| m.get_tag_string("Exif.Image.DateTime"))
                            .ok()
                            .and_then(|s| {
                                pattern.captures(&s).map(|c| {
                                    format!(
                                        "{}-{}-{} {}:{}:{}",
                                        &c[1], &c[2], &c[3], &c[4], &c[5], &c[6]
                                    )
                                })
                            }) {
                            result.push((stripped.to_string(), datetime))
                        } else {
                            warn!("unable to get metadata for {}", lowercase);
                        }
                    }
                    drop(stmt);
                }
            }
        } else if path.is_dir() {
            find_new(conn, root, result, path, pattern)?;
        }
    }

    Ok(())
}

fn sync(conn: &Arc<Mutex<Connection>>, image_dir: &str, pattern: &Regex) -> Result<(), Error> {
    let then = Instant::now();

    let obsolete = {
        let lock = lock(conn)?;
        let mut stmt = lock.prepare("SELECT path FROM paths")?;
        let obsolete = stmt.query_map(&[], |row| row.get::<i32, String>(0))?
            .filter_map(Result::ok)
            .filter(|path| ![image_dir, path].iter().collect::<PathBuf>().is_file())
            .collect::<Vec<_>>();
        drop(stmt);
        obsolete
    };

    let new = {
        let mut result = Vec::new();
        find_new(conn, image_dir, &mut result, image_dir, pattern)?;
        result
    };

    for &(ref path, ref datetime) in new.iter() {
        let hash = hash(&content([image_dir, &path].iter().collect::<PathBuf>())?);
        info!("insert {} (hash {})", path, hash);
        let mut lock = lock(conn)?;
        let transaction = lock.transaction()?;
        transaction.execute(
            "INSERT INTO paths (path, hash) VALUES (?1, ?2)",
            &[path, &hash],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO images (hash, datetime) VALUES (?1, ?2)",
            &[&hash, datetime],
        )?;
        transaction.commit()?;
    }

    for path in obsolete.iter() {
        info!("delete {}", path);
        let mut lock = lock(conn)?;
        let transaction = lock.transaction()?;
        let mut stmt = transaction.prepare("SELECT hash FROM paths WHERE path = ?1")?;
        if let Some(hash) = stmt.query_map(&[path], |row| row.get::<_, String>(0))?
            .filter_map(Result::ok)
            .next()
        {
            transaction.execute("DELETE FROM paths WHERE path = ?1", &[path])?;
            let mut stmt = transaction.prepare("SELECT 1 FROM paths WHERE hash = ?1")?;
            if let None = stmt.query_map(&[path], |_| ())?.next() {
                transaction.execute("DELETE FROM images WHERE hash = ?1", &[&hash])?;
            }
            drop(stmt);
        }
        drop(stmt);
    }

    info!(
        "sync took {} seconds (added {}; deleted {})",
        then.elapsed().as_secs(),
        new.len(),
        obsolete.len()
    );

    Ok(())
}

fn state(conn: &Arc<Mutex<Connection>>) -> Result<Value, Error> {
    let mut map = Map::new();
    let lock = lock(conn)?;
    let mut stmt = lock.prepare(
        "SELECT i.hash, i.datetime, t.tag FROM images AS i LEFT JOIN tags AS t ON i.hash = t.hash",
    )?;
    for (hash, datetime, tag) in stmt.query_map(&[], |row| {
        (
            row.get::<_, String>(0),
            row.get::<_, String>(1),
            row.get::<_, Option<String>>(2),
        )
    })?
        .filter_map(Result::ok)
    {
        let found = if let Some(&mut Value::Object(ref mut map)) = map.get_mut(&hash) {
            if let Some(&mut Value::Array(ref mut tags)) = map.get_mut("tags") {
                tags.extend(tag.iter().cloned().map(Value::String));
                true
            } else {
                unimplemented!()
            }
        } else {
            false
        };

        if !found {
            map.insert(
                hash,
                json!({
                    "datetime": datetime,
                    "tags": tag.iter().collect::<Vec<_>>(),
                }),
            );
        }
    }
    Ok(Value::Object(map))
}

fn apply(conn: &Arc<Mutex<Connection>>, patch: Value) -> Result<(), Error> {
    let hash = patch["hash"]
        .as_str()
        .ok_or_else(|| format_err!("hash not found in {}", patch))?;

    let tag = patch["tag"]
        .as_str()
        .ok_or_else(|| format_err!("tag not found in {}", patch))?;

    match patch["action"].as_str() {
        Some("add") => lock(conn)?
            .execute(
                "INSERT INTO tags (hash, tag) VALUES (?1, ?2)",
                &[&hash, &tag],
            )
            .map(drop)
            .map_err(Error::from),
        Some("remove") => lock(conn)?
            .execute(
                "DELETE FROM tags WHERE hash = ?1 AND tag = ?2",
                &[&hash, &tag],
            )
            .map(drop)
            .map_err(Error::from),
        _ => Err(format_err!("missing or unexpected action in {}", patch)),
    }
}

fn full_size_image(
    conn: &Arc<Mutex<Connection>>,
    image_dir: &str,
    path: &str,
) -> Result<Vec<u8>, Error> {
    let lock = lock(conn)?;
    let mut stmt = lock.prepare("SELECT path FROM paths WHERE hash = ?1 LIMIT 1")?;
    let result = if let Some(path) = stmt.query_map(&[&path], |row| row.get::<_, String>(0))?
        .filter_map(Result::ok)
        .next()
    {
        content([image_dir, &path].iter().collect::<PathBuf>())
    } else {
        Err(format_err!("image not found: {}", path))
    };
    drop(stmt);
    result
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

fn image(conn: &Arc<Mutex<Connection>>, image_dir: &str, path: &str) -> Result<Vec<u8>, Error> {
    if path.starts_with("small/") || path.starts_with("large/") {
        let mut split = path.split('/');
        if let (Some(size), Some(path)) = (split.next(), split.next()) {
            let result = {
                let lock = lock(conn)?;
                let mut stmt = lock.prepare("SELECT rowid FROM images WHERE hash = ?1 LIMIT 1")?;
                let row = stmt.query_map(&[&path], |row| row.get::<_, i64>(0))?
                    .filter_map(Result::ok)
                    .next();
                drop(stmt);

                let result = row.and_then(|row| {
                    lock.blob_open(DatabaseName::Main, "images", size, row, true)
                        .ok()
                }).and_then(|mut blob| {
                    let mut result = Vec::new();
                    blob.read_to_end(&mut result).ok().map(|_| result)
                });

                result
            };

            if let Some(result) = result {
                Ok(result)
            } else {
                let native_size = load_from_memory_with_format(
                    &full_size_image(conn, image_dir, path)?,
                    ImageFormat::JPEG,
                )?;

                let (width, height) = bound(
                    native_size.dimensions(),
                    if size == "small" {
                        SMALL_BOUNDS
                    } else {
                        LARGE_BOUNDS
                    },
                );

                let mut encoded = Vec::new();
                native_size
                    .resize(width, height, FilterType::Lanczos3)
                    .write_to(&mut encoded, ImageOutputFormat::JPEG(JPEG_QUALITY))?;

                lock(conn)?
                    .execute(
                        &format!("UPDATE images SET {} = ?1 WHERE hash = ?2", size),
                        &[&encoded, &path],
                    )
                    .map(drop)
                    .map_err(Error::from)?;

                Ok(encoded)
            }
        } else {
            Err(format_err!("malformed image path: {}", path))
        }
    } else {
        full_size_image(conn, image_dir, path)
    }
}

fn public(public_dir: &str, path: &str) -> Result<(Vec<u8>, ContentType), Error> {
    content([public_dir, path].iter().collect::<PathBuf>()).map(|bytes| {
        (
            bytes,
            match Path::new(path).extension().and_then(OsStr::to_str) {
                Some("html") => ContentType::html(),
                Some("js") => ContentType(mime::TEXT_JAVASCRIPT),
                Some("css") => ContentType(mime::TEXT_CSS),
                _ => ContentType::octet_stream(),
            },
        )
    })
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

fn handle(
    conn: &Arc<Mutex<Connection>>,
    image_dir: &str,
    public_dir: &str,
    req: Request,
) -> Box<Future<Item = Response, Error = Error>> {
    type F = Box<Future<Item = Response, Error = Error>>;

    match (req.method(), req.path().to_string().as_ref()) {
        (&Method::Post, "/patch") => {
            let conn = conn.clone();
            Box::new(
                req.body()
                    .concat2()
                    .from_err()
                    .and_then(move |body| {
                        result(
                            serde_json::from_slice(&body)
                                .map_err(Error::from)
                                .and_then(|patch| apply(&conn, patch)),
                        )
                    })
                    .map(|_| {
                        let body = "OK";
                        response()
                            .with_header(ContentLength(body.len() as u64))
                            .with_header(ContentType::plaintext())
                            .with_body(body)
                    }),
            ) as F
        }

        (&Method::Post, _) => {
            Box::new(ok(response().with_status(StatusCode::MethodNotAllowed))) as F
        }

        (&Method::Get, "/state") => Box::new(result(state(conn).map(|state| {
            let state = state.to_string().as_bytes().to_vec();
            response()
                .with_header(ContentLength(state.len() as u64))
                .with_header(ContentType::json())
                .with_body(state)
        }))) as F,

        (&Method::Get, path) => if path.starts_with("/images/") {
            Box::new(result(image(conn, image_dir, &path[8..]).map(|image| {
                response()
                    .with_header(ContentLength(image.len() as u64))
                    .with_header(ContentType::jpeg())
                    .with_body(image)
            }))) as F
        } else {
            Box::new(result(public(public_dir, &path[1..]).map(
                |(file, content_type)| {
                    response()
                        .with_header(ContentLength(file.len() as u64))
                        .with_header(content_type)
                        .with_body(file)
                },
            ))) as F
        },

        _ => Box::new(ok(response().with_status(StatusCode::MethodNotAllowed))) as F,
    }
}

fn serve(
    conn: &Arc<Mutex<Connection>>,
    address: &str,
    image_dir: &str,
    public_dir: &str,
) -> Result<(), Error> {
    struct Server {
        conn: Arc<Mutex<Connection>>,
        image_dir: Rc<String>,
        public_dir: Rc<String>,
    }

    impl Service for Server {
        type Request = Request;
        type Response = Response;
        type Error = hyper::Error;
        type Future = Box<Future<Item = Response, Error = hyper::Error>>;

        fn call(&self, req: Request) -> Self::Future {
            Box::new(
                handle(&self.conn, &self.image_dir, &self.public_dir, req).or_else(|e| {
                    error!("request error: {:?}", e);
                    let body = format!("{:?}", e);
                    Box::new(ok(response()
                        .with_status(StatusCode::InternalServerError)
                        .with_header(ContentLength(body.len() as u64))
                        .with_header(ContentType::plaintext())
                        .with_body(body)))
                }),
            )
        }
    }

    let conn = conn.clone();
    let image_dir = Rc::new(image_dir.to_string());
    let public_dir = Rc::new(public_dir.to_string());
    let mut server = Http::new().bind(&address.parse()?, move || {
        Ok(Server {
            conn: conn.clone(),
            image_dir: image_dir.clone(),
            public_dir: public_dir.clone(),
        })
    })?;
    server.no_proto();
    server.run().map_err(Error::from)
}

fn run(address: &str, image_dir: &str, state_file: &str, public_dir: &str) -> Result<(), Error> {
    init_logger()?;

    let conn = Arc::new(Mutex::new(open(state_file)?));

    let pattern = Regex::new(r"(\d{4}):(\d{2}):(\d{2}) (\d{2}):(\d{2}):(\d{2})")?;

    sync(&conn, image_dir, &pattern)?;

    {
        let image_dir = image_dir.to_string();
        let conn = conn.clone();
        let pattern = pattern.clone();

        spawn(move || loop {
            sleep(Duration::from_secs(10));

            if let Err(e) = sync(&conn, &image_dir, &pattern) {
                error!("sync error: {:?}", e);
                exit(-1)
            }
        });
    }

    serve(&conn, address, image_dir, public_dir)
}

fn arg(name: &str) -> Arg {
    Arg::with_name(name).takes_value(true).required(true)
}

fn main() {
    let matches = App::new(env!("CARGO_PKG_DESCRIPTION"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .arg(arg("address").help("address to which to bind"))
        .arg(arg("image directory").help("directoring containing image files"))
        .arg(arg("state file").help("SQLite database of image metadata to create or reuse"))
        .arg(arg("public directory").help("directory containing static resources"))
        .get_matches();

    if let Err(e) = run(
        matches.value_of("address").unwrap(),
        matches.value_of("image directory").unwrap(),
        matches.value_of("state file").unwrap(),
        matches.value_of("public directory").unwrap(),
    ) {
        error!("exit on error: {:?}", e);
        exit(-1)
    }
}
