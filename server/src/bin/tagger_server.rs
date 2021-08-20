#![deny(warnings)]

use {
    anyhow::{anyhow, Result},
    futures::{
        channel::mpsc::{self, Sender},
        future, FutureExt, SinkExt, StreamExt, TryFutureExt,
    },
    rand::Rng,
    sqlx::SqliteConnection,
    std::{process, sync::Arc, time::Duration},
    structopt::StructOpt,
    tagger_server::Options,
    tokio::{
        fs::File,
        io::AsyncReadExt,
        sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock},
        task, time,
    },
    tracing::{error, info},
};

const SYNC_INTERVAL: Duration = Duration::from_secs(10 * 60);

async fn content(file_name: &str) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    File::open(file_name)
        .await?
        .read_to_end(&mut buffer)
        .await?;

    Ok(buffer)
}

async fn sync_loop(
    options: Arc<Options>,
    conn: Arc<AsyncMutex<SqliteConnection>>,
    image_lock: Arc<AsyncRwLock<()>>,
    mut restart_tx: Sender<()>,
) -> Result<()> {
    let mut cert_and_key =
        if let (Some(cert_file), Some(key_file)) = (&options.cert_file, &options.key_file) {
            Some((
                cert_file,
                content(cert_file).await?,
                key_file,
                content(key_file).await?,
            ))
        } else {
            None
        };

    let mut auth_key = if let Some(auth_key_file) = &options.auth_key_file {
        Some((auth_key_file, content(auth_key_file).await?))
    } else {
        None
    };

    loop {
        tagger_server::sync(
            &conn,
            &image_lock,
            &options.image_directory,
            &options.cache_directory,
            options.preload_cache,
        )
        .await?;

        time::sleep(SYNC_INTERVAL).await;

        if let Some((cert_file, old_cert, key_file, old_key)) = &mut cert_and_key {
            let new_cert = content(cert_file).await?;
            let new_key = content(key_file).await?;

            if *old_cert != new_cert || *old_key != new_key {
                *old_cert = new_cert;
                *old_key = new_key;

                info!("cert or key changed -- restarting");
                restart_tx.send(()).await?;
            }
        }

        if let Some((key_file, old_key)) = &mut auth_key {
            let new_key = content(key_file).await?;

            if *old_key != new_key {
                *old_key = new_key;

                info!("auth key changed -- restarting");
                restart_tx.send(()).await?;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init_timed();

    let options = Arc::new(Options::from_args());

    let conn = Arc::new(AsyncMutex::new(
        tagger_server::open(&options.state_file).await?,
    ));

    // TODO: This lock is used to ensure no more than one task tries to read/write the same cache file
    // concurrently.  However, it's way too conservative since it prevents more than one task from writing any
    // cache files concurrently -- even unrelated ones.  We should use separate locks per image hash.
    let image_lock = Arc::new(AsyncRwLock::new(()));

    let (restart_tx, mut restart_rx) = mpsc::channel(2);

    task::spawn(
        sync_loop(
            options.clone(),
            conn.clone(),
            image_lock.clone(),
            restart_tx,
        )
        .map_err(|e| {
            error!("sync error: {:?}", e);
            process::exit(-1)
        }),
    );

    let mut default_auth_key = [0u8; 32];
    rand::thread_rng().fill(&mut default_auth_key);

    loop {
        future::select(
            tagger_server::serve(&conn, &image_lock, &options, default_auth_key).boxed(),
            restart_rx
                .next()
                .map(|o| o.ok_or_else(|| anyhow!("unexpected end of stream"))),
        )
        .await
        .factor_first()
        .0?;
    }
}
