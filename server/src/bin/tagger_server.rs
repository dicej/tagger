#![deny(warnings)]

use {
    anyhow::{anyhow, Result},
    futures::{
        channel::mpsc::{self, Sender},
        future, stream, FutureExt, SinkExt, StreamExt, TryFutureExt, TryStreamExt,
    },
    rand::Rng,
    sqlx::SqliteConnection,
    std::{ops::DerefMut, process, sync::Arc, time::Duration},
    structopt::StructOpt,
    tagger_server::{FileData, ItemData, LockMap, Options, PreloadPolicy},
    tokio::{fs::File, io::AsyncReadExt, sync::Mutex as AsyncMutex, task, time},
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
    image_locks: Arc<LockMap<Arc<str>, ()>>,
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
            &image_locks,
            &options.image_directory,
            &options.cache_directory,
            match options.preload_policy {
                PreloadPolicy::None => false,
                PreloadPolicy::New | PreloadPolicy::All => true,
            },
            options.deduplicate,
        )
        .await?;

        time::sleep(SYNC_INTERVAL).await;

        image_locks.clean().await;

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
    pretty_env_logger::init();

    let options = Arc::new(Options::from_args());

    let conn = Arc::new(AsyncMutex::new(
        tagger_server::open(&options.state_file).await?,
    ));

    let image_locks = Arc::new(LockMap::default());

    let (restart_tx, mut restart_rx) = mpsc::channel(2);

    task::spawn(
        {
            let conn = conn.clone();
            let options = options.clone();
            let image_locks = image_locks.clone();

            async move {
                if let PreloadPolicy::All = options.preload_policy {
                    let images = sqlx::query!(
                        "SELECT i.hash, i.video_offset, min(p.path) as \"path!: String\" \
                         FROM images i \
                         INNER JOIN paths p \
                         ON i.hash = p.hash \
                         GROUP BY i.hash"
                    )
                    .fetch(conn.lock().await.deref_mut())
                    .map_ok(|row| ItemData {
                        hash: row.hash,
                        file: FileData {
                            video_offset: row.video_offset,
                            path: row.path,
                        },
                    })
                    .collect::<Vec<_>>()
                    .await;

                    let errors = tagger_server::preload_cache_all(
                        &image_locks,
                        &options.image_directory,
                        &options.cache_directory,
                        stream::iter(images),
                    )
                    .await?;

                    for (item, _) in errors {
                        tagger_server::mark_bad(&conn, &item.hash).await?;
                    }
                }

                sync_loop(options, conn, image_locks, restart_tx).await
            }
        }
        .map_err(|e| {
            error!("sync error: {e:?}");
            process::exit(-1)
        }),
    );

    let mut default_auth_key = [0u8; 32];
    rand::thread_rng().fill(&mut default_auth_key);

    loop {
        future::select(
            tagger_server::serve(&conn, &image_locks, &options, default_auth_key).boxed(),
            restart_rx
                .next()
                .map(|o| o.ok_or_else(|| anyhow!("unexpected end of stream"))),
        )
        .await
        .factor_first()
        .0?;
    }
}
