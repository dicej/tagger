#![deny(warnings)]

use {
    anyhow::Result,
    std::{process, sync::Arc, time::Duration},
    structopt::StructOpt,
    tagger_server::Options,
    tokio::{sync::Mutex as AsyncMutex, task, time},
    tracing::error,
};

const SYNC_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init_timed();

    let options = Arc::new(Options::from_args());

    let conn = Arc::new(AsyncMutex::new(
        tagger_server::open(&options.state_file).await?,
    ));

    task::spawn({
        let options = options.clone();
        let conn = conn.clone();

        async move {
            loop {
                if let Err(e) = tagger_server::sync(
                    &conn,
                    &options.image_directory,
                    &options.cache_directory,
                    options.preload_cache,
                )
                .await
                {
                    error!("sync error: {:?}", e);
                    process::exit(-1)
                }

                time::sleep(SYNC_INTERVAL).await;
            }
        }
    });

    tagger_server::serve(&conn, &options).await
}
