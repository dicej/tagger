#![deny(warnings)]

use anyhow::Result;
use std::{process, sync::Arc, time::Duration};
use structopt::StructOpt;
use tagger_server::Options;
use tokio::{sync::Mutex as AsyncMutex, task, time};
use tracing::error;

const SYNC_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init_timed();

    let options = Arc::new(Options::from_args());

    let conn = Arc::new(AsyncMutex::new(
        tagger_server::open(&options.state_file).await?,
    ));

    tagger_server::sync(
        &conn,
        &options.image_directory,
        &options.cache_directory,
        options.preload_cache,
    )
    .await?;

    task::spawn({
        let options = options.clone();
        let conn = conn.clone();

        async move {
            loop {
                time::sleep(SYNC_INTERVAL).await;

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
            }
        }
    });

    tagger_server::serve(&conn, &options).await
}
