#![deny(warnings)]

use anyhow::{anyhow, Error, Result};
use futures::future::TryFutureExt;
use sycamore::prelude::{self as syc, template, Signal};
use tagger_shared::{GrantType, ImagesResponse, TagsResponse, TokenRequest, TokenSuccess};

fn main() -> Result<()> {
    log::set_logger(&wasm_bindgen_console_logger::DEFAULT_LOGGER)
        .map_err(|e| anyhow!("{:?}", e))?;
    log::set_max_level(log::LevelFilter::Info);

    let tags = Signal::new(String::new());
    let images = Signal::new(String::new());

    let location = web_sys::window()
        .ok_or_else(|| anyhow!("can't get browser window"))?
        .location();

    let root = format!(
        "{}//{}",
        location.protocol().map_err(|e| anyhow!("{:?}", e))?,
        location.host().map_err(|e| anyhow!("{:?}", e))?
    );

    log::info!("root is {}", root);

    wasm_bindgen_futures::spawn_local({
        let tags = tags.clone();
        let images = images.clone();

        async move {
            let client = reqwest::Client::new();

            let authorization = format!(
                "Bearer {}",
                client
                    .post(format!("{}/token", root))
                    .form(&TokenRequest {
                        grant_type: GrantType::Password,
                        username: "Jabberwocky".into(),
                        password: "Bandersnatch".into()
                    })
                    .send()
                    .await?
                    .json::<TokenSuccess>()
                    .await?
                    .access_token
            );

            tags.set(format!(
                "{:#?}",
                client
                    .get(format!("{}/tags", root))
                    .header("authorization", &authorization)
                    .send()
                    .await?
                    .json::<TagsResponse>()
                    .await?
            ));

            images.set(format!(
                "{:#?}",
                client
                    .get(format!("{}/images", root))
                    .header("authorization", &authorization)
                    .send()
                    .await?
                    .json::<ImagesResponse>()
                    .await?
            ));

            Ok::<_, Error>(())
        }
        .unwrap_or_else(|e| {
            log::error!("error retrieving data: {:?}", e);
        })
    });

    syc::render(move || {
        template! {
            pre { (tags.get()) }
            pre { (images.get()) }
        }
    });

    Ok(())
}
