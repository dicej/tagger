#![deny(warnings)]

use anyhow::{anyhow, Error, Result};
use futures::future::TryFutureExt;
use std::{ops::Deref, rc::Rc};
use sycamore::prelude::{self as syc, template, Keyed, KeyedProps, Signal};
use tagger_shared::{GrantType, ImagesResponse, TagsResponse, TokenRequest, TokenSuccess};

fn main() -> Result<()> {
    log::set_logger(&wasm_bindgen_console_logger::DEFAULT_LOGGER)
        .map_err(|e| anyhow!("{:?}", e))?;
    log::set_max_level(log::LevelFilter::Info);

    let token = Signal::new(String::new());
    let tags = Signal::new(String::new());
    let images = Signal::new(String::new());
    let image_vec = Signal::new(Vec::new());

    let location = web_sys::window()
        .ok_or_else(|| anyhow!("can't get browser window"))?
        .location();

    let root = Rc::<str>::from(format!(
        "{}//{}",
        location.protocol().map_err(|e| anyhow!("{:?}", e))?,
        location.host().map_err(|e| anyhow!("{:?}", e))?
    ));

    log::info!("root is {}", root);

    wasm_bindgen_futures::spawn_local({
        let token = token.clone();
        let tags = tags.clone();
        let images = images.clone();
        let image_vec = image_vec.clone();
        let root = root.clone();

        async move {
            let client = reqwest::Client::new();

            token.set(
                client
                    .post(format!("{}/token", root))
                    .form(&TokenRequest {
                        grant_type: GrantType::Password,
                        username: "Jabberwocky".into(),
                        password: "Bandersnatch".into(),
                    })
                    .send()
                    .await?
                    .json::<TokenSuccess>()
                    .await?
                    .access_token,
            );

            let authorization = format!("Bearer {}", token.get());

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

            let images_response = client
                .get(format!("{}/images", root))
                .header("authorization", &authorization)
                .send()
                .await?
                .json::<ImagesResponse>()
                .await?;

            images.set(format!("{:#?}", images_response));

            let mut vec = images_response
                .images
                .iter()
                .map(|(hash, _)| Rc::<str>::from(hash.clone()))
                .collect::<Vec<_>>();

            vec.sort_by(|a, b| {
                images_response
                    .images
                    .get(b.deref())
                    .unwrap()
                    .datetime
                    .cmp(&images_response.images.get(a.deref()).unwrap().datetime)
            });

            image_vec.set(vec);

            Ok::<_, Error>(())
        }
        .unwrap_or_else(|e| {
            log::error!("error retrieving data: {:?}", e);
        })
    });

    let image_keys = KeyedProps {
        iterable: image_vec.handle(),
        template: move |hash| {
            let href = syc::create_memo({
                let hash = hash.clone();
                let root = root.clone();
                let token = token.clone();

                move || format!("{}/image/{}?token={}", root, hash, token.get())
            });

            let src = syc::create_memo({
                let root = root.clone();
                let token = token.clone();

                move || format!("{}/image/{}?token={}&size=small", root, hash, token.get())
            });

            template! {
                a(href=href.get()) {
                    img(src=src.get())
                }
            }
        },
        key: |hash| hash.clone(),
    };

    syc::render(move || {
        template! {
            div {
                Keyed(image_keys)
            }
            pre { (tags.get()) }
            pre { (images.get()) }
        }
    });

    Ok(())
}
