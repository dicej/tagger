#![deny(warnings)]

use {
    crate::{
        image_overlay::{Direction, ImageOverlay, ImageOverlayProps, Select},
        images::{ImageState, Images, ImagesProps, ImagesState},
        login_overlay::{LoginOverlay, LoginOverlayProps},
        pagination::{Pagination, PaginationProps},
        toolbar::{Toolbar, ToolbarProps},
    },
    anyhow::{anyhow, Error, Result},
    chrono::Utc,
    futures::future::TryFutureExt,
    reqwest::{Client, StatusCode},
    serde_derive::{Deserialize, Serialize},
    std::{cell::Cell, convert::TryFrom, ops::Deref, panic, rc::Rc},
    sycamore::prelude::{self as syc, template, Signal, StateHandle},
    tagger_shared::{
        tag_expression::{TagExpression, TagTree},
        Authorization, ImageKey, ImagesQuery, ImagesResponse, TokenSuccess,
    },
    wasm_bindgen::{closure::Closure, JsCast},
    web_sys::KeyboardEvent,
};

mod image_overlay;
mod images;
mod login_overlay;
mod pagination;
mod tag_menu;
mod toolbar;

const DEFAULT_ITEMS_PER_PAGE: u32 = 100;

pub fn watch<T: Default + for<'de> serde::Deserialize<'de>, F: Fn() + Clone + 'static>(
    uri: StateHandle<String>,
    client: Client,
    token: Signal<Option<String>>,
    root: Rc<str>,
    filter: StateHandle<TagTree>,
    on_unauthorized: F,
) -> StateHandle<T> {
    let signal = Signal::new(T::default());

    syc::create_effect({
        let signal = signal.clone();

        move || {
            let client = client.clone();
            let token = token.get();
            let filter = filter.get();
            let uri = uri.get();
            let root = root.clone();
            let signal = signal.clone();
            let on_unauthorized = on_unauthorized.clone();

            wasm_bindgen_futures::spawn_local(
                {
                    let uri = uri.clone();

                    async move {
                        let mut request = client.get(format!(
                            "{}/{}{}",
                            root,
                            uri,
                            if let Some(filter) = Option::<TagExpression>::from(filter.deref()) {
                                format!(
                                    "{}filter={}",
                                    if uri.contains('?') { '&' } else { '?' },
                                    filter.to_string()
                                )
                            } else {
                                String::new()
                            }
                        ));

                        if let Some(token) = token.deref() {
                            request = request.header("authorization", &format!("Bearer {}", token));
                        }

                        let response = request.send().await?;

                        if response.status() == StatusCode::UNAUTHORIZED {
                            signal.set(T::default());
                            on_unauthorized();
                        } else {
                            signal.set(response.error_for_status()?.json::<T>().await?);
                        }

                        Ok::<_, Error>(())
                    }
                }
                .unwrap_or_else(move |e| {
                    log::error!("error retrieving {}: {:?}", uri, e);
                }),
            )
        }
    });

    signal.into_handle()
}

fn watch_changes<A: Eq>(handle: StateHandle<A>, fun: impl Fn(&Rc<A>, &Rc<A>) + 'static) {
    let mut old = handle.get();

    wasm_bindgen_futures::spawn_local(async move {
        syc::create_effect(move || {
            let new = handle.get();

            if new != old {
                fun(&old, &new);

                old = new;
            }
        })
    });
}

fn fold_changes<A: Eq, B>(
    handle: StateHandle<A>,
    signal: Signal<B>,
    fun: impl Fn(Rc<B>, Rc<A>) -> B + 'static,
) {
    watch_changes(handle, move |_, new| {
        signal.set(fun(signal.get_untracked(), new.clone()))
    });
}

fn fold<A, B>(
    handle: StateHandle<A>,
    init: B,
    fun: impl Fn(Rc<B>, Rc<A>) -> B + 'static,
) -> StateHandle<B> {
    let signal = Signal::new(init);

    syc::create_effect({
        let signal = signal.clone();

        move || signal.set(fun(signal.get_untracked(), handle.get()))
    });

    signal.into_handle()
}

#[derive(Serialize, Deserialize, Debug)]
struct State {
    #[serde(rename = "oi")]
    overlay_image: Option<usize>,

    #[serde(rename = "f")]
    filter: Option<TagTree>,

    #[serde(rename = "s")]
    start: Option<ImageKey>,

    #[serde(rename = "ipp")]
    items_per_page: Option<u32>,
}

fn logged_in(token: &Option<String>) -> bool {
    if let Some(token) = token {
        jsonwebtoken::dangerous_insecure_decode::<Authorization>(token)
            .map(|data| data.claims.subject.is_some())
            .unwrap_or(false)
    } else {
        false
    }
}

fn try_anonymous_login(
    token: Signal<Option<String>>,
    client: Client,
    root: Rc<str>,
    on_unauthorized: impl Fn() + 'static,
) {
    if token.get_untracked().is_some() {
        token.set(None);
    }

    wasm_bindgen_futures::spawn_local(
        async move {
            let response = client.get(format!("{}/token", root)).send().await?;

            if response.status() == StatusCode::UNAUTHORIZED {
                on_unauthorized();
            } else {
                token.set(Some(
                    response
                        .error_for_status()?
                        .json::<TokenSuccess>()
                        .await?
                        .access_token,
                ));
            }

            Ok::<_, Error>(())
        }
        .unwrap_or_else(move |e| {
            log::error!("error logging in anonymously: {:?}", e);
        }),
    );
}

fn main() -> Result<()> {
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    log::set_logger(&wasm_bindgen_console_logger::DEFAULT_LOGGER)
        .map_err(|e| anyhow!("{:?}", e))?;

    log::set_max_level(log::LevelFilter::Info);

    let window = web_sys::window().ok_or_else(|| anyhow!("can't get browser window"))?;

    let location = window.location();

    let token = Signal::new(None);

    let root = Rc::<str>::from(format!(
        "{}//{}",
        location.protocol().map_err(|e| anyhow!("{:?}", e))?,
        location.host().map_err(|e| anyhow!("{:?}", e))?
    ));

    let client = Client::new();

    let show_log_in = Signal::new(false);
    let log_in_error = Signal::new(None);
    let user_name = Signal::new(String::new());
    let password = Signal::new(String::new());

    let open_log_in = {
        let show_log_in = show_log_in.clone();
        let log_in_error = log_in_error.clone();
        let user_name = user_name.clone();
        let password = password.clone();

        move || {
            user_name.set(String::new());
            password.set(String::new());
            log_in_error.set(None);
            show_log_in.set(true);
        }
    };

    if let Ok(Some(storage)) = window.local_storage() {
        if let Ok(Some(stored_token)) = storage.get("token") {
            token.set(Some(stored_token));
        } else {
            try_anonymous_login(
                token.clone(),
                client.clone(),
                root.clone(),
                open_log_in.clone(),
            );
        }
    }

    syc::create_effect({
        let token = token.handle();
        let window = window.clone();

        move || {
            if let Ok(Some(storage)) = window.local_storage() {
                let _ = if let Some(token) = token.get().deref() {
                    storage.set("token", token)
                } else {
                    storage.delete("token")
                };
            }
        }
    });

    let overlay_image = Signal::new(None);

    let selecting = Signal::new(false);

    let start = Signal::new(Some(ImageKey {
        datetime: Utc::now(),
        hash: None,
    }));

    let filter = Signal::new(TagTree::default());

    let items_per_page = Signal::new(DEFAULT_ITEMS_PER_PAGE);

    if let Ok(hash) = location.hash() {
        if let Some(hash) = hash.strip_prefix('#') {
            match serde_urlencoded::from_str::<State>(hash) {
                Ok(state) => {
                    overlay_image.set(state.overlay_image);
                    filter.set(state.filter.unwrap_or_default());

                    if let Some(state_start) = state.start {
                        start.set(Some(state_start));
                    }

                    if let Some(state_items_per_page) = state.items_per_page {
                        items_per_page.set(state_items_per_page);
                    }
                }
                Err(e) => {
                    log::warn!("unable to decode state: {:?}", e);
                }
            }
        }
    }

    syc::create_effect({
        let overlay_image = overlay_image.handle();
        let filter = filter.handle();
        let start = start.handle();
        let items_per_page = items_per_page.handle();

        move || {
            let filter = filter.get();
            let items_per_page = items_per_page.get();

            match serde_urlencoded::to_string(&State {
                overlay_image: *overlay_image.get(),
                filter: if filter.0.is_empty() {
                    None
                } else {
                    Some(filter.deref().clone())
                },
                start: start.get().deref().clone(),
                items_per_page: if *items_per_page == DEFAULT_ITEMS_PER_PAGE {
                    None
                } else {
                    Some(*items_per_page)
                },
            }) {
                Ok(hash) => {
                    let _ = location.set_hash(&hash);
                }
                Err(e) => {
                    log::warn!("unable to encode state: {:?}", e);
                }
            }
        }
    });

    syc::create_effect({
        let mut old_filter = filter.get();
        let filter = filter.handle();
        let start = start.clone();

        move || {
            let new_filter = filter.get();
            if new_filter != old_filter {
                old_filter = new_filter;

                start.set(Some(ImageKey {
                    datetime: Utc::now(),
                    hash: None,
                }));
            }
        }
    });

    let on_unauthorized = {
        let open_log_in = open_log_in.clone();
        let client = client.clone();
        let token = token.clone();
        let root = root.clone();

        move || {
            let was_logged_in = logged_in(token.get().deref());

            try_anonymous_login(token.clone(), client.clone(), root.clone(), || ());

            if was_logged_in {
                open_log_in();
            }
        }
    };

    let selected_count = Signal::new(0);

    let images = fold(
        watch::<ImagesResponse, _>(
            syc::create_selector({
                let start = start.clone();
                let items_per_page = items_per_page.clone();

                move || {
                    format!(
                        "images?{}",
                        serde_urlencoded::to_string(ImagesQuery {
                            start: start.get().deref().clone(),
                            limit: Some(*items_per_page.get()),
                            filter: None // will be added by `watch`
                        })
                        .unwrap()
                    )
                }
            }),
            client.clone(),
            token.clone(),
            root.clone(),
            filter.handle(),
            on_unauthorized.clone(),
        ),
        ImagesState::default(),
        {
            let selected_count = selected_count.clone();

            move |state, response| ImagesState {
                states: response
                    .images
                    .iter()
                    .map(|data| {
                        (
                            data.hash.clone(),
                            state.states.get(&data.hash).cloned().unwrap_or_else({
                                let selected_count = selected_count.clone();

                                move || {
                                    let selected = Signal::new(false);

                                    fold_changes(
                                        selected.handle(),
                                        selected_count,
                                        |count, selected| {
                                            if *selected {
                                                *count + 1
                                            } else {
                                                *count - 1
                                            }
                                        },
                                    );

                                    ImageState { selected }
                                }
                            }),
                        )
                    })
                    .collect(),
                response,
            }
        },
    );

    let overlay_image_select = Rc::new(Cell::new(Select::None));

    syc::create_effect({
        let overlay_image = overlay_image.clone();
        let overlay_image_select = overlay_image_select.clone();
        let images = images.clone();

        move || {
            let images = images.get();

            match overlay_image_select.get() {
                Select::None => (),

                Select::First => {
                    if !images.response.images.is_empty() {
                        overlay_image.set(Some(0));
                    }
                }

                Select::Last => {
                    if !images.response.images.is_empty() {
                        overlay_image.set(Some(images.response.images.len() - 1));
                    }
                }
            }

            overlay_image_select.set(Select::None);
        }
    });

    let next_overlay_image = {
        let start = start.clone();
        let overlay_image = overlay_image.clone();
        let images = images.clone();
        let props = PaginationProps {
            images: images.clone(),
            start,
            show_message_on_zero: false,
        };

        move |direction| {
            if let Some(index) = *overlay_image.get() {
                let images = images.get();

                match direction {
                    Direction::Left => {
                        if index > 0 {
                            overlay_image.set(Some(index - 1))
                        } else if images.response.start > 0 {
                            overlay_image_select.set(Select::Last);
                            pagination::page_back(&props);
                        }
                    }

                    Direction::Right => {
                        if index + 1 < images.response.images.len() {
                            overlay_image.set(Some(index + 1))
                        } else {
                            let count = u32::try_from(images.response.images.len()).unwrap();
                            let ImagesResponse { start, total, .. } = *images.response;

                            if start + count < total {
                                overlay_image_select.set(Select::First);
                                pagination::page_forward(&props);
                            }
                        }
                    }
                }
            }
        }
    };

    let keydown = Closure::wrap(Box::new({
        let next_overlay_image = next_overlay_image.clone();
        let overlay_image = overlay_image.clone();

        move |event: KeyboardEvent| match event.key().deref() {
            "ArrowLeft" => next_overlay_image(Direction::Left),
            "ArrowRight" => next_overlay_image(Direction::Right),
            "Escape" => overlay_image.set(None),
            _ => (),
        }
    }) as Box<dyn Fn(KeyboardEvent)>);

    window
        .document()
        .ok_or_else(|| anyhow!("can't get browser document"))?
        .set_onkeydown(Some(keydown.as_ref().unchecked_ref()));

    keydown.forget();

    let pagination = PaginationProps {
        images: images.clone(),
        start: start.clone(),
        show_message_on_zero: false,
    };

    let image_overlay = ImageOverlayProps {
        root: root.clone(),
        overlay_image: overlay_image.clone(),
        images: images.clone(),
        next_overlay_image: Rc::new(next_overlay_image),
    };

    let login_overlay = LoginOverlayProps {
        root: root.clone(),
        client: client.clone(),
        token: token.clone(),
        show_log_in,
        log_in_error,
        user_name,
        password,
    };

    let toolbar = ToolbarProps {
        root: root.clone(),
        client,
        token,
        selecting: selecting.clone(),
        open_log_in: Rc::new(open_log_in),
        items_per_page,
        selected_count: selected_count.handle(),
        filter,
        images: images.clone(),
        on_unauthorized: Rc::new(on_unauthorized),
        start,
    };

    let images = ImagesProps {
        root,
        selecting: selecting.handle(),
        images,
        overlay_image,
    };

    sycamore::render(move || {
        template! {
            ImageOverlay(image_overlay)

            LoginOverlay(login_overlay)

            Toolbar(toolbar)

            Images(images)

            div(class="nav") {
                Pagination(pagination)
            }
        }
    });

    Ok(())
}
