//! Tagger client
//!
//! This crate contains the Tagger client, a single-page web application allowing users to browse a photo and video
//! collection hosted on a Tagger server.
//!
//! The UI is split into the following submodules, each of which contains one or more
//! [Sycamore](https://crates.io/crates/sycamore) components.
//!
//! * [login_overlay]: A simple log in overlay for authenticating with the server
//!
//! * [toolbar]: Container for menus, tool icons, and app status
//!
//! * [tag_menu]: Hierarchical widget for browsing and filtering media items by tag
//!
//! * [images]: Container for viewing and interacting with media item previews
//!
//! * [image_overlay]: Overlay for viewing one high resolution media item at a time and browsing items sequentially
//! (e.g. a lightbox)
//!
//! This top-level module ties all of the above modules together and also hosts code shared by those modules.
//!
//! If you're not yet familiar with how [Sycamore](https://crates.io/crates/sycamore) works (particularly how it
//! models reactivity), please read [this excellent
//! overview](https://sycamore-rs.netlify.app/docs/getting_started/installation).

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
    sycamore::prelude::{self as syc, view, ReadSignal, Signal},
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

/// Number of media items to show per page by default
const DEFAULT_ITEMS_PER_PAGE: u32 = 100;

/// Create a `ReadSignal` which resolves to the JSON response body returned from the specified URI.
///
/// The request will include an HTTP "Bearer" authorization header with the specified auth token.  Any time either
/// `uri`, `token`, or `filter` change, the request will be resent and the signal re-fired with the response unless
/// the response status is 401 Unauthorized, in which case the signal is set to `Default::default()` and
/// `on_unauthorized` is called.
///
/// The full request URL is formed using `root`/`uri`, with `filter` appended as a query parameter if it is
/// non-empty.
pub fn watch<T: Default + for<'de> serde::Deserialize<'de>, F: Fn() + Clone + 'static>(
    uri: ReadSignal<String>,
    client: Client,
    token: Signal<Option<String>>,
    root: Rc<str>,
    filter: ReadSignal<TagTree>,
    on_unauthorized: F,
) -> ReadSignal<T> {
    let signal = Signal::new(T::default());

    syc::create_effect({
        let signal = signal.clone();

        move || {
            // Note that we must use `wasm_bindgen_futures::spawn_local` to make the asynchronous HTTP request, but
            // we must call `{Read}Signal::get()` on our signals in the closure called by Sycamore (not the closure
            // called by wasm_bindgen) since Sycamore uses thread local state to track context, and that state
            // won't be available when wasm_bindgen calls our nested closure.

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
                                    filter
                                )
                            } else {
                                String::new()
                            }
                        ));

                        if let Some(token) = token.deref() {
                            request = request.header("authorization", &format!("Bearer {token}"));
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
                    log::error!("error retrieving {uri}: {e:?}");
                }),
            )
        }
    });

    signal.into_handle()
}

/// Call `fun` with the old and new values of `handle` whenever it changes.
fn watch_changes<A: Eq>(handle: ReadSignal<A>, fun: impl Fn(&Rc<A>, &Rc<A>) + 'static) {
    let mut old = handle.get();

    // We use `wasm_bindgen_futures::spawn_local` here to ensure that Sycamore doesn't try to tie the effect we
    // create to an existing thread-local context.  If we don't do this, and this function is called from within
    // e.g. another `syc::create_effect` closure, Sycamore will try to clean up the effect prematurely, and it
    // won't fire when we need it to.
    //
    // There's nothing special about `wasm_bindgen_futures::spawn_local` here (i.e. we don't need to do any
    // asynchronous I/O) -- it's just a convenient way to postpone running a closure until the currentl Sycamore
    // thread local state has been discarded.
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

/// Call `fun` with the current value of `signal` and new value of `handle` whenever latter changes, setting
/// `signal` to the result.
///
/// See also [watch_changes] and [fold].
fn fold_changes<A: Eq, B>(
    handle: ReadSignal<A>,
    signal: Signal<B>,
    fun: impl Fn(Rc<B>, Rc<A>) -> B + 'static,
) {
    watch_changes(handle, move |_, new| {
        signal.set(fun(signal.get_untracked(), new.clone()))
    });
}

/// Create a new `Signal` called `signal`, intializing it with `init`, and call `fun` with the current value of
/// `signal` and new value of `handle` whenever latter changes, setting `signal` to the result.
///
/// See also [watch_changes] and [fold_changes].  Unlike [fold_changes], this method does not require the `Eq`
/// bound on type `A` and therefore does not try to compare the old and new values of `handle` to see if they've
/// actually changed (i.e. `fun` is invoked any time `handle` fires, even if the value hasn't changed).
fn fold<A, B>(
    handle: ReadSignal<A>,
    init: B,
    fun: impl Fn(Rc<B>, Rc<A>) -> B + 'static,
) -> ReadSignal<B> {
    let signal = Signal::new(init);

    // See the comment in the body of [watch_changes] for why we use `wasm_bindgen_futures::spawn_local` here.
    wasm_bindgen_futures::spawn_local({
        let signal = signal.clone();

        async move {
            syc::create_effect({
                let signal = signal.clone();

                move || signal.set(fun(signal.get_untracked(), handle.get()))
            })
        }
    });

    signal.into_handle()
}

/// Represents the state of this application (e.g. which item the user is looking at, etc.)
///
/// This is used for URI-based "routing", e.g. https://[hostname]/#s=2022-01-10T01%3A17%3A10Z&ipp=1000
#[derive(Serialize, Deserialize, Debug)]
struct State {
    /// The index of the media item the user is currently looking at, if any
    #[serde(rename = "oi")]
    overlay_image: Option<usize>,

    /// The tag expression the user is currently using to filter items, if any
    #[serde(rename = "f")]
    filter: Option<TagTree>,

    /// The timestamp (and possibly hash) indicating where to start in the item list when displaying thumbnails
    #[serde(rename = "s")]
    start: Option<ImageKey>,

    /// The number of items per page to display (assume [DEFAULT_ITEMS_PER_PAGE] if unspecified)
    #[serde(rename = "ipp")]
    items_per_page: Option<u32>,
}

/// Return true iff the specified `token` exists and is not an "anonymous" token.
///
/// The tagger server may be configured to allow anonymous access (i.e. with empty credentials), in which case we
/// may have a token with no subject claim, which means we aren't really logged in yet.
fn logged_in(token: &Option<String>) -> bool {
    if let Some(token) = token {
        jsonwebtoken::dangerous_insecure_decode::<Authorization>(token)
            .map(|data| data.claims.subject.is_some())
            .unwrap_or(false)
    } else {
        false
    }
}

/// Attempt to log in with empty credentials, setting `token` to the resulting access token on success, or else
/// calling `on_unauthorized` on 401 Unauthorized.
///
/// The OAuth 2 authentication URL is formed using `root`/token.
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
            let response = client.get(format!("{root}/token")).send().await?;

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
            log::error!("error logging in anonymously: {e:?}");
        }),
    );
}

/// Start this application.
///
/// This will do all of the following:
///
/// * Attempt to authenticate with the Tagger server (which is assumed to be the same as the host from which the
/// app was loaded)
///
/// * Instantiate and wire up the reactive state for this app, using the "hash" portion of the URI to decode
/// routing state, if present
///
/// * Bind handlers for global keyboard events
///
/// * Create, populate and compose the UI components
fn main() -> Result<()> {
    // Dump a stack trace to the console on panic
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    // Send logging output to the console
    log::set_logger(&wasm_bindgen_console_logger::DEFAULT_LOGGER).map_err(|e| anyhow!("{e:?}"))?;

    log::set_max_level(log::LevelFilter::Info);

    let window = web_sys::window().ok_or_else(|| anyhow!("can't get browser window"))?;

    let location = window.location();

    // The most recent access token we've received from the Tagger server, if any
    let token = Signal::new(None);

    // Assume the Tagger server we want to connect to is the same as the host from which this app was loaded
    let root = Rc::<str>::from(format!(
        "{}//{}",
        location.protocol().map_err(|e| anyhow!("{e:?}"))?,
        location.host().map_err(|e| anyhow!("{e:?}"))?
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

    // First, check local storage to see if there's an existing access token we can use to talk to the server.  If
    // not, try to log in anonymously.  If either of those things fail, pop up the login overlay so the user can
    // provide credentials.
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

    // Whenever the access token changes, save it to local storage (or delete it if we've logged out)
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

    // The current image being viewed in the lightbox, if any
    let overlay_image = Signal::new(None);

    // Whether we're currently in "selecting" mode, i.e. selecting items to modify
    let selecting = Signal::new(false);

    // The timestamp (and possibly hash) indicating where to start in the item list when displaying thumbnails
    let start = Signal::new(Some(ImageKey {
        datetime: Utc::now(),
        hash: None,
    }));

    // The current expression used to filter items based on tags
    let filter = Signal::new(TagTree::default());

    // The number of thumbnails to display per page
    let items_per_page = Signal::new(DEFAULT_ITEMS_PER_PAGE);

    // Extract any routing information in the URI from the "hash" portion (e.g. if the user has bookmarked a
    // specific image)
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
                    log::warn!("unable to decode state: {e:?}");
                }
            }
        }
    }

    // Whenever the application state changes, encode it as a "route" and update the URI
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
                    log::warn!("unable to encode state: {e:?}");
                }
            }
        }
    });

    // Whenever the filter expression changes, reset the start to the current time (i.e. go to "page zero")
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

    // Whenever the server tells us our token is no longer valid, show the login overlay (but also try to log in
    // anonymously in the background in case the server allows that)
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

    // How many items are currently selected for modification
    let selected_count = Signal::new(0);

    // Define a reactive variable to receive the latest list of images from the server.
    //
    // Any time our access token, pagination state, or filter expression change, we send an updated query to the
    // server and store the response in this variable.
    //
    // Note that we bundle the state received from the server with local state, specifically which items are
    // currently selected.  We also wire that state to derived state (e.g. `selected_count`) here to ensure they
    // automatically stay in sync.
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

    // Track whether we should automatically feature the first, last, or none of the images in the lightbox
    // overlay, e.g. when the user pages forward or backward.
    //
    // See `next_overlay_image` below for more details.
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

    // Define a lambda to switch the lightbox overlay to the next or previous image in the thumbnail sequence.
    //
    // When we reach the end or beginning of the thumbnail sequence, we may need to page forward or backward if
    // there are more images available on the next or previous page, respectively.
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

    // Define a lambda to handle global key events by moving forward or backward in the thumbnail sequence, or else
    // closing the lightbox overlay.
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

    // Deliberately leak the lambda so it remains viable when we leave this function.
    //
    // See
    // https://rustwasm.github.io/wasm-bindgen/api/wasm_bindgen/closure/struct.Closure.html#method.into_js_value
    // for why we must do this.
    keydown.forget();

    // Finally, we instantiate the UI components using the reactive variables we defined above and compose
    // everything together into a top-level `View`, which we pass to Sycamore for rendering.

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
        view! {
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
