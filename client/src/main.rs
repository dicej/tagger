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
//!   (e.g. a lightbox)
//!
//! Additionally, there is the [client] module, which provides an API for communicating with the Tagger server.
//!
//! This top-level module ties all of the above modules together and also hosts code shared by those modules.
//!
//! If you're not yet familiar with how [Sycamore](https://crates.io/crates/sycamore) works (particularly how it
//! models reactivity), please read [this excellent
//! overview](https://sycamore-rs.netlify.app/docs/getting_started/installation).

#![deny(warnings)]

use {
    crate::{
        client::Client,
        image_overlay::{Direction, ImageOverlay, ImageOverlayProps, Select},
        images::{ImageState, Images, ImagesProps, ImagesState},
        login_overlay::{LoginOverlay, LoginOverlayProps},
        pagination::{Pagination, PaginationProps},
        toolbar::{Toolbar, ToolbarProps},
    },
    anyhow::{anyhow, Result},
    chrono::Utc,
    serde::{Deserializer, Serializer},
    serde_derive::{Deserialize, Serialize},
    std::{cell::Cell, convert::TryFrom, ops::Deref, panic, rc::Rc},
    sycamore::prelude::{self as syc, view, ReadSignal, Signal},
    tagger_shared::{tag_expression::TagTree, ImageKey, ImagesResponse},
    wasm_bindgen::{closure::Closure, JsCast},
    web_sys::KeyboardEvent,
};

#[cfg(feature = "demo")]
use {
    anyhow::Error,
    std::{
        fmt::{self, Display},
        str::FromStr,
    },
};

mod client;
mod image_overlay;
mod images;
mod login_overlay;
mod pagination;
mod tag_menu;
mod toolbar;

/// Number of media items to show per page by default
const DEFAULT_ITEMS_PER_PAGE: u32 = 100;

/// Call `fun` with the old and new values of `handle` whenever it changes.
fn watch_changes<A: Eq>(handle: ReadSignal<A>, fun: impl Fn(&Rc<A>, &Rc<A>) + 'static) {
    let mut old = handle.get();

    // We use `wasm_bindgen_futures::spawn_local` here to ensure that Sycamore doesn't try to tie the effect we
    // create to an existing thread-local context.  If we don't do this, and this function is called from within
    // e.g. another `syc::create_effect` closure, Sycamore will try to clean up the effect prematurely, and it
    // won't fire when we need it to.
    //
    // There's nothing special about `wasm_bindgen_futures::spawn_local` here (i.e. we don't need to do any
    // asynchronous I/O) -- it's just a convenient way to postpone running a closure until the current Sycamore
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

/// Credentials to use to log in to a demo account
///
/// See `State::demo` for details.
#[cfg(feature = "demo")]
#[derive(Debug, Clone)]
pub struct DemoCredentials {
    pub user_name: String,
    pub password: String,
}

#[cfg(feature = "demo")]
impl FromStr for DemoCredentials {
    type Err = Error;

    /// Parse a `DemoCredentials` from a string of the form "<base64 user name>:<base64 password>".
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split(':');

        if let (Some(a), Some(b)) = (split.next(), split.next()) {
            Ok(Self {
                user_name: String::from_utf8(base64::decode_config(a, base64::URL_SAFE)?)?,
                password: String::from_utf8(base64::decode_config(b, base64::URL_SAFE)?)?,
            })
        } else {
            Err(anyhow!("unable to parse {s} as DemoCredentials"))
        }
    }
}

#[cfg(feature = "demo")]
impl Display for DemoCredentials {
    /// Format a `DemoCredentials` using the format described in `DemoCredentials::from_str`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}",
            base64::encode_config(self.user_name.as_bytes(), base64::URL_SAFE),
            base64::encode_config(self.password.as_bytes(), base64::URL_SAFE),
        )
    }
}

#[cfg(feature = "demo")]
impl<'de> serde::Deserialize<'de> for DemoCredentials {
    /// Deserialize a `DemoCredentials` using `DemoCredentials::from_str`
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "demo")]
impl serde::Serialize for DemoCredentials {
    /// Serialize a `DemoCredentials` using `DemoCredentials::fmt``
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Represents the state of this application (e.g. which item the user is looking at, etc.)
///
/// This is used for URI-based "routing", e.g. https://[hostname]/#s=2022-01-10T01%3A17%3A10Z&ipp=1000
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct State {
    /// The index of the media item the user is currently looking at, if any
    #[serde(rename = "oi")]
    pub overlay_image: Option<usize>,

    /// The tag expression the user is currently using to filter items, if any
    #[serde(rename = "f")]
    pub filter: Option<TagTree>,

    /// The timestamp (and possibly hash) indicating where to start in the item list when displaying thumbnails
    #[serde(rename = "s")]
    pub start: Option<ImageKey>,

    /// The number of items per page to display (assume [DEFAULT_ITEMS_PER_PAGE] if unspecified)
    #[serde(rename = "ipp")]
    pub items_per_page: Option<u32>,

    /// Credentials to use to log in to a demo account, if any
    ///
    /// When this is specified, the app will operate in "demo" mode, meaning the user will be allowed to add or
    /// remove tags to/from media items locally, but those changes will not be persisted to the server and will be
    /// reset if user leaves or refreshes the page.
    #[cfg(feature = "demo")]
    pub demo: Option<DemoCredentials>,
}

/// Start this application.
///
/// This will do all of the following:
///
/// * Attempt to authenticate with the Tagger server (which is assumed to be the same as the host from which the
///   app was loaded)
///
/// * Instantiate and wire up the reactive state for this app, using the "hash" portion of the URI to decode
///   routing state, if present
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

    let show_log_in = Signal::new(false);
    let log_in_error = Signal::new(None);
    let user_name = Signal::new(String::new());
    let password = Signal::new(String::new());

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
    let state = location.hash().ok().and_then(|hash| {
        hash.strip_prefix('#')
            .and_then(|hash| match serde_urlencoded::from_str::<State>(hash) {
                Ok(state) => Some(state),
                Err(e) => {
                    log::warn!("unable to decode state: {e:?}");

                    None
                }
            })
    });

    let client = Client::new(
        state.as_ref(),
        token,
        root.clone(),
        show_log_in.clone(),
        log_in_error.clone(),
        user_name.clone(),
        password.clone(),
    );

    #[cfg(feature = "demo")]
    let mut demo = None;

    if let Some(state) = state {
        #[cfg(feature = "demo")]
        {
            demo = state.demo.clone();
        }

        overlay_image.set(state.overlay_image);
        filter.set(state.filter.unwrap_or_default());

        if let Some(state_start) = state.start {
            start.set(Some(state_start));
        }

        if let Some(state_items_per_page) = state.items_per_page {
            items_per_page.set(state_items_per_page);
        }
    }

    client.try_login()?;

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
                #[cfg(feature = "demo")]
                demo: demo.clone(),
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
        client.watch_images(filter.handle(), start.handle(), items_per_page.handle()),
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
        client: client.clone(),
        show_log_in,
        log_in_error,
        user_name,
        password,
    };

    let toolbar = ToolbarProps {
        client,
        selecting: selecting.clone(),
        items_per_page,
        selected_count: selected_count.handle(),
        filter,
        images: images.clone(),
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
