//! This module provides the `Client` type, which provides an API for communicating with the Tagger server,
//! including authentication, media and tag queries, and tag updates.
//!
//! When the `demo` feature is enabled, the `Client` type also provides the alternative capability of simulating a
//! Tagger server locally in the browser instead of connecting to a real one.  In that mode, any changes the user
//! makes (e.g. adding or removing tags) affect only the local state and are lost if the user leaves or refreshes
//! the page.

use {
    crate::State,
    anyhow::{anyhow, Error, Result},
    futures::TryFutureExt,
    reqwest::StatusCode,
    std::{ops::Deref, rc::Rc},
    sycamore::prelude::{self as syc, ReadSignal, Signal},
    tagger_shared::{
        tag_expression::{TagExpression, TagTree},
        Authorization, GrantType, ImageKey, ImagesQuery, ImagesResponse, Patch, TagsResponse,
        TokenRequest, TokenSuccess,
    },
};

/// Type alias for [demo::DemoClient]
#[cfg(feature = "demo")]
pub type Client = demo::DemoClient;

/// Type alias for [HttpClient]
#[cfg(not(feature = "demo"))]
pub type Client = HttpClient;

/// Indicates whether the user is currently logged in, or else in demo mode -- in which case no login is necessary
/// or desired
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum LoginStatus {
    /// User is logged in
    In,

    /// User is logged out
    Out,

    /// App is in demo mode, so no login is necessary
    Demo,
}

/// Indicates whether to prompt the user for credentials, e.g. on 401 Unauthorized
#[derive(Copy, Clone, Debug)]
enum LoginPolicy {
    /// Never prompt the user for credentials
    Never,

    /// Prompt the user for credentials if and when needed
    AsNeeded,
}

/// Represents the state of a connection (or connection-to-be) to a Tagger server
#[derive(Clone)]
pub struct HttpClient {
    /// `reqwest` client for making HTTP requests to the server
    client: reqwest::Client,

    /// Most recent authorization token received from the server, if any
    token: Signal<Option<String>>,

    /// Root URL used to make HTTP requests to the server
    root: Rc<str>,

    /// Indicates whether to prompt the user for login credentials (e.g. when loading the page for the first time
    /// or on token expiration)
    show_log_in: Signal<bool>,

    /// Error message to present to the user on login failure, if any
    log_in_error: Signal<Option<String>>,

    /// Most recent user name provided by user for login
    user_name: Signal<String>,

    /// Most recent password provided by user for login
    password: Signal<String>,

    login_policy: LoginPolicy,
}

impl HttpClient {
    /// Create a new [HttpClient] with the specified configuration and signals.
    ///
    /// In this implementation, the `_state` parameter is ignored.  It is present only to match the API provided by
    /// `demo::DemoClient` when the `demo` feature is enabled.
    #[allow(dead_code)]
    pub fn new(
        _state: Option<&State>,
        token: Signal<Option<String>>,
        root: Rc<str>,
        show_log_in: Signal<bool>,
        log_in_error: Signal<Option<String>>,
        user_name: Signal<String>,
        password: Signal<String>,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            token,
            root,
            show_log_in,
            log_in_error,
            user_name,
            password,
            login_policy: LoginPolicy::AsNeeded,
        }
    }

    /// Return a `ReadSignal` which tracks whether the user has permission to add and remove tags to/from media
    /// items on the server.
    ///
    /// This is based on the latest authorization token received from the server.
    pub fn may_select(&self) -> ReadSignal<bool> {
        syc::create_selector({
            let token = self.token.handle();

            move || {
                if let Some(token) = token.get().deref() {
                    jsonwebtoken::dangerous_insecure_decode::<Authorization>(token)
                        .map(|data| data.claims.may_patch)
                        .unwrap_or(false)
                } else {
                    false
                }
            }
        })
    }

    /// Send a PATCH /tags request to the Tagger server to add or remove tags to/from media items.
    ///
    /// The request is sent using the specified `client`, using `token` for authorization and `root`/tags as the
    /// URL.  The body is `patches`, serialized as JSON.  If the server returns 401 Unauthorized, the user may be
    /// prompted to log in again (see [HttpClient::show_log_in]).
    pub fn patch_tags(&self, patches: Vec<Patch>) {
        wasm_bindgen_futures::spawn_local(
            {
                let client = self.clone();

                async move {
                    let mut request = client.client.patch(format!("{}/tags", client.root));

                    if let Some(token) = client.token.get_untracked().deref() {
                        request = request.header("authorization", &format!("Bearer {token}"));
                    }

                    let response = request.json(&patches).send().await?;

                    if response.status() == StatusCode::UNAUTHORIZED {
                        client.on_unauthorized();
                    } else {
                        response.error_for_status()?;

                        client.token.trigger_subscribers();
                    }

                    Ok::<_, Error>(())
                }
            }
            .unwrap_or_else(move |e| {
                log::error!("error patching tags: {e:?}");
            }),
        )
    }

    /// Return a `ReadSignal` which tracks the latest response to GET /tags requests from the server
    ///
    /// `filter` represents the tag expression used to query a subset of tags.  Any time `filter` or the
    /// `self.token` change, the client will send a new request and publish the result to the returned signal.
    ///
    /// See also [tagger_shared::TagsQuery].
    pub fn watch_tags(&self, filter: ReadSignal<TagTree>) -> ReadSignal<TagsResponse> {
        self.watch(Signal::new("tags".into()).into_handle(), filter)
    }

    /// Return a `ReadSignal` which tracks the latest response to GET /images requests from the server
    ///
    /// See [tagger_shared::ImagesQuery] for the meanings of the parameters.  Whenever a parameter or the
    /// `self.token` change, the client will send a new request and publish the result to the returned signal.
    pub fn watch_images(
        &self,
        filter: ReadSignal<TagTree>,
        start: ReadSignal<Option<ImageKey>>,
        items_per_page: ReadSignal<u32>,
    ) -> ReadSignal<ImagesResponse> {
        self.watch(
            syc::create_selector(move || {
                format!(
                    "images?{}",
                    serde_urlencoded::to_string(ImagesQuery {
                        start: start.get().deref().clone(),
                        limit: Some(*items_per_page.get()),
                        filter: None // will be added by `watch`
                    })
                    .unwrap()
                )
            }),
            filter,
        )
    }

    /// Attempt to log the user in on initial page load.
    ///
    /// First, we'll try reusing the token found in local storage, if any.  Next, we'll try logging in anonymously.
    /// Finally, we'll prompt the user for credentials.
    pub fn try_login(&self) -> Result<()> {
        let window = web_sys::window().ok_or_else(|| anyhow!("can't get browser window"))?;

        // First, check local storage to see if there's an existing access token we can use to talk to the server.
        // If not, try to log in anonymously.  If either of those things fail, pop up the login overlay so the user
        // can provide credentials.
        if let Ok(Some(storage)) = window.local_storage() {
            if let Ok(Some(stored_token)) = storage.get("token") {
                self.token.set(Some(stored_token));
            } else {
                self.try_anonymous_login();
            }
        }

        // Whenever the access token changes, save it to local storage (or delete it if we've logged out)
        syc::create_effect({
            let token = self.token.handle();

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

        Ok(())
    }

    /// Attempt to log in to the server anonymously, and if that fails, prompt the user for credentials.
    pub fn try_anonymous_login(&self) {
        self.try_anonymous_login_with_fn({
            let client = self.clone();

            move || client.open_login()
        })
    }

    /// Attempt to log in to the server using the credentials provided by the user (see [HttpClient::user_name] and
    /// [HttpClient::password]).
    ///
    /// This operation runs asynchronously; `self.token` is updated on success, and `self.log_in_error` is set on
    /// 401 Unauthorized.
    pub fn log_in(&self) {
        wasm_bindgen_futures::spawn_local(
            {
                let client = self.clone();

                async move {
                    let request =
                        client
                            .client
                            .post(format!("{}/token", client.root))
                            .form(&TokenRequest {
                                grant_type: GrantType::Password,
                                username: client.user_name.get_untracked().trim().into(),
                                password: client.password.get_untracked().trim().into(),
                            });

                    client.user_name.set(String::new());
                    client.password.set(String::new());

                    let response = request.send().await?;

                    if response.status() == StatusCode::UNAUTHORIZED {
                        client
                            .log_in_error
                            .set(Some("Invalid user name or password".into()));
                    } else {
                        client.show_log_in.set(false);

                        client.token.set(Some(
                            response
                                .error_for_status()?
                                .json::<TokenSuccess>()
                                .await?
                                .access_token,
                        ));
                    }

                    Ok::<_, Error>(())
                }
            }
            .unwrap_or_else({
                let log_in_error = self.log_in_error.clone();

                move |e| {
                    log::error!("error logging in: {e:?}");

                    log_in_error.set(Some("Error communicating with server".into()));
                }
            }),
        );
    }

    /// Return the current [LoginStatus] of the user.
    ///
    /// The tagger server may be configured to allow anonymous access (i.e. with empty credentials), in which case
    /// we may have a token with no subject claim, which means we aren't really logged in yet.
    pub fn login_status(&self) -> LoginStatus {
        let logged_in = if let Some(token) = self.token.get().deref() {
            jsonwebtoken::dangerous_insecure_decode::<Authorization>(token)
                .map(|data| data.claims.subject.is_some())
                .unwrap_or(false)
        } else {
            false
        };

        if logged_in {
            LoginStatus::In
        } else {
            LoginStatus::Out
        }
    }

    /// Set `self.user_name`, `self.password`, `self.log_in_error`, and `self.show_log_in` to empty, empty, `None`,
    /// and `true`, respectively.
    pub fn open_login(&self) {
        match self.login_policy {
            LoginPolicy::Never => return,
            LoginPolicy::AsNeeded => (),
        }

        self.user_name.set(String::new());
        self.password.set(String::new());
        self.log_in_error.set(None);
        self.show_log_in.set(true);
    }

    /// Handle a 401 Unauthorized response from the server by attempting to log in again, prompting the user for
    /// credentials if necessary.
    fn on_unauthorized(&self) {
        let was_logged_in = self.login_status() == LoginStatus::In;

        self.try_anonymous_login_with_fn(|| ());

        if was_logged_in {
            self.open_login();
        }
    }

    /// Create a `ReadSignal` which resolves to the JSON response body returned from the specified URI.
    ///
    /// The request will include an HTTP "Bearer" authorization header with the specified auth token.  Any time
    /// either `uri`, `self.token`, or `filter` change, the request will be resent and the signal re-fired with the
    /// response unless the response status is 401 Unauthorized, in which case the signal is set to
    /// `Default::default()` and `on_unauthorized` is called.
    ///
    /// The full request URL is formed using `self.root`/`uri`, with `filter` appended as a query parameter if it
    /// is non-empty.
    fn watch<T: Default + for<'de> serde::Deserialize<'de>>(
        &self,
        uri: ReadSignal<String>,
        filter: ReadSignal<TagTree>,
    ) -> ReadSignal<T> {
        let signal = Signal::new(T::default());

        syc::create_effect({
            let client = self.clone();
            let signal = signal.clone();

            move || {
                // Note that we must use `wasm_bindgen_futures::spawn_local` to make the asynchronous HTTP request,
                // but we must call `{Read}Signal::get()` on our signals in the closure called by Sycamore (not the
                // closure called by wasm_bindgen) since Sycamore uses thread local state to track context, and
                // that state won't be available when wasm_bindgen calls our nested closure.

                let client = client.clone();
                let token = client.token.get();
                let uri = uri.get();
                let filter = filter.get();
                let signal = signal.clone();

                wasm_bindgen_futures::spawn_local(
                    {
                        let uri = uri.clone();

                        async move {
                            let mut request = client.client.get(format!(
                                "{}/{uri}{}",
                                client.root,
                                if let Some(filter) = Option::<TagExpression>::from(filter.deref())
                                {
                                    format!(
                                        "{}filter={filter}",
                                        if uri.contains('?') { '&' } else { '?' },
                                    )
                                } else {
                                    String::new()
                                }
                            ));

                            if let Some(token) = token.deref() {
                                request =
                                    request.header("authorization", &format!("Bearer {token}"));
                            }

                            let response = request.send().await?;

                            if response.status() == StatusCode::UNAUTHORIZED {
                                signal.set(T::default());
                                client.on_unauthorized();
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

    /// Attempt to log in with empty credentials, setting `token` to the resulting access token on success, or else
    /// calling `on_unauthorized` on 401 Unauthorized.
    ///
    /// The OAuth 2 authentication URL is formed using `self.root`/token.
    fn try_anonymous_login_with_fn(&self, on_unauthorized: impl Fn() + 'static) {
        match self.login_policy {
            LoginPolicy::Never => return,
            LoginPolicy::AsNeeded => (),
        }

        if self.token.get_untracked().is_some() {
            self.token.set(None);
        }

        let client = self.clone();

        wasm_bindgen_futures::spawn_local(
            async move {
                let response = client
                    .client
                    .get(format!("{}/token", client.root))
                    .send()
                    .await?;

                if response.status() == StatusCode::UNAUTHORIZED {
                    on_unauthorized();
                } else {
                    client.token.set(Some(
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
}

/// Module supporting the `demo` feature, which enables simulating a Tagger server locally in the browser so the
/// user can experiment without affecting the state of a real server
#[cfg(feature = "demo")]
mod demo {
    use {
        super::*,
        std::{
            collections::{HashMap, HashSet},
            convert::Infallible,
            sync::Arc,
        },
        tagger_shared::{tag_expression::Tag, Action, ImageData, ImagesResponseBuilder},
    };

    /// Maximum number of media items to retrieve from the server
    const IMAGE_LIMIT: u32 = 10_000;

    /// Represents the accumulated "add" and "remove" patch operations performed on a simulated server
    #[derive(Clone, Default)]
    struct DemoPatch {
        /// Acculmuated "add" operations
        to_add: HashMap<Arc<str>, HashSet<Tag>>,

        /// Acculmuated "remove" operations
        to_remove: HashMap<Arc<str>, HashSet<Tag>>,
    }

    /// Represents the state of a simulated server
    #[derive(Clone)]
    struct DemoState {
        /// The latest `ImagesResponse` received from the real server
        images: ReadSignal<ImagesResponse>,

        /// The latest `TagsResponse` received from the real server
        tags: ReadSignal<TagsResponse>,

        /// Accumulated "add" and "remove" patch operations performed on the simulated server
        patch: Signal<DemoPatch>,
    }

    /// Type alias representing a map of categories to tags to counts of items having each tag
    type TagCounts = HashMap<Option<Arc<str>>, HashMap<Arc<str>, u32>>;

    impl DemoState {
        /// Calculate an `ImagesResponse` and `TagCounts` according to the same logic the Tagger server uses.
        ///
        /// The `ImagesResponse` is calculated by starting with the `ImagesResponse` received from the real server,
        /// applying `self.patch` to it, and finally using [tagger_shared::ImagesResponseBuilder] to filter and
        /// paginate according to the query parameters just like the real server would.  At the same time, we
        /// accumulate tag counts which can later be fed to the [tags] method to generate a simulated
        /// `TagsResponse` if desired.
        fn images_and_tag_counts(
            &self,
            filter: &ReadSignal<TagTree>,
            token: &ReadSignal<Option<String>>,
            start: ReadSignal<Option<ImageKey>>,
            items_per_page: ReadSignal<u32>,
        ) -> (ImagesResponse, TagCounts) {
            let patch = self.patch.get();
            let images = self.images.get();

            let mut filter = Option::<TagExpression>::from(filter.get().deref());

            if let Some(token) = token.get().deref() {
                if let Ok(auth) = jsonwebtoken::dangerous_insecure_decode::<Authorization>(token) {
                    tagger_shared::maybe_wrap_filter(&mut filter, &auth.claims);
                }
            }

            let mut tag_counts = TagCounts::new();

            let mut builder = ImagesResponseBuilder::new(
                start.get().deref().as_ref().cloned(),
                (*items_per_page.get().deref()).try_into().unwrap(),
            );

            for image in &images.images {
                let tags = image
                    .tags
                    .iter()
                    .filter(|tag| match patch.to_remove.get(&image.hash) {
                        Some(to_remove) => !to_remove.contains(tag),
                        _ => true,
                    })
                    .chain(patch.to_add.get(&image.hash).iter().copied().flatten())
                    .cloned()
                    .collect::<HashSet<_>>();

                if filter
                    .as_ref()
                    .map(|filter| filter.evaluate_set(&tags))
                    .unwrap_or(true)
                {
                    for tag in &tags {
                        *tag_counts
                            .entry(tag.category.clone())
                            .or_default()
                            .entry(tag.value.clone())
                            .or_default() += 1;
                    }

                    assert!(builder
                        .consider::<Infallible, _>(&image.key(), || {
                            Ok(ImageData {
                                hash: image.hash.clone(),
                                datetime: image.datetime,
                                medium: image.medium,
                                duplicates: image.duplicates.clone(),
                                tags,
                            })
                        })
                        .is_ok());
                }
            }

            (builder.build(), tag_counts)
        }

        /// Calculate a `TagsResponse` according to the same logic the Tagger server uses.
        ///
        /// The result is calculated by starting with the `TagsResponse` received from the real server and then
        /// filtering the result using `tag_counts` (presumably created by a prior call to the
        /// [images_and_tag_counts] method).
        fn tags(&self, tag_counts: &TagCounts) -> TagsResponse {
            let tags = self.tags.get();

            let mut result = filter_tags(None, tags.deref(), tag_counts);

            result
                .categories
                .extend(tag_counts.iter().filter_map(|(category, inner_tags)| {
                    category.as_ref().and_then(|category| {
                        if contains_category(tags.deref(), category) {
                            None
                        } else {
                            Some((
                                category.clone(),
                                TagsResponse {
                                    immutable: None,
                                    categories: HashMap::new(),
                                    tags: inner_tags.clone(),
                                },
                            ))
                        }
                    })
                }));

            result
        }
    }

    /// Return whether the specified `category` can be found in `tags` or a sub-response thereof.
    fn contains_category(tags: &TagsResponse, category: &str) -> bool {
        tags.categories
            .iter()
            .any(|(cat, tags)| cat.deref() == category || contains_category(tags, category))
    }

    /// Return a clone of `tags`, except with the tag counts replaced by those found in `tag_counts`.
    ///
    /// This may lead to some entries being removed entirely when the corresponding `tag_counts` entries are not
    /// present.
    fn filter_tags(
        category: Option<Arc<str>>,
        tags: &TagsResponse,
        tag_counts: &TagCounts,
    ) -> TagsResponse {
        TagsResponse {
            immutable: tags.immutable,

            categories: tags
                .categories
                .iter()
                .filter_map(|(name, tags)| {
                    let tags = filter_tags(Some(name.clone()), tags, tag_counts);

                    if tags.categories.is_empty() && tags.tags.is_empty() {
                        None
                    } else {
                        Some((name.clone(), tags))
                    }
                })
                .collect(),

            tags: tag_counts.get(&category).cloned().unwrap_or_default(),
        }
    }

    /// Composes an [HttpClient] with an [Option<DemoState>], implementing all the same methods but redirecting
    /// any server communication to a simulated server when `demo_state` is non-empty.
    #[derive(Clone)]
    pub struct DemoClient {
        client: HttpClient,
        demo_state: Option<DemoState>,
    }

    impl DemoClient {
        /// Create a new `DemoClient`.
        ///
        /// If `state.demo` is empty, the returned object will have an empty `demo_state` and pass all method calls
        /// straight through to the underlying [HttpClient].  Otherwise, the returned object will have a non-empty
        /// `demo_state` and redirect most method calls to the simulated server.
        pub fn new(
            state: Option<&State>,
            token: Signal<Option<String>>,
            root: Rc<str>,
            show_log_in: Signal<bool>,
            log_in_error: Signal<Option<String>>,
            user_name: Signal<String>,
            password: Signal<String>,
        ) -> Self {
            let client = HttpClient {
                client: reqwest::Client::new(),
                token,
                root,
                show_log_in,
                log_in_error,
                user_name: user_name.clone(),
                password: password.clone(),
                login_policy: if state.and_then(|state| state.demo.as_ref()).is_some() {
                    LoginPolicy::Never
                } else {
                    LoginPolicy::AsNeeded
                },
            };

            Self {
                client: client.clone(),
                demo_state: state.and_then(|state| {
                    state.demo.as_ref().map(|credentials| {
                        user_name.set(credentials.user_name.clone());
                        password.set(credentials.password.clone());

                        DemoState {
                            images: client.watch_images(
                                Signal::new(TagTree::default()).into_handle(),
                                Signal::new(None).into_handle(),
                                Signal::new(IMAGE_LIMIT).into_handle(),
                            ),
                            tags: client.watch_tags(Signal::new(TagTree::default()).into_handle()),
                            patch: Signal::new(DemoPatch::default()),
                        }
                    })
                }),
            }
        }

        /// In demo mode, return a signal whose value is always `true`; otherwise, return
        /// `self.client.may_select()`.
        pub fn may_select(&self) -> ReadSignal<bool> {
            if self.demo_state.is_some() {
                Signal::new(true).into_handle()
            } else {
                self.client.may_select()
            }
        }

        /// In demo mode, accumulate the specified `patches` in the simulated server; otherwise, send the patches
        /// to the real server.
        pub fn patch_tags(&self, patches: Vec<Patch>) {
            if let Some(demo_state) = self.demo_state.as_ref() {
                let mut new = demo_state.patch.get_untracked().as_ref().clone();

                for patch in patches {
                    let hash = Arc::<str>::from(&patch.hash as &str);

                    match patch.action {
                        Action::Add => {
                            new.to_add
                                .entry(hash.clone())
                                .or_default()
                                .insert(patch.tag.clone());

                            let remove = if let Some(tags) = new.to_remove.get_mut(&hash) {
                                tags.remove(&patch.tag);

                                tags.is_empty()
                            } else {
                                false
                            };

                            if remove {
                                new.to_remove.remove(&hash);
                            }
                        }

                        Action::Remove => {
                            new.to_remove
                                .entry(hash.clone())
                                .or_default()
                                .insert(patch.tag.clone());

                            let remove = if let Some(tags) = new.to_add.get_mut(&hash) {
                                tags.remove(&patch.tag);

                                tags.is_empty()
                            } else {
                                false
                            };

                            if remove {
                                new.to_add.remove(&hash);
                            }
                        }
                    }
                }

                demo_state.patch.set(new);
            } else {
                self.client.patch_tags(patches)
            }
        }

        /// In demo mode, return a signal that queries the simulated server for a `TagsResponse`; otherwise, query
        /// the real server.
        pub fn watch_tags(&self, filter: ReadSignal<TagTree>) -> ReadSignal<TagsResponse> {
            if let Some(demo_state) = self.demo_state.as_ref() {
                syc::create_selector({
                    let demo_state = demo_state.clone();
                    let token = self.client.token.handle();

                    move || {
                        demo_state.tags(
                            &demo_state
                                .images_and_tag_counts(
                                    &filter,
                                    &token,
                                    Signal::new(None).into_handle(),
                                    Signal::new(IMAGE_LIMIT).into_handle(),
                                )
                                .1,
                        )
                    }
                })
            } else {
                self.client.watch_tags(filter)
            }
        }

        /// In demo mode, return a signal that queries the simulated server for a `ImagesResponse`; otherwise,
        /// query the real server.
        pub fn watch_images(
            &self,
            filter: ReadSignal<TagTree>,
            start: ReadSignal<Option<ImageKey>>,
            items_per_page: ReadSignal<u32>,
        ) -> ReadSignal<ImagesResponse> {
            if let Some(demo_state) = self.demo_state.as_ref() {
                syc::create_selector({
                    let demo_state = demo_state.clone();
                    let token = self.client.token.handle();

                    move || {
                        demo_state
                            .images_and_tag_counts(
                                &filter,
                                &token,
                                start.clone(),
                                items_per_page.clone(),
                            )
                            .0
                    }
                })
            } else {
                self.client.watch_images(filter, start, items_per_page)
            }
        }

        /// In demo mode, attempt to log in using the credentials specified via the `state` parameter of
        /// `DemoClient::new`; otherwise, call `self.client.try_login()`.
        pub fn try_login(&self) -> Result<()> {
            if self.demo_state.is_some() {
                self.client.log_in();
                Ok(())
            } else {
                self.client.try_login()
            }
        }

        /// Call `self.client.log_in()` if not in demo mode; otherwise, panic.
        pub fn log_in(&self) {
            if self.demo_state.is_none() {
                self.client.log_in();
            } else {
                unreachable!("UI should not give user this option")
            }
        }

        /// Call `self.client.try_anonymous_login()` if not in demo mode; otherwise, panic.
        pub fn try_anonymous_login(&self) {
            if self.demo_state.is_none() {
                self.client.try_anonymous_login();
            } else {
                unreachable!("UI should not give user this option")
            }
        }

        /// In demo mode, return `LoginStatus::Demo`; otherwise, return `self.client.login_status()`.
        pub fn login_status(&self) -> LoginStatus {
            if self.demo_state.is_none() {
                self.client.login_status()
            } else {
                LoginStatus::Demo
            }
        }

        /// Call `self.client.open_login()` if not in demo mode; otherwise, panic.
        pub fn open_login(&self) {
            if self.demo_state.is_none() {
                self.client.open_login();
            } else {
                unreachable!("UI should not give user this option")
            }
        }
    }

    #[cfg(test)]
    mod test {
        use {super::*, maplit::hashset, tagger_shared::Medium};

        #[test]
        fn demo_client() -> Result<()> {
            // Set up a simple test scenario with `image_count` media items and a few tags applied to those items.

            let image_count = 8;

            let tags = (0..image_count)
                .map(|index| Tag {
                    category: None,
                    value: index.to_string().into(),
                })
                .collect::<Box<[_]>>();

            let images = Signal::new(ImagesResponse {
                start: 0,
                total: image_count,
                later_start: None,
                earliest_start: None,
                images: (0..image_count)
                    .map(|index| {
                        Ok(ImageData {
                            hash: index.to_string().into(),
                            datetime: format!("2021-{:02}-01T00:00:00Z", index + 1).parse()?,
                            medium: Medium::Image,
                            duplicates: Vec::new(),
                            tags: hashset![
                                tags[usize::try_from(index).unwrap()].clone(),
                                Tag {
                                    category: Some("year".into()),
                                    value: "2021".into()
                                },
                                Tag {
                                    category: Some("month".into()),
                                    value: (index + 1).to_string().into()
                                }
                            ],
                        })
                    })
                    .collect::<Result<_>>()?,
            });

            let tags = Signal::new(TagsResponse {
                immutable: None,
                categories: [(
                    "year".into(),
                    TagsResponse {
                        immutable: Some(true),
                        categories: [(
                            "month".into(),
                            TagsResponse {
                                immutable: Some(true),
                                categories: HashMap::new(),
                                tags: (0..image_count)
                                    .map(|index| ((index + 1).to_string().into(), 1))
                                    .collect(),
                            },
                        )]
                        .into_iter()
                        .collect(),
                        tags: [("2021".into(), image_count)].into_iter().collect(),
                    },
                )]
                .into_iter()
                .collect(),
                tags: tags.iter().map(|tag| (tag.value.clone(), 1)).collect(),
            });

            let client = DemoClient {
                client: HttpClient {
                    client: reqwest::Client::new(),
                    token: Signal::new(None),
                    root: Rc::from("(invalid)"),
                    show_log_in: Signal::new(false),
                    log_in_error: Signal::new(None),
                    user_name: Signal::new(String::new()),
                    password: Signal::new(String::new()),
                    login_policy: LoginPolicy::Never,
                },
                demo_state: Some(DemoState {
                    images: images.handle(),
                    tags: tags.handle(),
                    patch: Signal::new(DemoPatch::default()),
                }),
            };

            let filter = Signal::new(TagTree::default());

            let start = Signal::new(None);

            let items_per_page = Signal::new(image_count);

            let client_tags = client.watch_tags(filter.handle());

            let client_images =
                client.watch_images(filter.handle(), start.handle(), items_per_page.handle());

            // To start with (before we've added or removed any tags), the client state should match the original
            // state.

            // Poor man's clone
            let mut images = serde_json::from_str::<ImagesResponse>(
                &serde_json::to_string(images.get().deref()).unwrap(),
            )
            .unwrap();

            let mut tags = serde_json::from_str::<TagsResponse>(
                &serde_json::to_string(tags.get().deref()).unwrap(),
            )
            .unwrap();

            assert_eq!(&images, client_images.get().deref());

            assert_eq!(&tags, client_tags.get().deref());

            // Now let's add a new tag to a couple of images and expect the client to include them.

            let tag = Tag {
                category: None,
                value: "foo".into(),
            };

            client.patch_tags(vec![
                Patch {
                    hash: "0".into(),
                    tag: tag.clone(),
                    action: Action::Add,
                },
                Patch {
                    hash: "1".into(),
                    tag: tag.clone(),
                    action: Action::Add,
                },
            ]);

            for index in 0..2 {
                images.images[usize::try_from(index).unwrap()]
                    .tags
                    .insert(tag.clone());
            }

            assert_eq!(&images, client_images.get().deref());

            tags.tags.insert(tag.value, 2);

            assert_eq!(&tags, client_tags.get().deref());

            // Now let's remove tags from a couple of images and expect the client to reflect that.

            client.patch_tags(vec![
                Patch {
                    hash: "4".into(),
                    tag: Tag {
                        category: None,
                        value: "4".into(),
                    },
                    action: Action::Remove,
                },
                Patch {
                    hash: "5".into(),
                    tag: Tag {
                        category: None,
                        value: "5".into(),
                    },
                    action: Action::Remove,
                },
            ]);

            for index in 4..6 {
                images.images[index].tags.remove(&Tag {
                    category: None,
                    value: index.to_string().into(),
                });
            }

            assert_eq!(&images, client_images.get().deref());

            tags.tags.remove("4");
            tags.tags.remove("5");

            assert_eq!(&tags, client_tags.get().deref());

            // Now add new tags with a new category.

            client.patch_tags(vec![
                Patch {
                    hash: "4".into(),
                    tag: Tag {
                        category: Some("um".into()),
                        value: "whut".into(),
                    },
                    action: Action::Add,
                },
                Patch {
                    hash: "5".into(),
                    tag: Tag {
                        category: Some("um".into()),
                        value: "why".into(),
                    },
                    action: Action::Add,
                },
            ]);

            for (index, value) in [(4, "whut"), (5, "why")] {
                images.images[index].tags.insert(Tag {
                    category: Some("um".into()),
                    value: value.into(),
                });
            }

            assert_eq!(&images, client_images.get().deref());

            tags.categories.insert(
                "um".into(),
                TagsResponse {
                    immutable: None,
                    categories: HashMap::new(),
                    tags: ["whut", "why"]
                        .into_iter()
                        .map(|tag| (tag.into(), 1))
                        .collect(),
                },
            );

            assert_eq!(&tags, client_tags.get().deref());

            Ok(())
        }
    }
}
