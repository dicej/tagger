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

#[derive(Clone)]
pub struct HttpClient {
    client: reqwest::Client,
    token: Signal<Option<String>>,
    root: Rc<str>,
    show_log_in: Signal<bool>,
    log_in_error: Signal<Option<String>>,
    user_name: Signal<String>,
    password: Signal<String>,
}

#[cfg(feature = "demo")]
pub type Client = demo::DemoClient;

#[cfg(not(feature = "demo"))]
pub type Client = HttpClient;

impl HttpClient {
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
        }
    }

    pub fn may_select(&self) -> ReadSignal<bool> {
        // We only enable selection mode if the server has given us an access token which says we may add and
        // remove tags to/from media items.
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
    /// URL.  The body is `patches`, serialized as JSON.  If the server returns 401 Unauthorized, `on_unauthorized`
    /// will be invoked.
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

    pub fn watch_tags(&self, filter: ReadSignal<TagTree>) -> ReadSignal<TagsResponse> {
        self.watch(Signal::new("tags".into()).into_handle(), filter)
    }

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

    pub fn try_anonymous_login(&self) {
        self.try_anonymous_login_with_fn({
            let client = self.clone();

            move || client.open_login()
        })
    }

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

    /// Return true iff the specified `token` exists and is not an "anonymous" token.
    ///
    /// The tagger server may be configured to allow anonymous access (i.e. with empty credentials), in which case
    /// we may have a token with no subject claim, which means we aren't really logged in yet.
    pub fn is_logged_in(&self) -> bool {
        if let Some(token) = self.token.get_untracked().deref() {
            jsonwebtoken::dangerous_insecure_decode::<Authorization>(token)
                .map(|data| data.claims.subject.is_some())
                .unwrap_or(false)
        } else {
            false
        }
    }

    pub fn open_login(&self) {
        self.user_name.set(String::new());
        self.password.set(String::new());
        self.log_in_error.set(None);
        self.show_log_in.set(true);
    }

    fn on_unauthorized(&self) {
        let was_logged_in = self.is_logged_in();

        self.try_anonymous_login_with_fn(|| ());

        if was_logged_in {
            self.open_login();
        }
    }

    /// Create a `ReadSignal` which resolves to the JSON response body returned from the specified URI.
    ///
    /// The request will include an HTTP "Bearer" authorization header with the specified auth token.  Any time
    /// either `uri`, `token`, or `filter` change, the request will be resent and the signal re-fired with the
    /// response unless the response status is 401 Unauthorized, in which case the signal is set to
    /// `Default::default()` and `on_unauthorized` is called.
    ///
    /// The full request URL is formed using `root`/`uri`, with `filter` appended as a query parameter if it is
    /// non-empty.
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
    /// The OAuth 2 authentication URL is formed using `root`/token.
    fn try_anonymous_login_with_fn(&self, on_unauthorized: impl Fn() + 'static) {
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

    const IMAGE_LIMIT: u32 = 10_000;

    #[derive(Clone, Default)]
    struct DemoPatch {
        to_add: HashMap<Arc<str>, HashSet<Tag>>,
        to_remove: HashMap<Arc<str>, HashSet<Tag>>,
    }

    #[derive(Clone)]
    struct DemoState {
        images: ReadSignal<ImagesResponse>,
        tags: ReadSignal<TagsResponse>,
        patch: Signal<DemoPatch>,
    }

    type TagCounts = HashMap<Option<Arc<str>>, HashMap<Arc<str>, u32>>;

    impl DemoState {
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

                for tag in &tags {
                    *tag_counts
                        .entry(tag.category.clone())
                        .or_default()
                        .entry(tag.value.clone())
                        .or_default() += 1;
                }

                if filter
                    .as_ref()
                    .map(|filter| filter.evaluate_set(&tags))
                    .unwrap_or(true)
                {
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

    fn contains_category(tags: &TagsResponse, category: &str) -> bool {
        tags.categories
            .iter()
            .any(|(cat, tags)| cat.deref() == category || contains_category(tags, category))
    }

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

    #[derive(Clone)]
    pub struct DemoClient {
        client: HttpClient,
        demo_state: Option<DemoState>,
    }

    impl DemoClient {
        pub fn new(
            state: Option<&State>,
            token: Signal<Option<String>>,
            root: Rc<str>,
            show_log_in: Signal<bool>,
            log_in_error: Signal<Option<String>>,
            user_name: Signal<String>,
            password: Signal<String>,
        ) -> Self {
            let client = HttpClient::new(
                state,
                token,
                root,
                show_log_in,
                log_in_error,
                user_name.clone(),
                password.clone(),
            );

            Self {
                client: client.clone(),
                demo_state: state.and_then(|state| {
                    state.demo.as_ref().map(|credentials| {
                        user_name.set(credentials.user_name.clone());
                        password.set(credentials.password.clone());

                        // todo: display a banner message explaining that in demo mode any changes will be lost if
                        // the user leaves or refreshes the page.

                        DemoState {
                            images: client.watch_images(
                                Signal::new(TagTree::default()).into_handle(),
                                Signal::new(None).into_handle(),
                                Signal::new(IMAGE_LIMIT).into_handle(),
                            ),
                            tags: client.watch_tags(Signal::new(TagTree::default()).into_handle()),
                            patch: Signal::new(DemoPatch {
                                to_add: HashMap::new(),
                                to_remove: HashMap::new(),
                            }),
                        }
                    })
                }),
            }
        }

        pub fn may_select(&self) -> ReadSignal<bool> {
            if self.demo_state.is_some() {
                Signal::new(true).into_handle()
            } else {
                self.client.may_select()
            }
        }

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

        pub fn try_login(&self) -> Result<()> {
            if self.demo_state.is_some() {
                self.client.log_in();

                Ok(())
            } else {
                self.client.try_login()
            }
        }

        pub fn log_in(&self) {
            if self.demo_state.is_none() {
                self.client.log_in();
            }
        }

        pub fn try_anonymous_login(&self) {
            if self.demo_state.is_none() {
                self.client.try_anonymous_login();
            }
        }

        pub fn is_logged_in(&self) -> bool {
            self.demo_state.is_none() && self.client.is_logged_in()
        }

        pub fn open_login(&self) {
            // todo: don't give user this option when in demo mode
            if self.demo_state.is_none() {
                self.client.open_login();
            }
        }
    }

    #[cfg(test)]
    mod test {
        use {super::*, maplit::hashset, tagger_shared::Medium};

        #[test]
        fn demo_client() -> Result<()> {
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

            assert_eq!(images.get().deref(), client_images.get().deref());

            assert_eq!(tags.get().deref(), client_tags.get().deref());

            Ok(())
        }
    }
}
