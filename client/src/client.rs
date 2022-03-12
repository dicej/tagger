use reqwest::{Client, StatusCode};

#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    token: Signal<Option<String>>,
    root: Rc<str>,
    show_log_in: Signal<bool>,
    log_in_error: Signal<Option<String>>,
    user_name: Signal<String>,
    password: Signal<String>,
}

#[cfg(feature = "demo")]
pub type Client = DemoClient;

#[cfg(not(feature = "demo"))]
pub type Client = HttpClient;

impl HttpClient {
    fn new(
        token: Signal<Option<String>>,
        root: Rc<str>,
        show_log_in: Signal<bool>,
        log_in_error: Signal<Option<String>>,
        user_name: Signal<String>,
        password: Signal<String>,
    ) -> Self {
        Self {
            client: Client::new(),
            root,
            filter,
            show_log_in,
            log_in_error,
            user_name,
            password,
        }
    }

    pub fn init(&self, _state: &State) {
        // ignore
    }

    pub fn may_select(&self) -> ReadSignal<bool> {
        // We only enable selection mode if the server has given us an access token which says we may add and
        // remove tags to/from media items.
        syc::create_selector({
            let token = token.handle();

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
                    let mut request = client.client.patch(format!("{root}/tags"));

                    if let Some(token) = client.token.get().deref() {
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
        self.watch(
            Signal::new("tags".into()).into_handle(),
            Signal::new(to_tree(&filter_chain, filter.get().deref())).into_handle(),
        );
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
                self.try_anonymous_login(self);
            }
        }

        // Whenever the access token changes, save it to local storage (or delete it if we've logged out)
        syc::create_effect({
            let token = self.token.handle();
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

        Ok(())
    }

    pub fn try_anonymous_login(&self) {
        self.try_anonymous_login_with_fn({
            let client = self.clone();

            move || client.open_log_in()
        })
    }

    pub fn log_in(&self) {
        wasm_bindgen_futures::spawn_local(
            {
                let client = self.clone();

                async move {
                    let request = client
                        .client
                        .post(format!("{root}/token"))
                        .form(&TokenRequest {
                            grant_type: GrantType::Password,
                            username: client.user_name.trim().into(),
                            password: client.password.trim().into(),
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
        if let Some(token) = self.token.get().deref() {
            jsonwebtoken::dangerous_insecure_decode::<Authorization>(token)
                .map(|data| data.claims.subject.is_some())
                .unwrap_or(false)
        } else {
            false
        }
    }

    fn open_login(&self) {
        self.user_name.set(String::new());
        self.password.set(String::new());
        self.log_in_error.set(None);
        self.show_log_in.set(true);
    }

    fn on_unauthorized(&self) {
        let was_logged_in = self.is_logged_in();

        self.try_anonymous_login(token.clone(), client.clone(), root.clone(), || ());

        if was_logged_in {
            open_log_in();
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
    fn watch<T: Default + for<'de> serde::Deserialize<'de>, F: Fn() + Clone + 'static>(
        &self,
        uri: ReadSignal<String>,
        filter: ReadSignal<TagTree>,
    ) -> ReadSignal<T> {
        let signal = Signal::new(T::default());

        syc::create_effect({
            let signal = signal.clone();

            move || {
                // Note that we must use `wasm_bindgen_futures::spawn_local` to make the asynchronous HTTP request,
                // but we must call `{Read}Signal::get()` on our signals in the closure called by Sycamore (not the
                // closure called by wasm_bindgen) since Sycamore uses thread local state to track context, and
                // that state won't be available when wasm_bindgen calls our nested closure.

                let client = self.clone();
                let uri = uri.get();
                let filter = filter.get();
                let signal = signal.clone();

                wasm_bindgen_futures::spawn_local(
                    {
                        let uri = uri.clone();

                        async move {
                            let mut request = client.client.get(format!(
                                "{root}/{uri}{}",
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

                            if let Some(token) = client.token.deref() {
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
}

#[cfg(feature = "demo")]
#[derive(Clone)]
struct DemoClient {
    client: HttpClient,
    in_demo_mode: Rc<Cell<bool>>,
}

#[cfg(feature = "demo")]
impl DemoClient {
    fn new(
        token: Signal<Option<String>>,
        root: Rc<str>,
        show_log_in: Signal<bool>,
        log_in_error: Signal<Option<String>>,
        user_name: Signal<String>,
        password: Signal<String>,
    ) -> Self {
        Self {
            client: HttpClient::new(token, root, show_log_in, log_in_error, user_name, password),
            in_demo_mode: Rc::new(Cell::new(false)),
        }
    }

    pub fn init(&self, state: &State) {
        if Some(DemoCredentials {
            user_name,
            password,
        }) = &state.demo
        {
            self.user_name.set(user_name.clone());
            self.password.set(password.clone());
            self.in_demo_mode.set(true);
            self.client.log_in();
            // todo: display a banner message explaining that in demo mode any changes will be lost if the user
            // leaves or refreshes the page.
        }
    }

    pub fn may_select(&self) -> ReadSignal<bool> {
        if self.in_demo_mode.get() {
            Signal::new(true).into_handle()
        } else {
            self.client.may_select()
        }
    }

    pub fn patch_tags(&self, patches: Vec<Patch>) {
        if self.in_demo_mode.get() {
            todo!()
        } else {
            self.client.patch_tags(patches)
        }
    }

    pub fn watch_tags(&self, filter: ReadSignal<TagTree>) -> ReadSignal<TagsResponse> {
        if self.in_demo_mode.get() {
            todo!()
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
        if self.in_demo_mode.get() {
            todo!()
        } else {
            self.client.watch_images(filter, start, items_per_page)
        }
    }

    pub fn try_login(&self) -> Result<()> {
        if self.in_demo_mode.get() {
            Ok(())
        } else {
            self.client.try_login()
        }
    }

    pub fn log_in(&self) {
        if !self.in_demo_mode.get() {
            self.client.log_in();
        }
    }

    pub fn try_anonymous_login(&self) {
        if !self.in_demo_mode.get() {
            self.client.try_anonymous_login();
        }
    }

    pub fn is_logged_in(&self) -> bool {
        (!self.in_demo_mode.get()) && self.client.is_logged_in()
    }
}
