//! This module provides the `Toolbar` component, which hosts various tool icons, menus, and status notifications.

use {
    crate::{
        images::ImagesState,
        pagination::{Pagination, PaginationProps},
        tag_menu::{List, TagMenu, TagMenuCommonProps, TagMenuProps},
    },
    anyhow::Error,
    futures::TryFutureExt,
    reqwest::{Client, StatusCode},
    std::{collections::HashSet, ops::Deref, rc::Rc},
    sycamore::prelude::{
        self as syc, component, view, Keyed, KeyedProps, ReadSignal, Signal, View,
    },
    tagger_shared::{
        tag_expression::{Tag, TagExpression, TagTree},
        Action, Authorization, ImageKey, Patch, TagsResponse,
    },
    wasm_bindgen::JsCast,
    web_sys::{Event, HtmlSelectElement, KeyboardEvent},
};

/// Send a PATCH /tags request to the Tagger server to add or remove tags to/from media items.
///
/// The request is sent using the specified `client`, using `token` for authorization and `root`/tags as the URL.
/// The body is `patches`, serialized as JSON.  If the server returns 401 Unauthorized, `on_unauthorized` will be
/// invoked.
fn patch_tags(
    client: Client,
    token: Signal<Option<String>>,
    root: Rc<str>,
    patches: Vec<Patch>,
    on_unauthorized: impl Fn() + Clone + 'static,
) {
    wasm_bindgen_futures::spawn_local(
        {
            async move {
                let mut request = client.patch(format!("{root}/tags"));

                if let Some(token) = token.get().deref() {
                    request = request.header("authorization", &format!("Bearer {token}"));
                }

                let response = request.json(&patches).send().await?;

                if response.status() == StatusCode::UNAUTHORIZED {
                    on_unauthorized();
                } else {
                    response.error_for_status()?;

                    token.trigger_subscribers();
                }

                Ok::<_, Error>(())
            }
        }
        .unwrap_or_else(move |e| {
            log::error!("error patching tags: {e:?}");
        }),
    )
}

/// Attempt to find the specified `category` in `tags`, and if it is present, return whether it is flagged as
/// immutable (i.e. the server says it will not allow tags in that category to be added to or removed from media
/// items).
///
/// If the category is not found, we return `false`.
fn is_immutable_category(tags: &TagsResponse, category: Option<&str>) -> bool {
    fn recurse(tags: &TagsResponse, category: &str) -> Option<bool> {
        for (cat, tags) in &tags.categories {
            if cat.deref() == category {
                return Some(tags.immutable.unwrap_or(false));
            } else if let Some(answer) = recurse(tags, category) {
                return Some(answer);
            }
        }
        None
    }

    if let Some(category) = category {
        recurse(tags, category)
    } else {
        tags.immutable
    }
    .unwrap_or(false)
}

/// Properties for populating and rendering the `Toolbar` component
pub struct ToolbarProps {
    /// Base URL for sending HTTP requests to the Tagger server
    pub root: Rc<str>,

    /// `reqwest` client for making HTTP requests to the server
    pub client: Client,

    /// Most recent access token received from the server
    pub token: Signal<Option<String>>,

    /// Indicates whether the UI is currently in "selecting" mode, i.e. the user is selecting items to modify
    pub selecting: Signal<bool>,

    /// Callback to make the login overlay visible
    pub open_log_in: Rc<dyn Fn()>,

    /// Number of media item thumbnails to show per page
    pub items_per_page: Signal<u32>,

    /// Number of media items currently selected for modification
    pub selected_count: ReadSignal<u32>,

    /// The current tag expression specified by the user to filter the set of media items displayed
    pub filter: Signal<TagTree>,

    /// The set of media items being displayed on the current page
    pub images: ReadSignal<ImagesState>,

    /// The timestamp (and possibly hash) indicating where to start in the item list when displaying thumbnails
    pub start: Signal<Option<ImageKey>>,

    /// Callback to invoke if the server responds to any request with 401 Unauthorized
    pub on_unauthorized: Rc<dyn Fn()>,
}

/// Define the `Toolbar` component, which hosts various tool icons, menus, and status notifications.
#[component(Toolbar<G>)]
#[allow(clippy::redundant_closure)]
pub fn toolbar(props: ToolbarProps) -> View<G> {
    let ToolbarProps {
        root,
        client,
        token,
        selecting,
        open_log_in,
        items_per_page,
        selected_count,
        filter,
        images,
        start,
        on_unauthorized,
    } = props;

    // The `TagMenu` component needs to know the set of tags (across all media items accessible to this user)
    // available from the server.
    let unfiltered_tags = crate::watch::<TagsResponse, _>(
        Signal::new("tags".into()).into_handle(),
        client.clone(),
        token.clone(),
        root.clone(),
        Signal::new(TagTree::default()).into_handle(),
        {
            let on_unauthorized = on_unauthorized.clone();
            move || on_unauthorized()
        },
    );

    let pagination = PaginationProps {
        images: images.clone(),
        start,
        show_message_on_zero: true,
    };

    let show_menu = Signal::new(false);

    let toggle_menu = {
        let show_menu = show_menu.clone();

        move |_| show_menu.set(!*show_menu.get())
    };

    // We only enable selection mode if the server has given us an access token which says we may add and remove
    // tags to/from media items.
    let may_select = syc::create_selector({
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
    });

    let toggle_selecting = {
        let selecting = selecting.clone();
        let images = images.clone();

        move |_| {
            if *selecting.get() {
                for state in images.get().states.values() {
                    if *state.selected.get() {
                        state.selected.set(false);
                    }
                }
            }

            selecting.set(!*selecting.get())
        }
    };

    let logged_in = syc::create_selector({
        let token = token.handle();

        move || crate::logged_in(token.get().deref())
    });

    let log_out = {
        let token = token.clone();
        let root = root.clone();
        let client = client.clone();
        let open_log_in = open_log_in.clone();

        move |_| {
            crate::try_anonymous_login(token.clone(), client.clone(), root.clone(), {
                let open_log_in = open_log_in.clone();
                move || open_log_in()
            })
        }
    };

    let open_log_in_event = move |_| open_log_in();

    let set_items_per_page = {
        let items_per_page = items_per_page.clone();

        move |event: Event| {
            if let Some(items) = event
                .target()
                .and_then(|target| target.dyn_into::<HtmlSelectElement>().ok())
                .and_then(|target| target.value().parse().ok())
            {
                items_per_page.set(items)
            }
        }
    };

    let selected = syc::create_selector(move || *selected_count.get() > 0);

    let selecting2 = selecting.clone();

    // When at least one media item is selected, we list the union of tags applied to any of those items.  In the
    // case of mutable tags, we also allow the user to remove them.
    let selected_tags = KeyedProps {
        iterable: syc::create_selector({
            let images = images.clone();

            move || {
                let images = images.get();

                let mut vec = images
                    .response
                    .images
                    .iter()
                    .filter(|data| *images.states.get(&data.hash).unwrap().selected.get())
                    .flat_map(|data| &data.tags)
                    .cloned()
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();

                vec.sort();

                vec
            }
        }),

        template: {
            let client = client.clone();
            let token = token.clone();
            let root = root.clone();
            let images = images.clone();
            let unfiltered_tags = unfiltered_tags.clone();
            let on_unauthorized = on_unauthorized.clone();

            move |tag| {
                let remove = {
                    let client = client.clone();
                    let token = token.clone();
                    let root = root.clone();
                    let tag = tag.clone();
                    let unfiltered_tags = unfiltered_tags.clone();
                    let images = images.clone();
                    let on_unauthorized = on_unauthorized.clone();

                    move |_| {
                        if !is_immutable_category(
                            unfiltered_tags.get().deref(),
                            tag.category.as_deref(),
                        ) {
                            let images = images.get();

                            patch_tags(
                                client.clone(),
                                token.clone(),
                                root.clone(),
                                images
                                    .response
                                    .images
                                    .iter()
                                    .filter_map(|data| {
                                        if *images.states.get(&data.hash).unwrap().selected.get()
                                            && data.tags.contains(&tag)
                                        {
                                            Some(Patch {
                                                hash: String::from(data.hash.deref()),
                                                tag: tag.clone(),
                                                action: Action::Remove,
                                            })
                                        } else {
                                            None
                                        }
                                    })
                                    .collect(),
                                {
                                    let on_unauthorized = on_unauthorized.clone();
                                    move || on_unauthorized()
                                },
                            )
                        }
                    }
                };

                let immutable = syc::create_selector({
                    let tag = tag.clone();
                    let unfiltered_tags = unfiltered_tags.clone();

                    move || {
                        is_immutable_category(
                            unfiltered_tags.get().deref(),
                            tag.category.as_deref(),
                        )
                    }
                });

                view! {
                    span(class="selected-tag") {
                        (tag) " " (if *immutable.get() {
                            view! {}
                        } else {
                            view! {
                                i(class="fa fa-times-circle remove", on:click=remove.clone())
                            }
                        })
                    }
                }
            }
        },

        key: |tag| tag.clone(),
    };

    // In addition to removing existing tags, we allow the user to add new ones.

    let add_tag_value = Signal::new(String::new());

    let add_tag_key = {
        let root = root.clone();
        let add_tag_value = add_tag_value.clone();
        let token = token.clone();
        let client = client.clone();
        let unfiltered_tags = unfiltered_tags.clone();
        let on_unauthorized = on_unauthorized.clone();

        move |event: Event| {
            if let Ok(event) = event.dyn_into::<KeyboardEvent>() {
                if event.key().deref() == "Enter" {
                    match add_tag_value.get().parse::<Tag>() {
                        Ok(tag) => {
                            if is_immutable_category(
                                unfiltered_tags.get().deref(),
                                tag.category.as_deref(),
                            ) {
                                log::error!(
                                    "cannot add tag {} since it belongs to an immutable category",
                                    tag
                                )
                            } else {
                                let images = images.get();

                                patch_tags(
                                    client.clone(),
                                    token.clone(),
                                    root.clone(),
                                    images
                                        .response
                                        .images
                                        .iter()
                                        .filter_map(|data| {
                                            if *images
                                                .states
                                                .get(&data.hash)
                                                .unwrap()
                                                .selected
                                                .get()
                                                && !data.tags.contains(&tag)
                                            {
                                                Some(Patch {
                                                    hash: String::from(data.hash.deref()),
                                                    tag: tag.clone(),
                                                    action: Action::Add,
                                                })
                                            } else {
                                                None
                                            }
                                        })
                                        .collect(),
                                    {
                                        let on_unauthorized = on_unauthorized.clone();
                                        move || on_unauthorized()
                                    },
                                )
                            }
                        }

                        Err(e) => {
                            log::error!("unable to parse tag {}: {e:?}", add_tag_value.get())
                        }
                    }

                    add_tag_value.set(String::new());
                }
            }
        }
    };

    let tag_menu = TagMenuProps {
        common: TagMenuCommonProps {
            client,
            token,
            root,
            filter: filter.clone(),
            filter_chain: List::Nil,
            unfiltered_tags: unfiltered_tags.clone(),
            on_unauthorized: on_unauthorized.clone(),
        },
        filtered_tags: unfiltered_tags,
        category: None,
    };

    let filter = syc::create_selector(move || Option::<TagExpression>::from(filter.get().deref()));
    let filter2 = filter.clone();

    view! {
        div {
            div(class="nav") {
                i(class="fa fa-bars big filter", on:click=toggle_menu)

                Pagination(pagination)

                (if *may_select.get() {
                    let selecting = selecting.clone();
                    let toggle_selecting = toggle_selecting.clone();

                    view! {
                        i(class=format!("fa fa-th-large big select{}", if *selecting.get() {
                            " enabled"
                        } else {
                            ""
                        }),
                          on:click=toggle_selecting)
                    }
                } else {
                    view! {}
                })
            }

            div(style=format!("display:{};", if *show_menu.get() { "block" } else { "none" })) {
                (if *logged_in.get() {
                    view! {
                        div(class="link", on:click=log_out.clone()) { "log out" }
                    }
                } else {
                    view! {
                        div(class="link", on:click=open_log_in_event.clone()) { "log in" }
                    }
                })

                label(for="items_per_page") { "items per page: " }

                select(name="items_per_page",
                       id="items_per_page",
                       on:change=set_items_per_page)
                {
                    (match *items_per_page.get() {
                        1000 => view! {
                            option(value="100") { "100" }
                            option(value="1000", selected=true) { "1000" }
                        },
                        _ => view! {
                            option(value="100", selected=true) { "100" }
                            option(value="1000") { "1000" }
                        },
                    })
                }

                TagMenu(tag_menu)
            }

            div(style=format!("display:{};", if *selecting2.get() { "block" } else { "none" })) {
                (if *selected.get() {
                    view! {
                        div {
                            "tags: " Keyed(KeyedProps {
                                iterable: selected_tags.iterable.clone(),
                                template: selected_tags.template.clone(),
                                key: selected_tags.key
                            })
                        }

                        div {
                            label(for="add_tag") { "add tag: " }

                            input(id="add_tag",
                                  on:keyup=add_tag_key.clone(),
                                  bind:value=add_tag_value.clone())
                        }
                    }
                } else {
                    view! {
                        em {
                            "Click images to select them (use Shift key to select an interval)"
                        }
                    }
                })
            }

            div(style=format!("display:{};", if filter.get().is_some() { "block" } else { "none" })) {
                "filter: " (filter2.get().deref().as_ref().map
                            (|expression| expression.to_string()).unwrap_or_else(String::new))
            }
        }
    }
}
