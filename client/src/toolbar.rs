//! This module provides the `Toolbar` component, which hosts various tool icons, menus, and status notifications.

use {
    crate::{
        client::Client,
        images::ImagesState,
        pagination::{Pagination, PaginationProps},
        tag_menu::{List, TagMenu, TagMenuCommonProps, TagMenuProps},
    },
    std::{collections::HashSet, ops::Deref},
    sycamore::prelude::{
        self as syc, component, view, Keyed, KeyedProps, ReadSignal, Signal, View,
    },
    tagger_shared::{
        tag_expression::{Tag, TagExpression, TagTree},
        Action, ImageKey, Patch, TagsResponse,
    },
    wasm_bindgen::JsCast,
    web_sys::{Event, HtmlSelectElement, KeyboardEvent},
};

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
    /// Client for making HTTP requests to the server
    pub client: Client,

    /// Indicates whether the UI is currently in "selecting" mode, i.e. the user is selecting items to modify
    pub selecting: Signal<bool>,

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
}

/// Define the `Toolbar` component, which hosts various tool icons, menus, and status notifications.
#[component(Toolbar<G>)]
#[allow(clippy::redundant_closure)]
pub fn toolbar(props: ToolbarProps) -> View<G> {
    let ToolbarProps {
        client,
        selecting,
        items_per_page,
        selected_count,
        filter,
        images,
        start,
    } = props;

    // The `TagMenu` component needs to know the set of tags (across all media items accessible to this user)
    // available from the server.
    let unfiltered_tags = client.watch_tags(Signal::new(TagTree::default()).into_handle());

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

    let may_select = client.may_select();

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
        let client = client.clone();

        move || client.is_logged_in()
    });

    let log_out = {
        let client = client.clone();

        move |_| client.try_anonymous_login()
    };

    let open_log_in_event = {
        let client = client.clone();

        move |_| client.open_login()
    };

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
            let images = images.clone();
            let unfiltered_tags = unfiltered_tags.clone();

            move |tag| {
                let remove = {
                    let client = client.clone();
                    let tag = tag.clone();
                    let unfiltered_tags = unfiltered_tags.clone();
                    let images = images.clone();

                    move |_| {
                        if !is_immutable_category(
                            unfiltered_tags.get().deref(),
                            tag.category.as_deref(),
                        ) {
                            let images = images.get();

                            client.patch_tags(
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
        let add_tag_value = add_tag_value.clone();
        let client = client.clone();
        let unfiltered_tags = unfiltered_tags.clone();

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
                                    "cannot add tag {tag} since it belongs to an immutable category",
                                )
                            } else {
                                let images = images.get();

                                client.patch_tags(
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
            filter: filter.clone(),
            filter_chain: List::Nil,
            unfiltered_tags: unfiltered_tags.clone(),
            show_menu: show_menu.clone(),
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
