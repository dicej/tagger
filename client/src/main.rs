//#![deny(warnings)]

use anyhow::{anyhow, Error, Result};
use chrono::{DateTime, Utc};
use futures::future::TryFutureExt;
use reqwest::Client;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
    panic,
    rc::Rc,
};
use sycamore::prelude::{
    self as syc, component, template, Keyed, KeyedProps, Signal, StateHandle, Template,
};
use tagger_shared::{
    tag_expression::{Tag, TagExpression, TagTree},
    GrantType, ImagesResponse, TagsResponse, TokenRequest, TokenSuccess,
};

#[derive(Clone, Debug)]
enum List<T> {
    Nil,
    Cons(Rc<(T, List<T>)>),
}

fn find_categories<'a>(
    filter_chain: &List<Tag>,
    categories: &'a HashMap<String, TagsResponse>,
) -> Option<&'a HashMap<String, TagsResponse>> {
    if let List::Cons(cons) = filter_chain {
        let next = find_categories(&cons.1, categories);
        if let Some(category) = cons.0.category.as_ref() {
            next.and_then(|next| next.get(category).map(|tags| &tags.categories))
        } else {
            next
        }
    } else {
        Some(categories)
    }
}

fn to_tree(filter_chain: &List<Tag>) -> TagTree {
    fn recurse(filter_chain: &List<Tag>, tree: TagTree) -> TagTree {
        match filter_chain {
            List::Nil => tree,
            List::Cons(cons) => {
                let mut parent = TagTree::default();
                parent.0.insert(cons.0.clone(), recurse(&cons.1, tree));
                parent
            }
        }
    }

    recurse(filter_chain, TagTree::default())
}

fn find_tag<'a>(
    mut filter_chain: &'a List<Tag>,
    category: Option<&str>,
    tag: &str,
) -> Option<&'a Tag> {
    loop {
        match filter_chain {
            List::Nil => break None,
            List::Cons(cons) => {
                if cons.0.category.as_deref() == category && cons.0.value.deref() == tag {
                    break Some(&cons.0);
                } else {
                    filter_chain = &cons.1;
                }
            }
        }
    }
}

fn resolve<'a>(filter_chain: &List<Tag>, filter: &'a TagTree) -> Option<&'a TagTree> {
    match filter_chain {
        List::Nil => Some(filter),
        List::Cons(cons) => resolve(&cons.1, filter).and_then(|tree| tree.0.get(&cons.0)),
    }
}

fn resolve_mut<'a>(filter_chain: &List<Tag>, filter: &'a mut TagTree) -> Option<&'a mut TagTree> {
    match filter_chain {
        List::Nil => Some(filter),
        List::Cons(cons) => resolve_mut(&cons.1, filter).and_then(|tree| tree.0.get_mut(&cons.0)),
    }
}

fn is_filtered(filter_chain: &List<Tag>, filter: &TagTree, tag: &Tag) -> bool {
    resolve(filter_chain, filter)
        .map(|tree| tree.0.contains_key(tag))
        .unwrap_or(false)
}

struct TagSubMenuProps {
    state: Rc<State>,
    tag: Tag,
    filter: Signal<TagTree>,
    filter_chain: List<Tag>,
}

#[component(TagSubMenu<G>)]
fn tag_sub_menu(props: TagSubMenuProps) -> Template<G> {
    let TagSubMenuProps {
        state,
        tag,
        filter,
        filter_chain,
    } = props;

    let tag_menu = {
        let tag = tag.clone();
        let filter_chain = filter_chain.clone();
        let filter = filter.clone();

        move || {
            let filter_chain = List::Cons(Rc::new((tag.clone(), filter_chain.clone())));

            TagMenuProps {
                state: state.clone(),
                filter: filter.clone(),
                filter_chain: filter_chain.clone(),
                tags: watch::<TagsResponse>(
                    "tags",
                    state.clone(),
                    Signal::new(to_tree(&filter_chain)).into_handle(),
                ),
                category: None,
            }
        }
    };

    tag_menu();

    let is_filtered =
        syc::create_selector(move || is_filtered(&filter_chain, filter.get().deref(), &tag));

    template! {
        (if *is_filtered.get() {
            let tag_menu = tag_menu();
            template! {
                ul {
                    TagMenu(tag_menu)
                }
            }
        } else {
            template! {}
        })
    }
}

struct TagMenuProps {
    state: Rc<State>,
    filter: Signal<TagTree>,
    filter_chain: List<Tag>,
    tags: StateHandle<TagsResponse>,
    category: Option<Rc<str>>,
}

#[component(TagMenu<G>)]
fn tag_menu(props: TagMenuProps) -> Template<G> {
    let TagMenuProps {
        state,
        filter,
        filter_chain,
        tags,
        category,
    } = props;

    let categories = if category.is_none() {
        let categories = KeyedProps {
            iterable: syc::create_selector({
                let tags = tags.clone();
                let filter_chain = filter_chain.clone();

                move || {
                    let tags = tags.get();

                    let empty = HashMap::new();

                    let mut vec = find_categories(&filter_chain, &tags.categories)
                        .unwrap_or(&empty)
                        .iter()
                        .map(|(category, _)| category.clone())
                        .collect::<Vec<_>>();

                    vec.sort();

                    vec
                }
            }),

            template: {
                let filter_chain = filter_chain.clone();
                let tags = tags.clone();
                let state = state.clone();
                let filter = filter.clone();

                move |category| {
                    let tag_menu = TagMenuProps {
                        state: state.clone(),
                        filter: filter.clone(),
                        filter_chain: filter_chain.clone(),
                        tags: tags.clone(),
                        category: Some(Rc::from(category.clone())),
                    };

                    template! {
                        li {
                            (category)
                            ul {
                                TagMenu(tag_menu)
                            }
                        }
                    }
                }
            },

            key: |category| category.clone(),
        };

        template! {
            Keyed(categories)
        }
    } else {
        template! {}
    };

    let tags = KeyedProps {
        iterable: syc::create_selector({
            let category = category.clone();
            let filter_chain = filter_chain.clone();

            move || {
                let tags = tags.get();

                let empty = TagsResponse::default();

                let mut vec = if let Some(category) = &category {
                    find_categories(&filter_chain, &tags.categories)
                        .and_then(|categories| categories.get(category.deref()))
                        .unwrap_or(&empty)
                } else {
                    tags.deref()
                }
                .tags
                .iter()
                .filter_map(|(tag, count)| {
                    if find_tag(&filter_chain, category.as_deref(), tag).is_none() {
                        Some((tag.clone(), *count))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

                vec.sort_by(|(a, _), (b, _)| a.cmp(b));

                vec
            }
        }),

        template: move |(tag_value, count)| {
            let tag = Tag {
                category: category.as_deref().map(String::from),
                value: tag_value.clone(),
            };

            let sub_menu = TagSubMenuProps {
                state: state.clone(),
                tag: tag.clone(),
                filter: filter.clone(),
                filter_chain: filter_chain.clone(),
            };

            let is_filtered = syc::create_selector({
                let filter_chain = filter_chain.clone();
                let filter = filter.clone();
                let tag = tag.clone();

                move || is_filtered(&filter_chain, filter.get().deref(), &tag)
            });

            let toggle = {
                let filter_chain = filter_chain.clone();
                let filter = filter.clone();
                let is_filtered = is_filtered.clone();

                move |_| {
                    let mut new_filter = filter.get().deref().clone();
                    if let Some(tree) = resolve_mut(&filter_chain, &mut new_filter) {
                        if *is_filtered.get() {
                            tree.0.remove(&tag);
                        } else {
                            tree.0.insert(tag.clone(), TagTree::default());
                        }

                        filter.set(new_filter);
                    }
                }
            };

            template! {
                li {
                    a(href="javascript:void(0);", on:click=toggle) {
                        (if *is_filtered.get() {
                            template! {
                                i(class="fa fa-check-square")
                            }
                        } else {
                            template! {
                                i(class="fa fa-square")
                            }
                        }) " " (tag_value) " (" (count) ")"
                    }
                    TagSubMenu(sub_menu)
                }
            }
        },

        key: |(tag, _)| tag.clone(),
    };

    template! {
        ul {
            (categories)
            Keyed(tags)
        }
    }
}

#[derive(Clone)]
struct ImageState {
    datetime: DateTime<Utc>,
    selected: Signal<bool>,
    tags: Signal<HashSet<Tag>>,
}

struct ImagesProps {
    state: Rc<State>,
    image_states: StateHandle<Rc<HashMap<Rc<str>, ImageState>>>,
}

#[component(Images<G>)]
fn images(props: ImagesProps) -> Template<G> {
    let ImagesProps {
        state,
        image_states,
    } = props;

    let images = KeyedProps {
        iterable: syc::create_selector({
            let image_states = image_states.clone();

            move || {
                let image_states = image_states.get();

                let mut vec = image_states
                    .iter()
                    .map(|(hash, _)| hash.clone())
                    .collect::<Vec<_>>();

                vec.sort_by(|a, b| {
                    image_states
                        .get(b.deref())
                        .unwrap()
                        .datetime
                        .cmp(&image_states.get(a.deref()).unwrap().datetime)
                });

                vec
            }
        }),

        template: move |hash| {
            let href = syc::create_selector({
                let hash = hash.clone();
                let state = state.clone();

                move || {
                    format!(
                        "{}/image/{}{}",
                        state.root,
                        hash,
                        if let Some(token) = state.token.get().deref() {
                            format!("?token={}", token)
                        } else {
                            String::new()
                        }
                    )
                }
            });

            let src = syc::create_selector({
                let hash = hash.clone();
                let state = state.clone();

                move || {
                    format!(
                        "{}/image/{}?size=small{}",
                        state.root,
                        hash,
                        if let Some(token) = state.token.get().deref() {
                            format!("&token={}", token)
                        } else {
                            String::new()
                        }
                    )
                }
            });

            let image = image_states.get().get(&hash).unwrap().clone();

            let tags = KeyedProps {
                iterable: syc::create_selector({
                    let tags = image.tags.clone();

                    move || {
                        let mut vec = tags.get().iter().cloned().collect::<Vec<_>>();

                        vec.sort();

                        vec
                    }
                }),

                template: move |tag| {
                    template! {
                        span(class="tag") {
                            (tag)
                        }
                    }
                },

                key: |tag| tag.clone(),
            };

            template! {
                span(class=if *image.selected.get() { "thumbnail-selected" } else { "thumbnail" }) {
                    a(href=href.get()) {
                        img(src=src.get(), class="thumbnail")
                    }
                    Keyed(tags)
                }
            }
        },

        key: |hash| hash.clone(),
    };

    template! {
        div {
            Keyed(images)
        }
    }
}

fn watch<T: Default + for<'de> Deserialize<'de>>(
    uri: &'static str,
    state: Rc<State>,
    filter: StateHandle<TagTree>,
) -> StateHandle<T> {
    let signal = Signal::new(T::default());

    syc::create_effect({
        let signal = signal.clone();

        move || {
            let token = state.token.get();
            let filter = filter.get();

            wasm_bindgen_futures::spawn_local(
                {
                    let state = state.clone();
                    let signal = signal.clone();

                    async move {
                        let mut request = state.client.get(format!(
                            "{}/{}{}",
                            state.root,
                            uri,
                            if let Some(filter) = Option::<TagExpression>::from(filter.deref()) {
                                format!("?filter={}", filter.to_string())
                            } else {
                                String::new()
                            }
                        ));

                        if let Some(token) = token.deref() {
                            request = request.header("authorization", &format!("Bearer {}", token));
                        }

                        signal.set(request.send().await?.json::<T>().await?);

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

struct State {
    token: Signal<Option<String>>,
    root: String,
    client: Client,
}

fn main() -> Result<()> {
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    log::set_logger(&wasm_bindgen_console_logger::DEFAULT_LOGGER)
        .map_err(|e| anyhow!("{:?}", e))?;
    log::set_max_level(log::LevelFilter::Info);

    let location = web_sys::window()
        .ok_or_else(|| anyhow!("can't get browser window"))?
        .location();

    let state = Rc::new(State {
        token: Signal::new(None),
        root: format!(
            "{}//{}",
            location.protocol().map_err(|e| anyhow!("{:?}", e))?,
            location.host().map_err(|e| anyhow!("{:?}", e))?
        ),
        client: Client::new(),
    });

    let filter = Signal::new(TagTree::default());

    let tags = watch::<TagsResponse>("tags", state.clone(), filter.handle());

    let images = watch::<ImagesResponse>("images", state.clone(), filter.handle());

    wasm_bindgen_futures::spawn_local({
        let state = state.clone();

        async move {
            state.token.set(Some(
                state
                    .client
                    .post(format!("{}/token", state.root))
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
            ));

            Ok::<_, Error>(())
        }
        .unwrap_or_else(|e| {
            log::error!("error retrieving data: {:?}", e);
        })
    });

    let show_menu = Signal::new(true);

    let mut image_states = Rc::new(HashMap::<Rc<str>, ImageState>::new());

    let images = ImagesProps {
        state: state.clone(),
        image_states: syc::create_memo(move || {
            log::info!("dicej memo image states");
            image_states = Rc::new(
                images
                    .get()
                    .images
                    .iter()
                    .map(|(hash, data)| {
                        (
                            Rc::from(hash.deref()),
                            if let Some(state) = image_states.get(hash.deref()) {
                                state.tags.set(data.tags.clone());
                                state.clone()
                            } else {
                                ImageState {
                                    datetime: data.datetime,
                                    tags: Signal::new(data.tags.clone()),
                                    selected: Signal::new(false),
                                }
                            },
                        )
                    })
                    .collect::<HashMap<_, _>>(),
            );

            log::info!("dicej done memo image states");

            image_states.clone()
        }),
    };

    let tag_menu = TagMenuProps {
        state,
        filter,
        filter_chain: List::Nil,
        tags,
        category: None,
    };

    sycamore::render(move || {
        let toggle = {
            let show_menu = show_menu.clone();

            move |_| show_menu.set(!*show_menu.get())
        };

        template! {
            div {
                a(href="javascript:void(0);", class="icon", on:click=toggle) {
                    i(class="fa fa-bars")
                }
                div(style=format!("display:{};", if *show_menu.get() { "block" } else { "none" })) {
                    TagMenu(tag_menu)
                }
            }
            Images(images)
        }
    });

    Ok(())
}
