#![deny(warnings)]

use anyhow::{anyhow, Error, Result};
use futures::future::TryFutureExt;
use reqwest::Client;
use serde::Deserialize;
use std::{collections::HashMap, ops::Deref, rc::Rc};
use sycamore::prelude::{
    self as syc, component, template, Keyed, KeyedProps, Signal, StateHandle, Template,
};
use tagger_shared::{
    tag_expression::{Tag, TagExpression, TagTree},
    GrantType, ImagesResponse, TagsResponse, TokenRequest, TokenSuccess,
};

#[derive(Clone)]
enum List<T> {
    Nil,
    Cons(Rc<(T, List<T>)>),
}

struct TagMenuProps {
    state: Rc<State>,
    filter_tree: StateHandle<TagTree>,
    filter_chain: List<Tag>,
    tags: StateHandle<TagsResponse>,
    category: Option<Rc<str>>,
}

fn find_categories<'a>(
    filter_chain: &List<Tag>,
    categories: &'a HashMap<String, TagsResponse>,
) -> &'a HashMap<String, TagsResponse> {
    if let List::Cons(cons) = filter_chain {
        let next = find_categories(&cons.1, categories);
        if let Some(category) = cons.0.category.as_ref() {
            &next.get(category).unwrap().categories
        } else {
            &next
        }
    } else {
        categories
    }
}

fn to_expression(mut filter_chain: &List<Tag>) -> Option<TagExpression> {
    let mut expression = None;
    loop {
        match filter_chain {
            List::Nil => break expression,
            List::Cons(cons) => {
                let tag = TagExpression::Tag(cons.0.clone());
                expression = Some(if let Some(expression) = expression {
                    TagExpression::And(Box::new(tag), Box::new(expression))
                } else {
                    tag
                });
                filter_chain = &cons.1;
            }
        }
    }
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

#[component(TagMenu<G>)]
fn tag_menu(props: TagMenuProps) -> Template<G> {
    let TagMenuProps {
        state,
        filter_tree,
        filter_chain,
        tags,
        category,
    } = props;

    let categories = if category.is_none() {
        let categories = KeyedProps {
            iterable: syc::create_memo({
                let tags = tags.clone();

                move || {
                    let tags = tags.get();

                    let mut vec = find_categories(&filter_chain, &tags.categories)
                        .iter()
                        .map(|(category, _)| category.clone())
                        .collect::<Vec<_>>();

                    vec.sort();

                    vec
                }
            }),

            template: move |category| {
                let tag_menu = TagMenuProps {
                    state,
                    filter_tree,
                    filter_chain,
                    tags,
                    category: Some(Rc::from(category)),
                };

                template! {
                    li {
                        (category)
                        ul {
                            TagMenu(tag_menu)
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
        iterable: syc::create_memo(move || {
            let tags = tags.get();

            let mut vec = if let Some(category) = category {
                find_categories(&filter_chain, &tags.categories)
                    .get(category.deref())
                    .unwrap()
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
        }),

        template: move |(tag, count)| {
            let tag = Tag {
                category: category.as_deref().map(String::from),
                value: tag.clone(),
            };

            let sub_list = if let Some(filter_tree) = filter_tree.get().0.get(&tag) {
                let filter_chain = List::Cons(Rc::new((tag, filter_chain)));

                let tag_menu = TagMenuProps {
                    state,
                    filter_tree: Signal::new(filter_tree.clone()).into_handle(),
                    filter_chain,
                    tags: watch::<TagsResponse>(
                        "tags",
                        state,
                        Signal::new(to_expression(&filter_chain)).into_handle(),
                    ),
                    category: None,
                };

                template! {
                    ul {
                        TagMenu(tag_menu)
                    }
                }
            } else {
                template! {}
            };

            template! {
                li {
                    (tag.value) " (" (count) ")" (sub_list)
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

struct ImagesProps {
    state: Rc<State>,
    images: StateHandle<ImagesResponse>,
}

#[component(Images<G>)]
fn images(props: ImagesProps) -> Template<G> {
    let ImagesProps { state, images } = props;

    let images = KeyedProps {
        iterable: syc::create_memo(move || {
            let images = images.get();

            let mut vec = images
                .images
                .iter()
                .map(|(hash, _)| hash.clone())
                .collect::<Vec<_>>();

            vec.sort_by(|a, b| {
                images
                    .images
                    .get(b.deref())
                    .unwrap()
                    .datetime
                    .cmp(&images.images.get(a.deref()).unwrap().datetime)
            });

            vec
        }),

        template: move |hash| {
            let href = syc::create_memo({
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

            let src = syc::create_memo({
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

            template! {
                a(href=href.get()) {
                    img(src=src.get())
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
    filter: StateHandle<Option<TagExpression>>,
) -> StateHandle<T> {
    let signal = Signal::new(T::default());

    syc::create_effect(move || {
        let state = state.clone();
        let token = state.token.get();
        let filter = filter.get();

        wasm_bindgen_futures::spawn_local(
            {
                let state = state.clone();
                let signal = signal.clone();

                async move {
                    let mut request = state.client.get(format!(
                        "{}/{}?filter={}",
                        state.root,
                        uri,
                        if let Some(filter) = filter.deref() {
                            filter.to_string()
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
    });

    signal.into_handle()
}

struct State {
    token: Signal<Option<String>>,
    root: String,
    client: Client,
}

fn main() -> Result<()> {
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

    let filter = Signal::new(None);

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

    let images = ImagesProps { state, images };

    let tag_menu = TagMenuProps {
        state,
        filter_tree: syc::create_memo(move || TagTree::from(filter.get().as_ref().as_ref())),
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
