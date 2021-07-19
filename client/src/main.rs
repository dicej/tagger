#![deny(warnings)]

use anyhow::{anyhow, Error, Result};
use chrono::{DateTime, Utc};
use fluvio_wasm_timer::Delay;
use futures::future::TryFutureExt;
use reqwest::Client;
use serde::Deserialize;
use std::{
    cell::Cell,
    collections::{HashMap, HashSet},
    ops::Deref,
    panic,
    rc::Rc,
    time::Duration,
};
use sycamore::prelude::{
    self as syc, component, template, Keyed, KeyedProps, Signal, StateHandle, Template,
};
use tagger_shared::{
    tag_expression::{Tag, TagExpression, TagTree},
    GrantType, ImagesResponse, TagsResponse, TokenRequest, TokenSuccess,
};
use wasm_bindgen::{closure::Closure, JsCast};
use web_sys::{Event, KeyboardEvent, MouseEvent, TouchEvent};

const LONG_CLICK_DELAY: Duration = Duration::from_secs(1);

const SWIPE_THRESHOLD_PIXELS: i32 = 50;

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
                        .keys()
                        .cloned()
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

                let mut vec = image_states.keys().cloned().collect::<Vec<_>>();

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

            let is_down = Rc::new(Cell::new(false));

            let down = {
                let image_states = image_states.clone();
                let is_down = is_down.clone();
                let selected = image.selected.clone();

                move |event: Event| {
                    event.prevent_default();

                    if image_states
                        .get()
                        .values()
                        .any(|state| *state.selected.get())
                    {
                        selected.set(!*selected.get());
                    } else {
                        is_down.set(true);

                        wasm_bindgen_futures::spawn_local({
                            let is_down = is_down.clone();
                            let selected = selected.clone();

                            async move {
                                let _ = Delay::new(LONG_CLICK_DELAY).await;

                                if is_down.get() {
                                    is_down.set(false);
                                    selected.set(!*selected.get());
                                }
                            }
                        });
                    }
                }
            };

            let up = {
                let full_size_image = state.full_size_image.clone();

                move |event: Event| {
                    event.prevent_default();

                    if is_down.get() {
                        is_down.set(false);
                        full_size_image.set(Some(hash.clone()));
                    }
                }
            };

            template! {
                span(class=if *image.selected.get() { "thumbnail-selected" } else { "thumbnail" }) {
                    img(src=src.get(),
                        class="thumbnail",
                        on:mousedown=down.clone(),
                        on:mouseup=up.clone(),
                        on:mouseleave=up.clone(),
                        on:touchstart=down,
                        on:touchend=up.clone(),
                        on:touchcancel=up)
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

fn full_size_image_url(state: Rc<State>, hash: &str) -> String {
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

fn event_coordinates(event: Event) -> Option<(i32, i32)> {
    match event.dyn_into::<MouseEvent>() {
        Ok(event) => Some((event.client_x(), event.client_y())),
        Err(event) => match event.dyn_into::<TouchEvent>() {
            Ok(event) => event
                .changed_touches()
                .get(0)
                .map(|touch| (touch.client_x(), touch.client_y())),
            Err(_) => None,
        },
    }
}

struct State {
    token: Signal<Option<String>>,
    root: String,
    client: Client,
    full_size_image: Signal<Option<Rc<str>>>,
}

fn main() -> Result<()> {
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    log::set_logger(&wasm_bindgen_console_logger::DEFAULT_LOGGER)
        .map_err(|e| anyhow!("{:?}", e))?;
    log::set_max_level(log::LevelFilter::Info);

    let window = web_sys::window().ok_or_else(|| anyhow!("can't get browser window"))?;

    let location = window.location();

    let state = Rc::new(State {
        token: Signal::new(None),
        root: format!(
            "{}//{}",
            location.protocol().map_err(|e| anyhow!("{:?}", e))?,
            location.host().map_err(|e| anyhow!("{:?}", e))?
        ),
        client: Client::new(),
        full_size_image: Signal::new(None),
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

    let show_menu = Signal::new(false);

    let mut image_states = Rc::new(HashMap::<Rc<str>, ImageState>::new());

    let image_states = syc::create_memo(move || {
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

        image_states.clone()
    });

    let images = ImagesProps {
        state: state.clone(),
        image_states: image_states.clone(),
    };

    let full_size_image = state.full_size_image.clone();
    let full_size_image_visible = syc::create_selector({
        let full_size_image = full_size_image.clone();

        move || full_size_image.get().is_some()
    });

    let tag_menu = TagMenuProps {
        state: state.clone(),
        filter,
        filter_chain: List::Nil,
        tags,
        category: None,
    };

    let toggle = {
        let show_menu = show_menu.clone();

        move |_| show_menu.set(!*show_menu.get())
    };

    let close_full_size = {
        let full_size_image = full_size_image.clone();

        move |_| full_size_image.set(None)
    };

    enum Direction {
        Left,
        Right,
    }

    let next = {
        let image_states = image_states.clone();
        let full_size_image = full_size_image.clone();

        move |direction| {
            if let Some(image) = full_size_image.get().deref() {
                let image_states = image_states.get();

                let mut vec = image_states.keys().cloned().collect::<Vec<_>>();

                vec.sort_by(|a, b| {
                    image_states
                        .get(b.deref())
                        .unwrap()
                        .datetime
                        .cmp(&image_states.get(a.deref()).unwrap().datetime)
                });

                if let Some(index) = vec.iter().position(|hash| hash == image) {
                    match direction {
                        Direction::Left => full_size_image
                            .set(Some(vec[(index + (vec.len() - 1)) % vec.len()].clone())),
                        Direction::Right => {
                            full_size_image.set(Some(vec[(index + 1) % vec.len()].clone()))
                        }
                    }
                }
            }
        }
    };

    let keydown = Closure::wrap(Box::new({
        let next = next.clone();

        move |event: KeyboardEvent| match event.key().deref() {
            "ArrowLeft" => next(Direction::Left),
            "ArrowRight" => next(Direction::Right),
            _ => (),
        }
    }) as Box<dyn Fn(KeyboardEvent)>);

    let down_coordinates = Rc::new(Cell::new(None));

    let mousedown = {
        let down_coordinates = down_coordinates.clone();

        move |event: Event| {
            event.prevent_default();

            down_coordinates.set(event_coordinates(event));
        }
    };

    let mouseup = {
        let full_size_image = state.full_size_image.clone();

        move |event: Event| {
            event.prevent_default();

            if let Some((down_x, down_y)) = down_coordinates.get() {
                down_coordinates.set(None);

                if let Some((up_x, up_y)) = event_coordinates(event) {
                    if (up_y - down_y).abs() > 2 * (up_x - down_x).abs() {
                        if (up_y - down_y).abs() > SWIPE_THRESHOLD_PIXELS {
                            full_size_image.set(None);
                        }
                    } else if (up_x - down_x).abs() > 2 * (up_y - down_y).abs() {
                        if up_x + SWIPE_THRESHOLD_PIXELS < down_x {
                            next(Direction::Right);
                        } else if down_x + SWIPE_THRESHOLD_PIXELS < up_x {
                            next(Direction::Left);
                        }
                    }
                }
            }
        }
    };

    window
        .document()
        .ok_or_else(|| anyhow!("can't get browser document"))?
        .set_onkeydown(Some(keydown.as_ref().unchecked_ref()));

    keydown.forget();

    sycamore::render(move || {
        template! {
            div(class="overlay",
                style=format!("height:{};", if *full_size_image_visible.get() { "100%" } else { "0" })) {

                span(class="close cursor", on:click=close_full_size) {
                    "×"
                }

                (if let Some(image) = full_size_image.get().deref() {
                    let url = full_size_image_url(state.clone(), image);
                    template! {
                        img(src=url,
                            on:mousedown=mousedown.clone(),
                            on:mouseup=mouseup.clone(),
                            on:mouseleave=mouseup.clone(),
                            on:touchstart=mousedown.clone(),
                            on:touchend=mouseup.clone(),
                            on:touchcancel=mouseup.clone())
                    }
                } else {
                    template! {}
                })
            }
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
