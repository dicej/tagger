#![deny(warnings)]

use anyhow::{anyhow, Error, Result};
use chrono::{DateTime, Utc};
use futures::future::TryFutureExt;
use reqwest::Client;
use serde::Deserialize;
use std::{
    cell::Cell,
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
    Action, GrantType, ImagesResponse, Patch, TagsResponse, TokenRequest, TokenSuccess,
};
use wasm_bindgen::{closure::Closure, JsCast};
use web_sys::{Event, KeyboardEvent, MouseEvent, TouchEvent};

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

            let have_filter = syc::create_selector({
                let filter_chain = filter_chain.clone();
                let filter = filter.clone();

                move || {
                    resolve(&filter_chain, filter.get().deref())
                        .map(|tree| !tree.0.is_empty())
                        .unwrap_or(false)
                }
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
                        (if *have_filter.get() {
                            if *is_filtered.get() {
                                template! {
                                    i(class="fa fa-check-square")
                                }
                            } else {
                                template! {
                                    i(class="fa fa-square")
                                }
                            }
                        } else {
                            template! {
                                i(class="fa fa-minus-square")
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
            let src = format!("{}/image/{}?size=small", state.root, hash);

            let image = image_states.get().get(&hash).unwrap().clone();

            let click = {
                let image_states = image_states.clone();
                let state = state.clone();

                move |event: Event| {
                    if *state.selecting.get() {
                        let image_states = image_states.get();

                        if let Ok(event) = event.dyn_into::<MouseEvent>() {
                            if event.get_modifier_state("Shift") {
                                let mut vec = image_states.keys().cloned().collect::<Vec<_>>();

                                vec.sort_by(|a, b| {
                                    image_states
                                        .get(b.deref())
                                        .unwrap()
                                        .datetime
                                        .cmp(&image_states.get(a.deref()).unwrap().datetime)
                                });

                                if let (Some(first_selected), Some(last_selected), Some(me)) = (
                                    vec.iter().position(|hash| {
                                        *image_states.get(hash.deref()).unwrap().selected.get()
                                    }),
                                    vec.iter().rposition(|hash| {
                                        *image_states.get(hash.deref()).unwrap().selected.get()
                                    }),
                                    vec.iter().position(|other| other == &hash),
                                ) {
                                    let range = if me < first_selected {
                                        me..first_selected
                                    } else if last_selected < me {
                                        (last_selected + 1)..(me + 1)
                                    } else {
                                        me..(me + 1)
                                    };

                                    for hash in &vec[range] {
                                        let selected = &image_states.get(hash).unwrap().selected;
                                        selected.set(!*selected.get());
                                    }

                                    return;
                                }
                            }
                        }

                        let selected = &image_states.get(&hash).unwrap().selected;
                        selected.set(!*selected.get());
                    } else {
                        state.full_size_image.set(Some(hash.clone()));
                    }
                }
            };

            template! {
                img(src=src,
                    class=if *image.selected.get() { "thumbnail selected" } else { "thumbnail" },
                    on:click=click)
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

fn event_coordinates(event: Event) -> Option<(i32, i32)> {
    match event.dyn_into::<MouseEvent>() {
        Ok(event) => Some((event.client_x(), event.client_y())),
        Err(event) => match event.dyn_into::<TouchEvent>() {
            Ok(event) => {
                let touches = event.changed_touches();

                if touches.length() == 1 {
                    touches
                        .get(0)
                        .map(|touch| (touch.client_x(), touch.client_y()))
                } else {
                    None
                }
            }
            Err(_) => None,
        },
    }
}

fn patch_tags(state: Rc<State>, patches: Vec<Patch>) {
    wasm_bindgen_futures::spawn_local(
        {
            async move {
                let mut request = state.client.patch(format!("{}/tags", state.root));

                if let Some(token) = state.token.get().deref() {
                    request = request.header("authorization", &format!("Bearer {}", token));
                }

                let status = request.json(&patches).send().await?.status();

                if !status.is_success() {
                    return Err(anyhow!("unexpected status code: {}", status));
                }

                state.token.trigger_subscribers();

                Ok::<_, Error>(())
            }
        }
        .unwrap_or_else(move |e| {
            log::error!("error patching tags: {:?}", e);
        }),
    )
}

fn is_immutable_category(tags: &TagsResponse, category: Option<&str>) -> bool {
    fn recurse(tags: &TagsResponse, category: &str) -> Option<bool> {
        for (cat, tags) in &tags.categories {
            if cat == category {
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

struct State {
    token: Signal<Option<String>>,
    root: String,
    client: Client,
    full_size_image: Signal<Option<Rc<str>>>,
    selecting: Signal<bool>,
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
        selecting: Signal::new(false),
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
        tags: tags.clone(),
        category: None,
    };

    let toggle_menu = {
        let show_menu = show_menu.clone();

        move |_| show_menu.set(!*show_menu.get())
    };

    let toggle_selecting = {
        let selecting = state.selecting.clone();
        let image_states = image_states.clone();

        move |_| {
            if *selecting.get() {
                for state in image_states.get().values() {
                    state.selected.set(false);
                }
            }

            selecting.set(!*selecting.get())
        }
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
        let full_size_image = full_size_image.clone();
        let image_states = image_states.clone();

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
            down_coordinates.set(event_coordinates(event));
        }
    };

    let mouseup = {
        let full_size_image = state.full_size_image.clone();
        let state = state.clone();

        move |event: Event| {
            if let Some((down_x, down_y)) = down_coordinates.get() {
                down_coordinates.set(None);

                if let Some((up_x, up_y)) = event_coordinates(event) {
                    if (up_y - down_y).abs() > 2 * (up_x - down_x).abs() {
                        if (up_y - down_y).abs() > SWIPE_THRESHOLD_PIXELS {
                            full_size_image.set(None);
                            return;
                        }
                    } else if (up_x - down_x).abs() > 2 * (up_y - down_y).abs() {
                        if up_x + SWIPE_THRESHOLD_PIXELS < down_x {
                            next(Direction::Right);
                            return;
                        } else if down_x + SWIPE_THRESHOLD_PIXELS < up_x {
                            next(Direction::Left);
                            return;
                        }
                    }
                }

                if let Some(image) = full_size_image.get().deref() {
                    let _ = location.assign(&format!("{}/image/{}", state.root, image));
                }
            }
        }
    };

    window
        .document()
        .ok_or_else(|| anyhow!("can't get browser document"))?
        .set_onkeydown(Some(keydown.as_ref().unchecked_ref()));

    keydown.forget();

    let selected_tags = KeyedProps {
        iterable: syc::create_selector({
            let image_states = image_states.clone();

            move || {
                let mut vec = image_states
                    .get()
                    .values()
                    .filter(|state| *state.selected.get())
                    .flat_map(|state| state.tags.get().deref().clone())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();

                vec.sort();

                vec
            }
        }),

        template: {
            let state = state.clone();
            let image_states = image_states.clone();
            let tags = tags.clone();

            move |tag| {
                let remove = {
                    let tag = tag.clone();
                    let tags = tags.clone();
                    let state = state.clone();
                    let image_states = image_states.clone();

                    move |_| {
                        if !is_immutable_category(tags.get().deref(), tag.category.as_deref()) {
                            patch_tags(
                                state.clone(),
                                image_states
                                    .get()
                                    .iter()
                                    .filter_map(|(hash, state)| {
                                        if *state.selected.get() && state.tags.get().contains(&tag)
                                        {
                                            Some(Patch {
                                                hash: String::from(hash.deref()),
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
                    let tags = tags.clone();

                    move || is_immutable_category(tags.get().deref(), tag.category.as_deref())
                });

                template! {
                    span(class="selected-tag") {
                        (tag) " " (if *immutable.get() {
                            template! {}
                        } else {
                            template! {
                                a(href="javascript:void(0);", class="remove", on:click=remove.clone()) {
                                    i(class="fa fa-times-circle")
                                }
                            }
                        })
                    }
                }
            }
        },

        key: |tag| tag.clone(),
    };

    let input_value = Signal::new(String::new());

    let inputkey = {
        let state = state.clone();
        let input_value = input_value.clone();
        let image_states = image_states.clone();

        move |event: Event| {
            if let Ok(event) = event.dyn_into::<KeyboardEvent>() {
                if event.key().deref() == "Enter" {
                    match input_value.get().parse::<Tag>() {
                        Ok(tag) => {
                            if is_immutable_category(tags.get().deref(), tag.category.as_deref()) {
                                log::error!(
                                    "cannot add tag {} since it belongs to an immutable category",
                                    tag
                                )
                            } else {
                                patch_tags(
                                    state.clone(),
                                    image_states
                                        .get()
                                        .iter()
                                        .filter_map(|(hash, state)| {
                                            if *state.selected.get()
                                                && !state.tags.get().contains(&tag)
                                            {
                                                Some(Patch {
                                                    hash: String::from(hash.deref()),
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

                        Err(e) => log::error!("unable to parse tag {}: {:?}", input_value.get(), e),
                    }

                    input_value.set(String::new());
                }
            }
        }
    };

    let selecting = state.selecting.clone();
    let selecting2 = state.selecting.clone();

    let selected = syc::create_selector({
        let image_states = image_states.clone();

        move || {
            image_states
                .get()
                .values()
                .any(|state| *state.selected.get())
        }
    });

    sycamore::render(move || {
        template! {
            div(class="overlay",
                style=format!("height:{};", if *full_size_image_visible.get() { "100%" } else { "0" })) {

                span(class="close cursor", on:click=close_full_size) {
                    "×"
                }

                (if let Some(image) = full_size_image.get().deref() {
                    let url = format!("{}/image/{}?size=large", state.root, image);

                    let image = image_states.get().get(image).unwrap().clone();

                    let tags = KeyedProps {
                        iterable: syc::create_selector({
                            move || {
                                let mut vec = image.tags.get().iter().cloned().collect::<Vec<_>>();

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
                        img(src=url,
                            on:mousedown=mousedown.clone(),
                            on:mouseup=mouseup.clone(),
                            on:mouseleave=mouseup.clone(),
                            on:touchstart=mousedown.clone(),
                            on:touchend=mouseup.clone(),
                            on:touchcancel=mouseup.clone()) {}

                        span(class="tags") {
                            Keyed(tags)
                        }
                    }
                } else {
                    template! {}
                })
            }

            div {
                div(class="nav") {
                    a(href="javascript:void(0);", class="icon filter", on:click=toggle_menu) {
                        i(class="fa fa-bars")
                    }

                    a(href="javascript:void(0);",
                      class=format!("icon select {}", if *selecting.get() { " enabled" } else { "" }),
                      on:click=toggle_selecting)
                    {
                        i(class="fa fa-th-large")
                    }
                }

                div(style=format!("display:{};", if *show_menu.get() { "block" } else { "none" })) {
                    TagMenu(tag_menu)
                }

                div(style=format!("display:{};", if *selecting2.get() { "block" } else { "none" })) {
                    (if *selected.get() {
                        template! {
                            div {
                                "tags: " Keyed(KeyedProps {
                                    iterable: selected_tags.iterable.clone(),
                                    template: selected_tags.template.clone(),
                                    key: selected_tags.key
                                })
                            }

                            div {
                                "add tag: " input(on:keyup=inputkey.clone(),
                                                  bind:value=input_value.clone(),
                                                  class="edit")
                            }
                        }
                    } else {
                        template! {
                            em {
                                "Click images to select them"
                            }
                        }
                    })
                }
            }

            Images(images)
        }
    });

    Ok(())
}
