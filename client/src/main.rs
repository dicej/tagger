#![deny(warnings)]

use {
    anyhow::{anyhow, Error, Result},
    chrono::Utc,
    futures::future::TryFutureExt,
    reqwest::{Client, StatusCode},
    serde_derive::{Deserialize, Serialize},
    std::{
        cell::Cell,
        cmp::Ordering,
        collections::{HashMap, HashSet},
        convert::TryFrom,
        ops::Deref,
        panic,
        rc::Rc,
        sync::Arc,
    },
    sycamore::prelude::{
        self as syc, component, template, Indexed, IndexedProps, Keyed, KeyedProps, Signal,
        StateHandle, Template,
    },
    tagger_shared::{
        tag_expression::{Tag, TagExpression, TagState, TagTree},
        Action, Authorization, GrantType, ImageKey, ImagesQuery, ImagesResponse, Medium, Patch,
        TagsResponse, TokenRequest, TokenSuccess,
    },
    wasm_bindgen::{closure::Closure, JsCast},
    web_sys::{Event, HtmlSelectElement, HtmlVideoElement, KeyboardEvent, MouseEvent},
};

const DEFAULT_ITEMS_PER_PAGE: u32 = 100;

#[derive(Clone, Debug)]
enum List<T> {
    Nil,
    Cons(Rc<(T, List<T>)>),
}

fn find_categories<'a>(
    filter_chain: &List<Tag>,
    categories: &'a HashMap<Arc<str>, TagsResponse>,
) -> Option<&'a HashMap<Arc<str>, TagsResponse>> {
    if let List::Cons(cons) = filter_chain {
        let next = find_categories(&cons.1, categories);
        if let Some(category) = cons.0.category.as_deref() {
            next.and_then(|next| next.get(category).map(|tags| &tags.categories))
        } else {
            next
        }
    } else {
        Some(categories)
    }
}

fn subtree(state: &TagState) -> Option<&TagTree> {
    if let TagState::Included(subtree) = state {
        Some(subtree)
    } else {
        None
    }
}

fn subtree_mut(state: &mut TagState) -> Option<&mut TagTree> {
    if let TagState::Included(subtree) = state {
        Some(subtree)
    } else {
        None
    }
}

fn to_tree(filter_chain: &List<Tag>, filter: &TagTree) -> TagTree {
    fn recurse<'a>(
        filter_chain: &List<Tag>,
        filter: &'a TagTree,
        tree: TagTree,
    ) -> (Option<&'a TagTree>, TagTree) {
        match filter_chain {
            List::Nil => (Some(filter), tree),
            List::Cons(cons) => {
                let get_subtree = subtree;
                let (filter, subtree) = recurse(&cons.1, filter, tree);
                let state = filter.and_then(|filter| filter.0.get(&cons.0));

                let mut parent = TagTree::default();
                parent.0.insert(
                    cons.0.clone(),
                    state
                        .and_then(|state| {
                            if let TagState::Excluded = state {
                                Some(TagState::Excluded)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(TagState::Included(subtree)),
                );

                (state.and_then(get_subtree), parent)
            }
        }
    }

    recurse(filter_chain, filter, TagTree::default()).1
}

fn tags_for_category<'a>(
    category: &Option<Arc<str>>,
    filter_chain: &List<Tag>,
    empty: &'a TagsResponse,
    tags: &'a TagsResponse,
) -> &'a HashMap<Arc<str>, u32> {
    &if let Some(category) = category {
        find_categories(filter_chain, &tags.categories)
            .and_then(|categories| categories.get(category.deref()))
            .unwrap_or(empty)
    } else {
        tags
    }
    .tags
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
        List::Cons(cons) => {
            resolve(&cons.1, filter).and_then(|tree| tree.0.get(&cons.0).and_then(subtree))
        }
    }
}

fn resolve_mut<'a>(filter_chain: &List<Tag>, filter: &'a mut TagTree) -> Option<&'a mut TagTree> {
    match filter_chain {
        List::Nil => Some(filter),
        List::Cons(cons) => resolve_mut(&cons.1, filter)
            .and_then(|tree| tree.0.get_mut(&cons.0).and_then(subtree_mut)),
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum FilterState {
    Include,
    Exclude,
    None,
}

fn filter_state(filter_chain: &List<Tag>, filter: &TagTree, tag: &Tag) -> FilterState {
    resolve(filter_chain, filter)
        .and_then(|tree| {
            tree.0.get(tag).map(|state| {
                if let TagState::Excluded = state {
                    FilterState::Exclude
                } else {
                    FilterState::Include
                }
            })
        })
        .unwrap_or(FilterState::None)
}

fn page_start(props: &PaginationProps) {
    props.start.set(None);
}

fn page_back(props: &PaginationProps) {
    props
        .start
        .set(props.images.get().response.later_start.clone());
}

fn page_forward(props: &PaginationProps) {
    let images = props.images.get();
    let ImagesResponse { start, total, .. } = *images.response;
    let count = u32::try_from(images.response.images.len()).unwrap();

    if start + count < total {
        props
            .start
            .set(images.response.images.last().map(|data| data.key()));
    }
}

fn page_end(props: &PaginationProps) {
    if let Some(earliest_start) = &props.images.get().response.earliest_start {
        props.start.set(Some(earliest_start.clone()));
    }
}

#[derive(Clone)]
struct PaginationProps {
    images: StateHandle<ImagesState>,
    start: Signal<Option<ImageKey>>,
    show_message_on_zero: bool,
}

#[component(Pagination<G>)]
fn pagination(props: PaginationProps) -> Template<G> {
    template! {
        span(class="pagination") {
            ({
                let images = props.images.get();
                let ImagesResponse { start, total, .. } = *images.response;

                if total == 0 {
                    if props.show_message_on_zero {
                        template! {
                            em {
                                "No images match current filter"
                            }
                        }
                    } else {
                        template! { }
                    }
                } else {
                    let count = u32::try_from(images.response.images.len()).unwrap();

                    let left_style = if start > 0 {
                        "visibility:visible;"
                    } else {
                        "visibility:hidden;"
                    };

                    let right_style = if start + count < total {
                        "visibility:visible;"
                    } else {
                        "visibility:hidden;"
                    };

                    let props1 = props.clone();
                    let props2 = props.clone();
                    let props3 = props.clone();
                    let props4 = props.clone();

                    template! {
                        i(class="fa fa-angle-double-left big start",
                          on:click=move |_| page_start(&props1),
                          style=left_style) " "

                        i(class="fa fa-angle-left big back",
                          on:click=move |_| page_back(&props2),
                          style=left_style)

                        (format!(" {}-{} of {} ",
                                 start + 1,
                                 start + count,
                                 total))

                        i(class="fa fa-angle-right big forward",
                          on:click=move |_| page_forward(&props3),
                          style=right_style) " "

                        i(class="fa fa-angle-double-right big end",
                          on:click=move |_| page_end(&props4),
                          style=right_style)
                    }
                }
            })
        }
    }
}

struct TagSubMenuProps {
    client: Client,
    token: Signal<Option<String>>,
    root: Rc<str>,
    tag: Tag,
    filter: Signal<TagTree>,
    filter_chain: List<Tag>,
    unfiltered_tags: StateHandle<TagsResponse>,
    on_unauthorized: Rc<dyn Fn()>,
}

#[component(TagSubMenu<G>)]
fn tag_sub_menu(props: TagSubMenuProps) -> Template<G> {
    let TagSubMenuProps {
        client,
        token,
        root,
        tag,
        filter,
        filter_chain,
        unfiltered_tags,
        on_unauthorized,
    } = props;

    let tag_menu = {
        let tag = tag.clone();
        let filter_chain = filter_chain.clone();
        let filter = filter.clone();
        let on_unauthorized = on_unauthorized.clone();

        move || {
            let filter_chain = List::Cons(Rc::new((tag.clone(), filter_chain.clone())));
            let on_unauthorized = on_unauthorized.clone();

            TagMenuProps {
                client: client.clone(),
                token: token.clone(),
                root: root.clone(),
                filter: filter.clone(),
                filter_chain: filter_chain.clone(),
                unfiltered_tags: unfiltered_tags.clone(),
                filtered_tags: watch::<TagsResponse, _>(
                    Signal::new("tags".into()).into_handle(),
                    client.clone(),
                    token.clone(),
                    root.clone(),
                    Signal::new(to_tree(&filter_chain, filter.get().deref())).into_handle(),
                    {
                        let on_unauthorized = on_unauthorized.clone();
                        move || on_unauthorized()
                    },
                ),
                category: None,
                on_unauthorized: on_unauthorized.clone(),
            }
        }
    };

    let filter_state =
        syc::create_selector(move || filter_state(&filter_chain, filter.get().deref(), &tag));

    template! {
        (if let FilterState::Include = *filter_state.get() {
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

fn compare_numeric(a: &str, b: &str) -> Ordering {
    match (a.parse::<u64>(), b.parse::<u64>()) {
        (Ok(a), Ok(b)) => a.cmp(&b),
        (Ok(_), Err(_)) => Ordering::Greater,
        (Err(_), Ok(_)) => Ordering::Less,
        (Err(_), Err(_)) => a.cmp(b),
    }
}

struct TagMenuProps {
    client: Client,
    token: Signal<Option<String>>,
    root: Rc<str>,
    filter: Signal<TagTree>,
    filter_chain: List<Tag>,
    unfiltered_tags: StateHandle<TagsResponse>,
    filtered_tags: StateHandle<TagsResponse>,
    category: Option<Arc<str>>,
    on_unauthorized: Rc<dyn Fn()>,
}

#[component(TagMenu<G>)]
fn tag_menu(props: TagMenuProps) -> Template<G> {
    let TagMenuProps {
        client,
        token,
        root,
        filter,
        filter_chain,
        unfiltered_tags,
        filtered_tags,
        category,
        on_unauthorized,
    } = props;

    let categories = if category.is_none() {
        let categories = KeyedProps {
            iterable: syc::create_selector({
                let unfiltered_tags = unfiltered_tags.clone();
                let filter_chain = filter_chain.clone();

                move || {
                    let unfiltered_tags = unfiltered_tags.get();

                    let empty = HashMap::new();

                    let mut vec = find_categories(&filter_chain, &unfiltered_tags.categories)
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
                let unfiltered_tags = unfiltered_tags.clone();
                let filtered_tags = filtered_tags.clone();
                let client = client.clone();
                let token = token.clone();
                let root = root.clone();
                let filter = filter.clone();
                let on_unauthorized = on_unauthorized.clone();

                move |category| {
                    let tag_menu = TagMenuProps {
                        client: client.clone(),
                        token: token.clone(),
                        root: root.clone(),
                        filter: filter.clone(),
                        filter_chain: filter_chain.clone(),
                        unfiltered_tags: unfiltered_tags.clone(),
                        filtered_tags: filtered_tags.clone(),
                        category: Some(category.clone()),
                        on_unauthorized: on_unauthorized.clone(),
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

    let counts = syc::create_selector({
        let category = category.clone();
        let filter_chain = filter_chain.clone();
        let empty = TagsResponse::default();

        move || tags_for_category(&category, &filter_chain, &empty, &filtered_tags.get()).clone()
    });

    let tags = KeyedProps {
        iterable: syc::create_selector({
            let unfiltered_tags = unfiltered_tags.clone();
            let category = category.clone();
            let filter_chain = filter_chain.clone();
            let empty = TagsResponse::default();

            move || {
                let unfiltered_tags = unfiltered_tags.get();

                let mut vec = tags_for_category(&category, &filter_chain, &empty, &unfiltered_tags)
                    .keys()
                    .filter(|tag| find_tag(&filter_chain, category.as_deref(), tag).is_none())
                    .cloned()
                    .collect::<Vec<_>>();

                vec.sort_by(|a, b| compare_numeric(a, b));

                vec
            }
        }),

        template: move |tag_value| {
            let tag = Tag {
                category: category.clone(),
                value: tag_value.clone(),
            };

            let sub_menu = TagSubMenuProps {
                client: client.clone(),
                token: token.clone(),
                root: root.clone(),
                tag: tag.clone(),
                filter: filter.clone(),
                filter_chain: filter_chain.clone(),
                unfiltered_tags: unfiltered_tags.clone(),
                on_unauthorized: on_unauthorized.clone(),
            };

            let filter_state = syc::create_selector({
                let filter_chain = filter_chain.clone();
                let filter = filter.clone();
                let tag = tag.clone();

                move || filter_state(&filter_chain, filter.get().deref(), &tag)
            });

            let toggle_included = {
                let filter_chain = filter_chain.clone();
                let filter = filter.clone();
                let filter_state = filter_state.clone();
                let tag = tag.clone();

                move |_| {
                    let mut new_filter = filter.get().deref().clone();
                    if let Some(tree) = resolve_mut(&filter_chain, &mut new_filter) {
                        if let FilterState::Include = *filter_state.get() {
                            tree.0.remove(&tag);
                        } else {
                            tree.0.insert(tag.clone(), TagState::default());
                        }

                        filter.set(new_filter);
                    }
                }
            };

            let toggle_excluded = {
                let filter_chain = filter_chain.clone();
                let filter = filter.clone();
                let filter_state = filter_state.clone();

                move |_| {
                    let mut new_filter = filter.get().deref().clone();
                    if let Some(tree) = resolve_mut(&filter_chain, &mut new_filter) {
                        if let FilterState::Exclude = *filter_state.get() {
                            tree.0.remove(&tag);
                        } else {
                            tree.0.insert(tag.clone(), TagState::Excluded);
                        }

                        filter.set(new_filter);
                    }
                }
            };

            let counts = counts.clone();

            let filter_state2 = filter_state.clone();

            template! {
                li {
                    i(class=format!("fa fa-check include{}",
                                    if let FilterState::Include = *filter_state.get() {
                                        " included"
                                    } else {
                                        ""
                                    }), on:click=toggle_included)

                    i(class=format!("fa fa-times exclude{}",
                                    if let FilterState::Exclude = *filter_state2.get() {
                                        " excluded"
                                    } else {
                                        ""
                                    }), on:click=toggle_excluded)

                    " " (tag_value) " (" (*counts.get().get(&tag_value).unwrap_or(&0)) ")"

                    TagSubMenu(sub_menu)
                }
            }
        },

        key: |tag| tag.clone(),
    };

    template! {
        ul {
            (categories)
            Keyed(tags)
        }
    }
}

fn play_video(event: Event) {
    if let Some(video) = event.target() {
        if let Ok(video) = video.dyn_into::<HtmlVideoElement>() {
            let _ = video.play();
        }
    }
}

fn reset_video(event: Event) {
    if let Some(video) = event.target() {
        if let Ok(video) = video.dyn_into::<HtmlVideoElement>() {
            let _ = video.pause();
            video.set_current_time(0.0);
        }
    }
}

#[derive(Clone)]
struct ImageState {
    selected: Signal<bool>,
}

impl Drop for ImageState {
    fn drop(&mut self) {
        if *self.selected.get_untracked() {
            let selected = self.selected.clone();

            wasm_bindgen_futures::spawn_local(async move {
                selected.set(false);
            });
        }
    }
}

struct ImagesProps {
    root: Rc<str>,
    selecting: StateHandle<bool>,
    images: StateHandle<ImagesState>,
    overlay_image: Signal<Option<usize>>,
}

#[component(Images<G>)]
fn images(props: ImagesProps) -> Template<G> {
    let ImagesProps {
        root,
        selecting,
        images,
        overlay_image,
    } = props;

    let images = IndexedProps {
        iterable: syc::create_selector({
            let images = images.clone();

            move || {
                let images = images.get();

                images
                    .response
                    .images
                    .iter()
                    .map(|data| data.hash.clone())
                    .enumerate()
                    .collect()
            }
        }),

        template: move |(index, hash)| {
            let url = format!("{}/image/small/{}", root, hash);

            let images = images.get();

            if let Some(data) = images.response.images.get(index) {
                let state = images.states.get(&data.hash).unwrap();

                let click = {
                    let images = images.clone();
                    let state = state.clone();
                    let selecting = selecting.clone();
                    let overlay_image = overlay_image.clone();

                    move |event: Event| {
                        if *selecting.get() {
                            if !*state.selected.get() {
                                if let Ok(event) = event.dyn_into::<MouseEvent>() {
                                    if event.get_modifier_state("Shift") {
                                        if let (Some(first_selected), Some(last_selected)) = (
                                            images.response.images.iter().position(|data| {
                                                *images
                                                    .states
                                                    .get(&data.hash)
                                                    .unwrap()
                                                    .selected
                                                    .get()
                                            }),
                                            images.response.images.iter().rposition(|data| {
                                                *images
                                                    .states
                                                    .get(&data.hash)
                                                    .unwrap()
                                                    .selected
                                                    .get()
                                            }),
                                        ) {
                                            let range = if index < first_selected {
                                                index..first_selected
                                            } else if last_selected < index {
                                                (last_selected + 1)..(index + 1)
                                            } else {
                                                index..(index + 1)
                                            };

                                            for state in images.response.images[range]
                                                .iter()
                                                .map(|data| images.states.get(&data.hash).unwrap())
                                            {
                                                let selected = &state.selected;
                                                selected.set(true);
                                            }

                                            return;
                                        }
                                    }
                                }
                            }

                            let selected = &state.selected;
                            selected.set(!*selected.get());
                        } else {
                            overlay_image.set(Some(index));
                        }
                    }
                };

                let selected = state.selected.clone();

                match data.medium {
                    Medium::ImageWithVideo | Medium::Video => {
                        let video_url = format!("{}/image/small-video/{}", root, hash);

                        template! {
                            video(src=video_url,
                                  poster=url,
                                  muted="true",
                                  playsinline="true",
                                  class=if *selected.get() { "thumbnail selected" } else { "thumbnail" },
                                  on:mouseenter=play_video,
                                  on:mouseleave=reset_video,
                                  on:ended=reset_video,
                                  on:click=click)
                        }
                    }

                    Medium::Image => template! {
                        img(src=url,
                            class=if *selected.get() { "thumbnail selected" } else { "thumbnail" },
                            on:click=click)
                    },
                }
            } else {
                template! {}
            }
        },
    };

    template! {
        div {
            Indexed(images)
        }
    }
}

fn watch<T: Default + for<'de> serde::Deserialize<'de>, F: Fn() + Clone + 'static>(
    uri: StateHandle<String>,
    client: Client,
    token: Signal<Option<String>>,
    root: Rc<str>,
    filter: StateHandle<TagTree>,
    on_unauthorized: F,
) -> StateHandle<T> {
    let signal = Signal::new(T::default());

    syc::create_effect({
        let signal = signal.clone();

        move || {
            let client = client.clone();
            let token = token.get();
            let filter = filter.get();
            let uri = uri.get();
            let root = root.clone();
            let signal = signal.clone();
            let on_unauthorized = on_unauthorized.clone();

            wasm_bindgen_futures::spawn_local(
                {
                    let uri = uri.clone();

                    async move {
                        let mut request = client.get(format!(
                            "{}/{}{}",
                            root,
                            uri,
                            if let Some(filter) = Option::<TagExpression>::from(filter.deref()) {
                                format!(
                                    "{}filter={}",
                                    if uri.contains('?') { '&' } else { '?' },
                                    filter.to_string()
                                )
                            } else {
                                String::new()
                            }
                        ));

                        if let Some(token) = token.deref() {
                            request = request.header("authorization", &format!("Bearer {}", token));
                        }

                        let response = request.send().await?;

                        if response.status() == StatusCode::UNAUTHORIZED {
                            signal.set(T::default());
                            on_unauthorized();
                        } else {
                            signal.set(response.error_for_status()?.json::<T>().await?);
                        }

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

fn watch_changes<A: Eq>(handle: StateHandle<A>, fun: impl Fn(&Rc<A>, &Rc<A>) + 'static) {
    let mut old = handle.get();

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

fn fold_changes<A: Eq, B>(
    handle: StateHandle<A>,
    signal: Signal<B>,
    fun: impl Fn(Rc<B>, Rc<A>) -> B + 'static,
) {
    watch_changes(handle, move |_, new| {
        signal.set(fun(signal.get_untracked(), new.clone()))
    });
}

fn fold<A, B>(
    handle: StateHandle<A>,
    init: B,
    fun: impl Fn(Rc<B>, Rc<A>) -> B + 'static,
) -> StateHandle<B> {
    let signal = Signal::new(init);

    syc::create_effect({
        let signal = signal.clone();

        move || signal.set(fun(signal.get_untracked(), handle.get()))
    });

    signal.into_handle()
}

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
                let mut request = client.patch(format!("{}/tags", root));

                if let Some(token) = token.get().deref() {
                    request = request.header("authorization", &format!("Bearer {}", token));
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
            log::error!("error patching tags: {:?}", e);
        }),
    )
}

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

enum Direction {
    Left,
    Right,
}

#[derive(Clone, Copy)]
enum Select {
    None,
    First,
    Last,
}

#[derive(Default)]
struct ImagesState {
    response: Rc<ImagesResponse>,
    states: HashMap<Arc<str>, ImageState>,
}

#[derive(Serialize, Deserialize, Debug)]
struct State {
    #[serde(rename = "oi")]
    overlay_image: Option<usize>,

    #[serde(rename = "f")]
    filter: Option<TagTree>,

    #[serde(rename = "s")]
    start: Option<ImageKey>,

    #[serde(rename = "ipp")]
    items_per_page: Option<u32>,
}

fn try_anonymous_login(
    token: Signal<Option<String>>,
    client: Client,
    root: Rc<str>,
    on_unauthorized: impl Fn() + 'static,
) {
    if token.get_untracked().is_some() {
        token.set(None);
    }

    wasm_bindgen_futures::spawn_local(
        async move {
            let response = client.get(format!("{}/token", root)).send().await?;

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
            log::error!("error logging in anonymously: {:?}", e);
        }),
    );
}

fn logged_in(token: &Option<String>) -> bool {
    if let Some(token) = token {
        jsonwebtoken::dangerous_insecure_decode::<Authorization>(token)
            .map(|data| data.claims.subject.is_some())
            .unwrap_or(false)
    } else {
        false
    }
}

fn main() -> Result<()> {
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    log::set_logger(&wasm_bindgen_console_logger::DEFAULT_LOGGER)
        .map_err(|e| anyhow!("{:?}", e))?;

    log::set_max_level(log::LevelFilter::Info);

    let window = web_sys::window().ok_or_else(|| anyhow!("can't get browser window"))?;

    let location = window.location();

    let token = Signal::new(None);

    let root = Rc::<str>::from(format!(
        "{}//{}",
        location.protocol().map_err(|e| anyhow!("{:?}", e))?,
        location.host().map_err(|e| anyhow!("{:?}", e))?
    ));

    let client = Client::new();

    let show_log_in = Signal::new(false);
    let log_in_error = Signal::new(None);
    let user_name = Signal::new(String::new());
    let password = Signal::new(String::new());

    let open_log_in = {
        let show_log_in = show_log_in.clone();
        let log_in_error = log_in_error.clone();
        let user_name = user_name.clone();
        let password = password.clone();

        move || {
            user_name.set(String::new());
            password.set(String::new());
            log_in_error.set(None);
            show_log_in.set(true);
        }
    };

    if let Ok(Some(storage)) = window.local_storage() {
        if let Ok(Some(stored_token)) = storage.get("token") {
            token.set(Some(stored_token));
        } else {
            try_anonymous_login(
                token.clone(),
                client.clone(),
                root.clone(),
                open_log_in.clone(),
            );
        }
    }

    syc::create_effect({
        let token = token.handle();
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

    let overlay_image = Signal::new(None);

    let selecting = Signal::new(false);

    let start = Signal::new(Some(ImageKey {
        datetime: Utc::now(),
        hash: None,
    }));

    let filter = Signal::new(TagTree::default());

    let items_per_page = Signal::new(DEFAULT_ITEMS_PER_PAGE);

    if let Ok(hash) = location.hash() {
        if let Some(hash) = hash.strip_prefix('#') {
            match serde_urlencoded::from_str::<State>(hash) {
                Ok(state) => {
                    overlay_image.set(state.overlay_image);
                    filter.set(state.filter.unwrap_or_default());

                    if let Some(state_start) = state.start {
                        start.set(Some(state_start));
                    }

                    if let Some(state_items_per_page) = state.items_per_page {
                        items_per_page.set(state_items_per_page);
                    }
                }
                Err(e) => {
                    log::warn!("unable to decode state: {:?}", e);
                }
            }
        }
    }

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
            }) {
                Ok(hash) => {
                    let _ = location.set_hash(&hash);
                }
                Err(e) => {
                    log::warn!("unable to encode state: {:?}", e);
                }
            }
        }
    });

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

    let on_unauthorized = {
        let open_log_in = open_log_in.clone();
        let client = client.clone();
        let token = token.clone();
        let root = root.clone();

        move || {
            let was_logged_in = logged_in(token.get().deref());

            try_anonymous_login(token.clone(), client.clone(), root.clone(), || ());

            if was_logged_in {
                open_log_in();
            }
        }
    };

    let unfiltered_tags = watch::<TagsResponse, _>(
        Signal::new("tags".into()).into_handle(),
        client.clone(),
        token.clone(),
        root.clone(),
        Signal::new(TagTree::default()).into_handle(),
        on_unauthorized.clone(),
    );

    let selected_count = Signal::new(0);

    let images = fold(
        watch::<ImagesResponse, _>(
            syc::create_selector({
                let start = start.clone();
                let items_per_page = items_per_page.clone();

                move || {
                    format!(
                        "images?{}",
                        serde_urlencoded::to_string(ImagesQuery {
                            start: start.get().deref().clone(),
                            limit: Some(*items_per_page.get()),
                            filter: None // will be added by `watch`
                        })
                        .unwrap()
                    )
                }
            }),
            client.clone(),
            token.clone(),
            root.clone(),
            filter.handle(),
            on_unauthorized.clone(),
        ),
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

    let show_menu = Signal::new(false);

    let overlay_image_visible = syc::create_selector({
        let overlay_image = overlay_image.clone();

        move || overlay_image.get().is_some()
    });

    let images_props = ImagesProps {
        root: root.clone(),
        selecting: selecting.handle(),
        images: images.clone(),
        overlay_image: overlay_image.clone(),
    };

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

    let tag_menu = TagMenuProps {
        client: client.clone(),
        token: token.clone(),
        root: root.clone(),
        filter: filter.clone(),
        filter_chain: List::Nil,
        unfiltered_tags: unfiltered_tags.clone(),
        filtered_tags: unfiltered_tags.clone(),
        category: None,
        on_unauthorized: Rc::new(on_unauthorized.clone()),
    };

    let toggle_menu = {
        let show_menu = show_menu.clone();

        move |_| show_menu.set(!*show_menu.get())
    };

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

    let close_overlay = {
        let overlay_image = overlay_image.clone();

        move |_| overlay_image.set(None)
    };

    let next = {
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
                            page_back(&props);
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
                                page_forward(&props);
                            }
                        }
                    }
                }
            }
        }
    };

    let keydown = Closure::wrap(Box::new({
        let next = next.clone();
        let overlay_image = overlay_image.clone();

        move |event: KeyboardEvent| match event.key().deref() {
            "ArrowLeft" => next(Direction::Left),
            "ArrowRight" => next(Direction::Right),
            "Escape" => overlay_image.set(None),
            _ => (),
        }
    }) as Box<dyn Fn(KeyboardEvent)>);

    window
        .document()
        .ok_or_else(|| anyhow!("can't get browser document"))?
        .set_onkeydown(Some(keydown.as_ref().unchecked_ref()));

    keydown.forget();

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
                                on_unauthorized.clone(),
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

                template! {
                    span(class="selected-tag") {
                        (tag) " " (if *immutable.get() {
                            template! {}
                        } else {
                            template! {
                                i(class="fa fa-times-circle remove", on:click=remove.clone())
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
        let root = root.clone();
        let input_value = input_value.clone();
        let images = images.clone();
        let token = token.clone();
        let client = client.clone();

        move |event: Event| {
            if let Ok(event) = event.dyn_into::<KeyboardEvent>() {
                if event.key().deref() == "Enter" {
                    match input_value.get().parse::<Tag>() {
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
                                    on_unauthorized.clone(),
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

    let selecting2 = selecting.clone();

    let playing = Signal::new(false);

    let toggle_playing = {
        let playing = playing.clone();

        move |_| playing.set(!*playing.get())
    };

    let pagination1 = PaginationProps {
        images: images.clone(),
        start: start.clone(),
        show_message_on_zero: true,
    };

    let pagination2 = PaginationProps {
        images: images.clone(),
        start,
        show_message_on_zero: false,
    };

    syc::create_effect({
        let overlay_image = overlay_image.clone();
        let playing = playing.clone();

        move || {
            let _ = overlay_image.get();

            playing.set(false)
        }
    });

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

    let close_log_in = {
        let show_log_in = show_log_in.clone();

        move |_| show_log_in.set(false)
    };

    let log_in_key = {
        let user_name = user_name.clone();
        let password = password.clone();
        let show_log_in = show_log_in.clone();
        let log_in_error = log_in_error.clone();
        let token = token.clone();
        let root = root.clone();
        let client = client.clone();

        move |event: Event| {
            if let Ok(event) = event.dyn_into::<KeyboardEvent>() {
                if event.key().deref() == "Enter" {
                    wasm_bindgen_futures::spawn_local(
                        {
                            let user_name = user_name.get();
                            let password = password.get();
                            let show_log_in = show_log_in.clone();
                            let log_in_error = log_in_error.clone();
                            let token = token.clone();
                            let client = client.clone();
                            let root = root.clone();

                            async move {
                                let response = client
                                    .post(format!("{}/token", root))
                                    .form(&TokenRequest {
                                        grant_type: GrantType::Password,
                                        username: user_name.trim().into(),
                                        password: password.trim().into(),
                                    })
                                    .send()
                                    .await?;

                                if response.status() == StatusCode::UNAUTHORIZED {
                                    log_in_error.set(Some("Invalid user name or password".into()));
                                } else {
                                    show_log_in.set(false);

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
                        }
                        .unwrap_or_else({
                            let log_in_error = log_in_error.clone();

                            move |e| {
                                log::error!("error logging in: {:?}", e);

                                log_in_error.set(Some("Error communicating with server".into()));
                            }
                        }),
                    );
                }
            }
        }
    };

    let log_in_key2 = log_in_key.clone();

    let log_out = {
        let token = token.clone();
        let root = root.clone();
        let open_log_in = open_log_in.clone();

        move |_| {
            try_anonymous_login(
                token.clone(),
                client.clone(),
                root.clone(),
                open_log_in.clone(),
            )
        }
    };

    let filter = syc::create_selector(move || Option::<TagExpression>::from(filter.get().deref()));
    let filter2 = filter.clone();

    let log_in_error2 = log_in_error.clone();

    let logged_in = syc::create_selector({
        let token = token.handle();

        move || logged_in(token.get().deref())
    });

    let selected = syc::create_selector(move || *selected_count.get() > 0);

    let open_log_in_event = move |_| open_log_in();

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

    sycamore::render(move || {
        template! {
            div(class="overlay",
                style=format!("height:{};", if *overlay_image_visible.get() { "100%" } else { "0" }))
            {
                i(class="fa fa-times big close", on:click=close_overlay)

                (if let Some(index) = *overlay_image.get() {
                    let images = images.get();

                    if let Some(image) = images.response.images.get(index) {
                        let url = format!("{}/image/large/{}", root, image.hash);

                        let medium = image.medium;

                        let mut vec = image.tags.iter().cloned().collect::<Vec<_>>();

                        vec.sort();

                        let tags = IndexedProps {
                            iterable: Signal::new(vec).into_handle(),

                            template: |tag| {
                                template! {
                                    span(class="tag") {
                                        (tag)
                                    }
                                }
                            }
                        };

                        let playing = *playing.get();

                        let play_button = match medium {
                            Medium::ImageWithVideo => {
                                template! {
                                    i(class=format!("big play fa {}", if playing { "fa-stop" } else { "fa-play" }),
                                      on:click=toggle_playing.clone())
                                }
                            }
                            Medium::Image | Medium::Video => template! {}
                        };

                        let count = u32::try_from(images.response.images.len()).unwrap();
                        let ImagesResponse { start, total, .. } = *images.response;

                        let have_left = index > 0 || start > 0;
                        let have_right = index + 1 < images.response.images.len() || start + count < total;

                        let left = if have_left {
                            let next = next.clone();

                            template! {
                                i(class="fa fa-angle-left big left",
                                  on:click=move |_| next(Direction::Left))
                            }
                        } else {
                            template! {}
                        };

                        let right = if have_right {
                            let next = next.clone();

                            template! {
                                i(class="fa fa-angle-right big right",
                                  on:click=move |_| next(Direction::Right))
                            }
                        } else {
                            template! {}
                        };

                        let original_url = format!("{}/image/original/{}", root, image.hash);

                        let show_video = match medium {
                            Medium::ImageWithVideo => playing,
                            Medium::Video => true,
                            Medium::Image => false
                        };

                        let image = if show_video {
                            let video_url = format!("{}/image/large-video/{}", root, image.hash);

                            template! {
                                video(src=video_url,
                                      poster=url,
                                      autoplay="true",
                                      controls="true")
                            }
                        } else {
                            template! {
                                img(src=url)
                            }
                        };

                        template! {
                            (left) (right) (play_button) (image) span(class="tags") {
                                Indexed(tags)
                            }

                            a(href=original_url, class="original", target="_blank") {
                                "original"
                            }
                        }
                    } else {
                        template! {}
                    }
                } else {
                    template! {}
                })
            }

            div(class="log-in",
                style=format!("height:{};", if *show_log_in.get() { "100%" } else { "0" }))
            {
                div(class="error",
                    style=if log_in_error.get().is_some() {
                        "visibility:visible;"
                    } else {
                        "visibility:hidden;"
                    })
                {
                    (log_in_error2.get().deref().clone().unwrap_or_else(|| "placeholder".to_owned()))
                }

                i(class="fa fa-times big close", on:click=close_log_in) {}

                form(class="log-in") {
                    p {
                        label(for="user_name") { "user name: " }

                        input(bind:value=user_name.clone(),
                              on:keyup=log_in_key,
                              id="user_name") {}
                    }

                    p {
                        label(for="password") { "password: " }

                        input(type="password",
                              on:keyup=log_in_key2,
                              bind:value=password.clone(),
                              id="password") {}
                    }
                }
            }

            div {
                div(class="nav") {
                    i(class="fa fa-bars big filter", on:click=toggle_menu)

                    Pagination(pagination1)

                    (if *may_select.get() {
                        let selecting = selecting.clone();
                        let toggle_selecting = toggle_selecting.clone();

                        template! {
                            i(class=format!("fa fa-th-large big select{}", if *selecting.get() {
                                " enabled"
                            } else {
                                ""
                            }),
                              on:click=toggle_selecting)
                        }
                    } else {
                        template! {}
                    })
                }

                div(style=format!("display:{};", if *show_menu.get() { "block" } else { "none" })) {
                    (if *logged_in.get() {
                        template! {
                            div(class="link", on:click=log_out.clone()) { "log out" }
                        }
                    } else {
                        template! {
                            div(class="link", on:click=open_log_in_event.clone()) { "log in" }
                        }
                    })

                    label(for="items_per_page") { "items per page: " }

                    select(name="items_per_page",
                           id="items_per_page",
                           on:change=set_items_per_page)
                    {
                        (match *items_per_page.get() {
                            1000 => template! {
                                option(value="100") { "100" }
                                option(value="1000", selected=true) { "1000" }
                            },
                            _ => template! {
                                option(value="100", selected=true) { "100" }
                                option(value="1000") { "1000" }
                            },
                        })
                    }

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
                                                  bind:value=input_value.clone())
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

                div(style=format!("display:{};", if filter.get().is_some() { "block" } else { "none" })) {
                    "filter: " (filter2.get().deref().as_ref().map
                                (|expression| expression.to_string()).unwrap_or_else(String::new))
                }
            }

            Images(images_props)

            div(class="nav") {
                Pagination(pagination2)
            }
        }
    });

    Ok(())
}
