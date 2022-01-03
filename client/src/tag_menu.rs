use {
    crate::watch,
    reqwest::Client,
    std::{cmp::Ordering, collections::HashMap, ops::Deref, rc::Rc, sync::Arc},
    sycamore::prelude::{
        self as syc, component, view, Keyed, KeyedProps, ReadSignal, Signal, View,
    },
    tagger_shared::{
        tag_expression::{Tag, TagState, TagTree},
        TagsResponse,
    },
};

#[derive(Clone, Debug)]
pub enum List<T> {
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

pub struct TagMenuCommonProps {
    pub client: Client,
    pub token: Signal<Option<String>>,
    pub root: Rc<str>,
    pub filter: Signal<TagTree>,
    pub filter_chain: List<Tag>,
    pub unfiltered_tags: ReadSignal<TagsResponse>,
    pub on_unauthorized: Rc<dyn Fn()>,
}

struct TagSubMenuProps {
    common: TagMenuCommonProps,
    tag: Tag,
}

#[component(TagSubMenu<G>)]
#[allow(clippy::redundant_closure)]
fn tag_sub_menu(props: TagSubMenuProps) -> View<G> {
    let TagSubMenuProps {
        common:
            TagMenuCommonProps {
                client,
                token,
                root,
                filter,
                filter_chain,
                unfiltered_tags,
                on_unauthorized,
            },
        tag,
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
                common: TagMenuCommonProps {
                    client: client.clone(),
                    token: token.clone(),
                    root: root.clone(),
                    filter: filter.clone(),
                    filter_chain: filter_chain.clone(),
                    unfiltered_tags: unfiltered_tags.clone(),
                    on_unauthorized: on_unauthorized.clone(),
                },
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
            }
        }
    };

    let filter_state =
        syc::create_selector(move || filter_state(&filter_chain, filter.get().deref(), &tag));

    view! {
        (if let FilterState::Include = *filter_state.get() {
            let tag_menu = tag_menu();

            view! {
                ul {
                    TagMenu(tag_menu)
                }
            }
        } else {
            view! {}
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

pub struct TagMenuProps {
    pub common: TagMenuCommonProps,
    pub filtered_tags: ReadSignal<TagsResponse>,
    pub category: Option<Arc<str>>,
}

#[component(TagMenu<G>)]
pub fn tag_menu(props: TagMenuProps) -> View<G> {
    let TagMenuProps {
        common:
            TagMenuCommonProps {
                client,
                token,
                root,
                filter,
                filter_chain,
                unfiltered_tags,
                on_unauthorized,
            },
        filtered_tags,
        category,
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
                        common: TagMenuCommonProps {
                            client: client.clone(),
                            token: token.clone(),
                            root: root.clone(),
                            filter: filter.clone(),
                            filter_chain: filter_chain.clone(),
                            unfiltered_tags: unfiltered_tags.clone(),
                            on_unauthorized: on_unauthorized.clone(),
                        },
                        filtered_tags: filtered_tags.clone(),
                        category: Some(category.clone()),
                    };

                    view! {
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

        view! {
            Keyed(categories)
        }
    } else {
        view! {}
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
                common: TagMenuCommonProps {
                    client: client.clone(),
                    token: token.clone(),
                    root: root.clone(),
                    filter: filter.clone(),
                    filter_chain: filter_chain.clone(),
                    unfiltered_tags: unfiltered_tags.clone(),
                    on_unauthorized: on_unauthorized.clone(),
                },
                tag: tag.clone(),
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

            view! {
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

    view! {
        ul {
            (categories)
            Keyed(tags)
        }
    }
}
