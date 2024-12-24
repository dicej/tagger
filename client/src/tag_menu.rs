//! This module provides the `TagMenu` component, which provides a hierarchical, tree-style UI for filtering media
//! items by tag.
//!
//! Note that this module contains utility code for working with types defined in the `tagger_shared` crate --
//! refer to the documentation for that crate to get the complete picture.  Specifically, see
//! `tagger_shared::tag_expression::TagTree`, which we use heavily in this module.

use {
    crate::client::Client,
    std::{cmp::Ordering, collections::HashMap, ops::Deref, rc::Rc, sync::Arc},
    sycamore::prelude::{
        self as syc, component, view, Keyed, KeyedProps, ReadSignal, Signal, View,
    },
    tagger_shared::{
        tag_expression::{Tag, TagState, TagTree},
        TagsResponse,
    },
};

/// Lisp-style singly-linked list
#[derive(Clone, Debug)]
pub enum List<T> {
    Nil,
    Cons(Rc<(T, List<T>)>),
}

/// Given a `filter_chain`, which denotes a path of ANDed-together tags in a filter tree, identify any categories
/// of tags which could be used to further filter a set of media items.
///
/// For example, if the current filter is "year:2017 and state:hawaii", and some of the matching items also have
/// tags like "city:honolulu" and "city:kailua-kona", then "city" would be one of the categories we'd return here,
/// but "year" and "state" would not be since we're already filtering by those categories.
fn find_categories(
    filter_chain: &List<Tag>,
    categories: &HashMap<Arc<str>, TagsResponse>,
    result: &mut Vec<Arc<str>>,
) {
    for (category, tags) in categories {
        if find_category(filter_chain, category.deref()).is_some() {
            find_categories(filter_chain, &tags.categories, result);
        } else {
            result.push(category.clone());
        }
    }
}

/// If `state` is a `TagState::Included` return a shared reference to the subtree; otherwise, return `None`.
fn subtree(state: &TagState) -> Option<&TagTree> {
    if let TagState::Included(subtree) = state {
        Some(subtree)
    } else {
        None
    }
}

/// If `state` is a `TagState::Included` return a unique reference to the subtree; otherwise, return `None`.
fn subtree_mut(state: &mut TagState) -> Option<&mut TagTree> {
    if let TagState::Included(subtree) = state {
        Some(subtree)
    } else {
        None
    }
}

/// Create a new `TagTree` which represents the path taken through `filter` using tags from `filter_chain`.
///
/// In other words, the returned tree will match `filter` except with extraneous branches (those not specified by
/// `filter_chain`) removed.
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

/// Identify which tags (if any) in `tags` are appropriate to list at the next level of the tree, i.e. which tags
/// could be used to further filter a set of media items.
///
/// We use `category` to indicate whether we're building a submenu for a specific category or for uncategorized
/// tags.
///
/// See also [find_categories].
fn tags_for_category<'a>(
    category: &Option<Arc<str>>,
    tags: &'a TagsResponse,
) -> Option<&'a TagsResponse> {
    if let Some(inner) = category {
        if let Some(tags) = tags.categories.get(inner) {
            Some(tags)
        } else {
            for tags in tags.categories.values() {
                if let Some(tags) = tags_for_category(category, tags) {
                    return Some(tags);
                }
            }

            None
        }
    } else {
        Some(tags)
    }
}

/// Return a reference to the first `Tag` found in `filter_chain` which matches the specified `tag` name and
/// `category`, if present.
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

/// Return a reference to the first `Tag` found in `filter_chain` which matches the specified `category`, if
/// present.
fn find_category<'a>(mut filter_chain: &'a List<Tag>, category: &str) -> Option<&'a Tag> {
    loop {
        match filter_chain {
            List::Nil => break None,
            List::Cons(cons) => {
                if cons.0.category.as_deref() == Some(category) {
                    break Some(&cons.0);
                } else {
                    filter_chain = &cons.1;
                }
            }
        }
    }
}

/// Return a shared reference to the subtree of `filter` reachable via the list of tags in `filter_chain`, if any.
fn resolve<'a>(filter_chain: &List<Tag>, filter: &'a TagTree) -> Option<&'a TagTree> {
    match filter_chain {
        List::Nil => Some(filter),
        List::Cons(cons) => {
            resolve(&cons.1, filter).and_then(|tree| tree.0.get(&cons.0).and_then(subtree))
        }
    }
}

/// Return a unique reference to the subtree of `filter` reachable via the list of tags in `filter_chain`, if any.
fn resolve_mut<'a>(filter_chain: &List<Tag>, filter: &'a mut TagTree) -> Option<&'a mut TagTree> {
    match filter_chain {
        List::Nil => Some(filter),
        List::Cons(cons) => resolve_mut(&cons.1, filter)
            .and_then(|tree| tree.0.get_mut(&cons.0).and_then(subtree_mut)),
    }
}

/// Represents the state of a tag menu item
#[derive(Copy, Clone, PartialEq, Eq)]
enum FilterState {
    /// This tag is included in the filter (i.e. only media items having this tag should be shown)
    Include,

    /// This tag is excluded in the filter (i.e. only media items *not* having this tag should be shown)
    Exclude,

    /// This tag is not present in the filter (i.e. media items may be shown regardless of whether they have this
    /// tag)
    None,
}

/// Attempt to find the specified `tag` in the subtree of `filter` reachable via `filter_chain` and determine
/// whether it is included, excluded, or not present.
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

/// Properties common to [TagSubMenuProps] and [TagMenuProps]
pub struct TagMenuCommonProps {
    /// Client for making HTTP requests to the Tagger server
    pub client: Client,

    /// The current filter specified by the user, represented as a `TagTree`
    pub filter: Signal<TagTree>,

    /// The path which identifies the subtree of `filter` which this (sub)menu represents
    pub filter_chain: List<Tag>,
}

/// Properties for populating and rendering the `TagSubMenu` component
struct TagSubMenuProps {
    /// See [TagMenuCommonProps]
    common: TagMenuCommonProps,

    /// The tag under which this submenu will appear
    tag: Tag,
}

/// Define the `TagSubMenu` component, which represents a set of tags and categories which may be used to further
/// refine a filter when a specific tag has been included.
///
/// For example, if the user has specified the filter "year:2017 and state:hawaii", and some of the matching items
/// also have tags like "city:honolulu", "city:kailua-kona", and "sunset", then "city" would be one of the
/// categories listed in the submenu, and "sunset" would be one of the uncategorized tags listed there as well.
#[component(TagSubMenu<G>)]
#[allow(clippy::redundant_closure)]
fn tag_sub_menu(props: TagSubMenuProps) -> View<G> {
    let TagSubMenuProps {
        common:
            TagMenuCommonProps {
                client,
                filter,
                filter_chain,
            },
        tag,
    } = props;

    let tag_menu = {
        let tag = tag.clone();
        let filter_chain = filter_chain.clone();
        let filter = filter.clone();

        move || {
            let filter_chain = List::Cons(Rc::new((tag.clone(), filter_chain.clone())));

            TagMenuProps {
                common: TagMenuCommonProps {
                    client: client.clone(),
                    filter: filter.clone(),
                    filter_chain: filter_chain.clone(),
                },
                tags: client.watch_tags(
                    Signal::new(to_tree(&filter_chain, filter.get().deref())).into_handle(),
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

/// Compare two strings, numerically when applicable.
///
/// If both strings can be parsed as `u64`s, then compare them numerically.  Otherwise, compare them
/// lexicographically.
fn compare_numeric(a: &str, b: &str) -> Ordering {
    match (a.parse::<u64>(), b.parse::<u64>()) {
        (Ok(a), Ok(b)) => a.cmp(&b),
        (Ok(_), Err(_)) => Ordering::Greater,
        (Err(_), Ok(_)) => Ordering::Less,
        (Err(_), Err(_)) => a.cmp(b),
    }
}

/// Search `tags` for the specified `tag` and return the image count if found; zero otherwise.
fn count_for_tag(tags: &TagsResponse, tag: &Tag) -> u32 {
    *tags_for_category(&tag.category, tags)
        .and_then(|tags| tags.tags.get(&tag.value))
        .unwrap_or(&0)
}

/// Properties for populating and rendering the `TagMenu` component
pub struct TagMenuProps {
    /// See [TagMenuCommonProps]
    pub common: TagMenuCommonProps,

    /// The most recent set of tags and associated image counts received from the server
    pub tags: ReadSignal<TagsResponse>,

    /// The category for which we are displaying this menu, if any
    pub category: Option<Arc<str>>,
}

/// Define the `TagMenu` component, which provides a hierarchical, tree-style UI for filtering media items by tag.
#[component(TagMenu<G>)]
pub fn tag_menu(props: TagMenuProps) -> View<G> {
    let TagMenuProps {
        common:
            TagMenuCommonProps {
                client,
                filter,
                filter_chain,
            },
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

                    let mut vec = Vec::new();

                    find_categories(&filter_chain, &tags.categories, &mut vec);

                    vec.sort();

                    vec
                }
            }),

            template: {
                let filter_chain = filter_chain.clone();
                let tags = tags.clone();
                let client = client.clone();
                let filter = filter.clone();

                move |category| {
                    let tag_menu = TagMenuProps {
                        common: TagMenuCommonProps {
                            client: client.clone(),
                            filter: filter.clone(),
                            filter_chain: filter_chain.clone(),
                        },
                        tags: tags.clone(),
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

    let tags = KeyedProps {
        iterable: syc::create_selector({
            let tags = tags.clone();
            let category = category.clone();
            let filter_chain = filter_chain.clone();
            let empty = TagsResponse::default();

            move || {
                let tags = tags.get();

                let mut vec = tags_for_category(&category, &tags)
                    .unwrap_or(&empty)
                    .tags
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
                    filter: filter.clone(),
                    filter_chain: filter_chain.clone(),
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
                let tag = tag.clone();

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

            let tags = tags.clone();

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

                    " " (tag_value) " (" (count_for_tag(tags.get().deref(), &tag)) ")"

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
