//! This module provides the `Pagination` component, which allows the user to browse a sequence of media thumbnails
//! which spans more than one page.

use {
    crate::images::ImagesState,
    std::convert::TryFrom,
    sycamore::prelude::{component, view, ReadSignal, Signal, View},
    tagger_shared::{ImageKey, ImagesResponse},
};

/// Go to the first page of the sequence
fn page_start(props: &PaginationProps) {
    props.start.set(None);
}

/// Go to the previous page of the sequence, if there is one
pub fn page_back(props: &PaginationProps) {
    props
        .start
        .set(props.images.get().response.later_start.clone());
}

/// Go to the next page of the sequence, if there is one
pub fn page_forward(props: &PaginationProps) {
    let images = props.images.get();
    let ImagesResponse { start, total, .. } = *images.response;
    let count = u32::try_from(images.response.images.len()).unwrap();

    if start + count < total {
        props
            .start
            .set(images.response.images.last().map(|data| data.key()));
    }
}

/// Go to the last page of the sequence
fn page_end(props: &PaginationProps) {
    if let Some(earliest_start) = &props.images.get().response.earliest_start {
        props.start.set(Some(earliest_start.clone()));
    }
}

/// Properties used to populate and render the `Pagination` component
#[derive(Clone)]
pub struct PaginationProps {
    /// Media items to be displayed on the current page, plus metadata about how to query the server for other
    /// pages
    pub images: ReadSignal<ImagesState>,

    /// The timestamp (and possibly hash) indicating which page we should be on
    ///
    /// More precisely, this indicates the most recent media item we should display.
    pub start: Signal<Option<ImageKey>>,

    /// Indicates whether to show a message to the user when the current sequence of thumbnails is empty
    pub show_message_on_zero: bool,
}

/// Define the `Pagination` component, which allows the user to browse a set of media thumbnails which spans more
/// than one page.
#[component(Pagination<G>)]
pub fn pagination(props: PaginationProps) -> View<G> {
    view! {
        span(class="pagination") {
            ({
                let images = props.images.get();
                let ImagesResponse { start, total, .. } = *images.response;

                if total == 0 {
                    if props.show_message_on_zero {
                        view! {
                            em {
                                "No images match current filter"
                            }
                        }
                    } else {
                        view! { }
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

                    view! {
                        i(class="fa fa-angle-double-left big start",
                          on:click=move |_| page_start(&props1),
                          style=left_style) " "

                        i(class="fa fa-angle-left big back",
                          on:click=move |_| page_back(&props2),
                          style=left_style)

                        (format!(" {}-{} of {total} ",
                                 start + 1,
                                 start + count))

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
