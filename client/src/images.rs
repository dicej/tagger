//! This module provides the `Images` component, which displays a sequence of media item thumbnails.

use {
    std::{collections::HashMap, rc::Rc, sync::Arc},
    sycamore::prelude::{
        self as syc, component, view, Indexed, IndexedProps, ReadSignal, Signal, View,
    },
    tagger_shared::{ImagesResponse, Medium},
    wasm_bindgen::JsCast,
    web_sys::{Event, HtmlVideoElement, MouseEvent},
};

/// Pairs a /images response from the Tagger server with some local state for tracking which items are currently
/// selected
#[derive(Default)]
pub struct ImagesState {
    /// Response received from the Tagger server for our /images request
    pub response: Rc<ImagesResponse>,

    /// Map of item hashes to local state for each item
    pub states: HashMap<Arc<str>, ImageState>,
}

/// Local (i.e. client-side) state for a specific media item
#[derive(Clone)]
pub struct ImageState {
    /// Reactive variable which tracks whether this item is selected or not
    pub selected: Signal<bool>,
}

impl Drop for ImageState {
    /// Asynchronously set `self.selected` to `false` to ensure derived state is updated.
    ///
    /// This is important because other parts of the UI rely on knowing whether any items are selected or not.  If
    /// we let this instance be dropped while `selected` is `true` without setting it to `false` explicitly, the UI
    /// may end up in an inconsistent state that indicates some items are selected even though none really are.
    fn drop(&mut self) {
        if *self.selected.get_untracked() {
            let selected = self.selected.clone();

            // We use `wasm_bindgen_futures::spawn_local` here to ensure the `Signal::set` call happens outside of
            // any Sycamore context.  This guarantees that we won't try to call it e.g. from within Sycamore
            // clean-up code such that the thread-local context is in an indeterminate state.
            wasm_bindgen_futures::spawn_local(async move {
                selected.set(false);
            });
        }
    }
}

/// Call `HtmlVideoElement::play` on the target of the specified `event`, if possible
fn play_video(event: Event) {
    if let Some(video) = event.target() {
        if let Ok(video) = video.dyn_into::<HtmlVideoElement>() {
            let _ = video.play();
        }
    }
}

/// Pause and reset the `HtmlVideoElement` target of the specified `event`, if possible
fn reset_video(event: Event) {
    if let Some(video) = event.target() {
        if let Ok(video) = video.dyn_into::<HtmlVideoElement>() {
            let _ = video.pause();
            video.set_current_time(0.0);

            // We (re)load the video here to force the poster image to be displayed (again)
            //
            // See https://stackoverflow.com/questions/14245644/html5-video-end-of-a-video-poster for details.
            let _ = video.load();
        }
    }
}

/// Properties used to populate and render the `Images` component
pub struct ImagesProps {
    /// Base URL for requesting images from the server
    pub root: Rc<str>,

    /// Indicates whether the UI is in "selecting" mode, i.e. if clicking on a thumbnail will cause its selection
    /// state to be toggled on or off
    pub selecting: ReadSignal<bool>,

    /// The current item sequence, including which items, if any, are selected
    pub images: ReadSignal<ImagesState>,

    /// Index of the item currently being displayed in the lightbox overlay, if any
    pub overlay_image: Signal<Option<usize>>,
}

/// Define the `Images` component, which displays a sequence of media item thumbnails.
#[component(Images<G>)]
pub fn images(props: ImagesProps) -> View<G> {
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

                // Define a lambda to handle a mouse click event.
                //
                // While in "selecting" mode, we treat mouse clicks as selection toggle events, optionally
                // including a shift key modifier to (de)select an interval.
                //
                // While not in "selecting" mode (or when a control key modifier is used), we simply set
                // `overlay_image` to the index of the clicked item, which tells the lightbox overlay to display
                // the high-resolution version of that item.
                let on_click = {
                    let images = images.clone();
                    let state = state.clone();
                    let selecting = selecting.clone();
                    let overlay_image = overlay_image.clone();

                    move |event: Event| {
                        if let Ok(event) = event.dyn_into::<MouseEvent>() {
                            if *selecting.get() {
                                if event.get_modifier_state("Control") {
                                    overlay_image.set(Some(index));
                                    return;
                                }

                                if !*state.selected.get() && event.get_modifier_state("Shift") {
                                    if let (Some(first_selected), Some(last_selected)) = (
                                        images.response.images.iter().position(|data| {
                                            *images.states.get(&data.hash).unwrap().selected.get()
                                        }),
                                        images.response.images.iter().rposition(|data| {
                                            *images.states.get(&data.hash).unwrap().selected.get()
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

                                let selected = &state.selected;
                                selected.set(!*selected.get());
                            } else {
                                overlay_image.set(Some(index));
                            }
                        }
                    }
                };

                let selected = state.selected.clone();

                match data.medium {
                    // Videos and "motion photo" images are rendered as HTML5 video elements which display their
                    // poster image by default and play a preview clip on mouse over.
                    Medium::ImageWithVideo | Medium::Video => {
                        let video_url = format!("{root}/image/small-video/{hash}");

                        view! {
                            video(src=video_url,
                                  autoplay=false,
                                  poster=url,
                                  muted=true,
                                  playsinline=true,
                                  class=if *selected.get() { "thumbnail selected" } else { "thumbnail" },
                                  on:mouseenter=play_video,
                                  on:mouseleave=reset_video,
                                  on:click=on_click)
                        }
                    }

                    Medium::Image => view! {
                        img(src=url,
                            class=if *selected.get() { "thumbnail selected" } else { "thumbnail" },
                            on:click=on_click)
                    },
                }
            } else {
                view! {}
            }
        },
    };

    view! {
        div {
            Indexed(images)
        }
    }
}
