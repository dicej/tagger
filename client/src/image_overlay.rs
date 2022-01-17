//! This module provides the `ImageOverlay` component, a lightbox-style widget for browsing a sequence of media
//! items, one at a time, at high resolution.

use {
    crate::images::ImagesState,
    std::{convert::TryFrom, rc::Rc},
    sycamore::prelude::{
        self as syc, component, view, Indexed, IndexedProps, ReadSignal, Signal, View,
    },
    tagger_shared::{ImagesResponse, Medium},
    wasm_bindgen::JsCast,
    web_sys::HtmlVideoElement,
};

/// Indicates which item to display next in a sequence
pub enum Direction {
    /// Display the previous item
    Left,

    /// Display the next item
    Right,
}

/// Indicates which item, if any, to display after paging forward or backward from one sequence to another
#[derive(Clone, Copy)]
pub enum Select {
    /// Don't display any item
    None,

    /// Display the first item in the sequence
    First,

    /// Display the last item in the sequence
    Last,
}

/// Properties used to populate and render the `ImageOverlay` component
pub struct ImageOverlayProps {
    /// Base URL for requesting media content from the server
    pub root: Rc<str>,

    /// Index of the currently-displayed image, if any, in the sequence
    pub overlay_image: Signal<Option<usize>>,

    /// Current sequence of items we're browsing
    pub images: ReadSignal<ImagesState>,

    /// Callback to display the next item when browsing forward or backward
    pub next_overlay_image: Rc<dyn Fn(Direction)>,
}

/// Define the `ImageOverlay` component, a lightbox-style widget for browsing a sequence of media items, one at a
/// time, at high resolution.
#[component(ImageOverlay<G>)]
pub fn image_overlay(props: ImageOverlayProps) -> View<G> {
    let ImageOverlayProps {
        root,
        overlay_image,
        images,
        next_overlay_image,
    } = props;

    // This component should only be visible when there is an item to display.
    let overlay_image_visible = syc::create_selector({
        let overlay_image = overlay_image.clone();

        move || overlay_image.get().is_some()
    });

    // Define a lambda to hide the component by setting the display item to `None`.
    let close_overlay = {
        let overlay_image = overlay_image.clone();

        move |_| overlay_image.set(None)
    };

    // When displaying a "motion photo" image (i.e. an image with an embedded video clip), we can toggle between
    // displaying the image and the video using this reactive variable.
    let playing = Signal::new(false);

    // Define a lambda to flip `playing` to the opposite value.
    let toggle_playing = {
        let playing = playing.clone();

        move |_| playing.set(!*playing.get())
    };

    // Whenever we display a new item, we reset `playing` to false.
    syc::create_effect({
        let overlay_image = overlay_image.clone();
        let playing = playing.clone();

        move || {
            let _ = overlay_image.get();

            playing.set(false)
        }
    });

    view! {
        div(class="overlay",
            style=format!("height:{};", if *overlay_image_visible.get() { "100%" } else { "0" }))
        {
            i(class="fa fa-times big close", on:click=close_overlay)

            (if let Some(index) = *overlay_image.get() {
                let images = images.get();

                if let Some(image) = images.response.images.get(index) {
                    let url = format!("{root}/image/large/{}", image.hash);

                    let medium = image.medium;

                    let mut vec = image.tags.iter().cloned().collect::<Vec<_>>();

                    vec.sort();

                    let tags = IndexedProps {
                        iterable: Signal::new(vec).into_handle(),

                        template: |tag| {
                            view! {
                                span(class="tag") {
                                    (tag)
                                }
                            }
                        }
                    };

                    let playing = *playing.get();

                    let play_button = match medium {
                        Medium::ImageWithVideo => {
                            view! {
                                i(class=format!("big play fa {}", if playing { "fa-stop" } else { "fa-play" }),
                                  on:click=toggle_playing.clone())
                            }
                        }
                        Medium::Image | Medium::Video => view! {}
                    };

                    let count = u32::try_from(images.response.images.len()).unwrap();
                    let ImagesResponse { start, total, .. } = *images.response;

                    let have_left = index > 0 || start > 0;
                    let have_right = index + 1 < images.response.images.len() || start + count < total;

                    let left = if have_left {
                        let next_overlay_image = next_overlay_image.clone();

                        view! {
                            i(class="fa fa-angle-left big left",
                              on:click=move |_| next_overlay_image(Direction::Left))
                        }
                    } else {
                        view! {}
                    };

                    let right = if have_right {
                        let next_overlay_image = next_overlay_image.clone();

                        view! {
                            i(class="fa fa-angle-right big right",
                              on:click=move |_| next_overlay_image(Direction::Right))
                        }
                    } else {
                        view! {}
                    };

                    let original_url = format!("{root}/image/original/{}", image.hash);

                    let show_video = match medium {
                        Medium::ImageWithVideo => playing,
                        Medium::Video => true,
                        Medium::Image => false
                    };

                    // Removing the old video from the DOM is not enough to make it stop loading and/or playing, so
                    // we need to clear it out explicitly.  See https://stackoverflow.com/a/28060352/5327218.
                    if let Some(video) = web_sys::window()
                        .and_then(|w| w.document())
                        .and_then(|d| d.get_element_by_id("video"))
                        .and_then(|e| e.dyn_into::<HtmlVideoElement>().ok())
                    {
                        let _ = video.pause();
                        let _ = video.remove_attribute("src");
                        video.load();
                    }

                    let image = if show_video {
                        let video_url = format!("{root}/image/large-video/{}", image.hash);

                        view! {
                            video(src=video_url,
                                  id="video",
                                  poster=url,
                                  autoplay=true,
                                  controls=true)
                        }
                    } else {
                        view! {
                            img(src=url)
                        }
                    };

                    view! {
                        (left) (right) (play_button) (image) span(class="tags") {
                            Indexed(tags)
                        }

                        a(href=original_url, class="original", target="_blank") {
                            "original"
                        }
                    }
                } else {
                    view! {}
                }
            } else {
                view! {}
            })
        }
    }
}
