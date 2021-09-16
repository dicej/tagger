use {
    crate::images::ImagesState,
    std::{convert::TryFrom, rc::Rc},
    sycamore::prelude::{
        self as syc, component, template, Indexed, IndexedProps, Signal, StateHandle, Template,
    },
    tagger_shared::{ImagesResponse, Medium},
    wasm_bindgen::JsCast,
    web_sys::HtmlVideoElement,
};

pub enum Direction {
    Left,
    Right,
}

#[derive(Clone, Copy)]
pub enum Select {
    None,
    First,
    Last,
}

pub struct ImageOverlayProps {
    pub root: Rc<str>,
    pub overlay_image: Signal<Option<usize>>,
    pub images: StateHandle<ImagesState>,
    pub next_overlay_image: Rc<dyn Fn(Direction)>,
}

#[component(ImageOverlay<G>)]
pub fn image_overlay(props: ImageOverlayProps) -> Template<G> {
    let ImageOverlayProps {
        root,
        overlay_image,
        images,
        next_overlay_image,
    } = props;

    let overlay_image_visible = syc::create_selector({
        let overlay_image = overlay_image.clone();

        move || overlay_image.get().is_some()
    });

    let close_overlay = {
        let overlay_image = overlay_image.clone();

        move |_| overlay_image.set(None)
    };

    let playing = Signal::new(false);

    let toggle_playing = {
        let playing = playing.clone();

        move |_| playing.set(!*playing.get())
    };

    syc::create_effect({
        let overlay_image = overlay_image.clone();
        let playing = playing.clone();

        move || {
            let _ = overlay_image.get();

            playing.set(false)
        }
    });

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
                        let next_overlay_image = next_overlay_image.clone();

                        template! {
                            i(class="fa fa-angle-left big left",
                              on:click=move |_| next_overlay_image(Direction::Left))
                        }
                    } else {
                        template! {}
                    };

                    let right = if have_right {
                        let next_overlay_image = next_overlay_image.clone();

                        template! {
                            i(class="fa fa-angle-right big right",
                              on:click=move |_| next_overlay_image(Direction::Right))
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
                        let video_url = format!("{}/image/large-video/{}", root, image.hash);

                        template! {
                            video(src=video_url,
                                  id="video",
                                  poster=url,
                                  autoplay=true,
                                  controls=true)
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
    }
}
