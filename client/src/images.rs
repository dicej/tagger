use {
    std::{collections::HashMap, rc::Rc, sync::Arc},
    sycamore::prelude::{
        self as syc, component, template, Indexed, IndexedProps, Signal, StateHandle, Template,
    },
    tagger_shared::{ImagesResponse, Medium},
    wasm_bindgen::JsCast,
    web_sys::{Event, HtmlVideoElement, MouseEvent},
};

#[derive(Default)]
pub struct ImagesState {
    pub response: Rc<ImagesResponse>,
    pub states: HashMap<Arc<str>, ImageState>,
}

#[derive(Clone)]
pub struct ImageState {
    pub selected: Signal<bool>,
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

pub struct ImagesProps {
    pub root: Rc<str>,
    pub selecting: StateHandle<bool>,
    pub images: StateHandle<ImagesState>,
    pub overlay_image: Signal<Option<usize>>,
}

#[component(Images<G>)]
pub fn images(props: ImagesProps) -> Template<G> {
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
                                  on:click=on_click)
                        }
                    }

                    Medium::Image => template! {
                        img(src=url,
                            class=if *selected.get() { "thumbnail selected" } else { "thumbnail" },
                            on:click=on_click)
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
