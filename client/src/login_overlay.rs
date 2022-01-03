use {
    anyhow::Error,
    futures::TryFutureExt,
    reqwest::{Client, StatusCode},
    std::{ops::Deref, rc::Rc},
    sycamore::prelude::{component, view, Signal, View},
    tagger_shared::{GrantType, TokenRequest, TokenSuccess},
    wasm_bindgen::JsCast,
    web_sys::{Event, KeyboardEvent},
};

pub struct LoginOverlayProps {
    pub root: Rc<str>,
    pub client: Client,
    pub token: Signal<Option<String>>,
    pub show_log_in: Signal<bool>,
    pub log_in_error: Signal<Option<String>>,
    pub user_name: Signal<String>,
    pub password: Signal<String>,
}

#[component(LoginOverlay<G>)]
pub fn login_overlay(props: LoginOverlayProps) -> View<G> {
    let LoginOverlayProps {
        root,
        client,
        token,
        show_log_in,
        log_in_error,
        user_name,
        password,
    } = props;

    let on_key = {
        let user_name = user_name.clone();
        let password = password.clone();
        let show_log_in = show_log_in.clone();
        let log_in_error = log_in_error.clone();

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

    let close_log_in = {
        let show_log_in = show_log_in.clone();

        move |_| show_log_in.set(false)
    };

    let on_key2 = on_key.clone();

    let log_in_error2 = log_in_error.clone();

    view! {
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

                    input(bind:value=user_name,
                          on:keyup=on_key,
                          id="user_name") {}
                }

                p {
                    label(for="password") { "password: " }

                    input(type="password",
                          on:keyup=on_key2,
                          bind:value=password,
                          id="password") {}
                }
            }
        }
    }
}
