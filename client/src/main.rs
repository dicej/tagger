#![deny(warnings)]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate stdweb;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate im;
#[macro_use]
extern crate render;

use failure::Error;
use im::{OrdMap, OrdSet};
use render::dispatch::{apply_all, Dispatcher, Node};
use render::dom;
use render::dom::client::Document;
use std::sync::Arc;
use stdweb::web::event::ReadyStateChangeEvent;
use stdweb::web::{document, IEventTarget, XhrReadyState, XmlHttpRequest};

static SERVER: &str = "http://localhost:2238";

#[derive(Clone, Deserialize, PartialEq)]
struct Image {
    datetime: String,
    tags: OrdSet<String>,
}

struct State {
    all: OrdMap<String, Image>,
    visible: OrdMap<String, Selectable>,
}

impl State {
    fn from(all: OrdMap<String, Image>) -> Self {
        State {
            all,
            visible: all,
            selected: OrdSet::new(),
        }
    }
}

fn tag_menu<D: dom::Document + 'static>(menu_type: MenuType) -> Box<Node<State, State, D>> {
    html!(
        <table>
            <tr onclick=|_, s: State| s.toggle_all(),>
                <td>{|s| if s.get_all() { "✔" } else { " " }}</td>
                <td>{"All"}</td>
            </tr>
            <tr onclick=|_, s: State| s.toggle_untagged(),>
                <td>{|s| if s.get_untagged() { "✔" } else { " " }}</td>
                <td>{"Untagged"}</td>
            </tr>
            {apply_all(|s| s.get_tags(menu_type),
                       html!(
                           <tr onclick=|((tag, ), _), s: State| s.toggle_tag(menu_type, tag),>
                               <td>{|(tag, )| if s.get_tag(menu_type, tag) { "✔" } else { " " }}</td>
                               <td>{|(tag, )| tag}</td>
                           </tr>
                       ))}
        </table>
    )
}

fn node<D: dom::Document + 'static>() -> Box<Node<State, State, D>> {
    html!(
        <div>
            <a href="#", onclick=|_, s: State| s.toggle_filter(),>{"Filter"}</a>
            {maybe(|s| s.has_selected(),
                   html!(
                       {" | "}
                       <a href="#", onclick=|_, s: State| s.toggle_apply(),>{"Apply"}</a>
                   ))}
        </div>
        {maybe(|s| s.get_filter(), tag_menu(MenuType::Filter))}
        {maybe(|s| s.get_apply(), tag_menu(MenuType::Apply))}
        <div>
            {apply_all(|s| s.visible,
                       html!(
                           <div class="image",>
                               <img src=|(hash, _)| format!("{}/images/small/{}", SERVER, hash),
                                    class=|(_, sel): (_, Selectable)| sel.class(),
                                    onclick=|((hash, _), _), s: State| s.select(hash)/>
                               <br/>
                               {|(_, sel): (_, Selectable)| join(sel.image.tags)}
                           </div>
                       ))}
        </div>
   )
}

fn render(state: &str) -> Result<(), Error> {
    Dispatcher::from(
        &node(),
        &Document::from(document()),
        &document()
            .body()
            .ok_or_else(|| format_err!("document has no body"))?
            .into(),
        &State::from(serde_json::from_str(state)?),
    );

    Ok(())
}

fn send_request() -> Result<(), Error> {
    let request = XmlHttpRequest::new();

    request.add_event_listener({
        let request = request.clone();
        move |_: ReadyStateChangeEvent| {
            if let (XhrReadyState::Done, Ok(Some(response))) =
                (request.ready_state(), request.response_text())
            {
                console!(log, format!("response is {}", response));
                log_error(render(&response));
            }
        }
    });

    request.open("GET", &format!("{}/state", SERVER))?;

    request.send()?;

    Ok(())
}

fn log_error(result: Result<(), Error>) -> bool {
    if let &Err(ref e) = &result {
        console!(error, format!("exit on error: {:?}", e));
        true
    } else {
        false
    }
}

fn main() {
    stdweb::initialize();

    if !log_error(send_request()) {
        stdweb::event_loop();
    }
}
