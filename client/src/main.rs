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
use stdweb::web::event::ReadyStateChangeEvent;
use stdweb::web::{document, IEventTarget, XhrReadyState, XmlHttpRequest};

#[derive(Clone, Deserialize, PartialEq)]
struct Image {
    datetime: String,
    tags: OrdSet<String>,
}

type State = OrdMap<String, Image>;

fn node<D: dom::Document + 'static>() -> Box<Node<State, State, D>> {
    html!({ apply_all(|s| s, html!(<div>{|(k,_)| k}</div>)) })
}

fn render(state: &str) -> Result<(), Error> {
    Dispatcher::from(
        &node(),
        &Document::from(document()),
        &document()
            .body()
            .ok_or_else(|| format_err!("document has no body"))?
            .into(),
        &serde_json::from_str::<State>(state)?,
    );

    Ok(())
}

fn run() -> Result<(), Error> {
    let request = XmlHttpRequest::new();

    request.add_event_listener({
        let request = request.clone();
        move |_: ReadyStateChangeEvent| {
            if let (XhrReadyState::Done, Ok(Some(response))) =
                (request.ready_state(), request.response_text())
            {
                console!(log, format!("response is {}", response));
                drop(log_error(render(&response)));
            }
        }
    });

    request.open("GET", "http://localhost:2237/state")?;

    request.send()?;

    Ok(())
}

fn log_error(result: Result<(), Error>) -> Result<(), Error> {
    if let &Err(ref e) = &result {
        console!(error, format!("exit on error: {:?}", e));
    }
    result
}

fn main() {
    stdweb::initialize();

    if log_error(run()).is_ok() {
        stdweb::event_loop();
    }
}
