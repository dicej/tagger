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
extern crate render;
#[macro_use]
extern crate derive_deref;

mod collections;

use collections::{Map, Set};
use failure::Error;
use render::dispatch::{Dispatcher, Node};
use render::dom;
use render::dom::client::Document;
use stdweb::web::event::ReadyStateChangeEvent;
use stdweb::web::{document, IEventTarget, XhrReadyState, XmlHttpRequest};

#[derive(Clone, Deserialize)]
struct Image {
    datetime: String,
    tags: Set<String>,
}

#[derive(Clone, Deserialize)]
struct State {
    images: Map<String, Image>,
}

fn node<D: dom::Document>() -> Box<Node<State, State, D>> {
    unimplemented!()
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
