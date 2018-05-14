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

#[derive(Clone, Deserialize, PartialEq)]
struct Image {
    datetime: String,
    tags: OrdSet<String>,
}

type State = OrdMap<String, Image>;

fn node<D: dom::Document + 'static>() -> Box<Node<State, State, D>> {
    html!(
      <table>{
        apply_all(|s| s,
          html!(
            <tr>
              <td>{|(hash, _)| hash}</td>
              <td>{|(_, image): (_, Arc<Image>)| image.datetime.clone()}</td>
              <td>{|(_, image): (_, Arc<Image>)| image.tags.iter().map(|s| String::from(&s as &str)).collect::<Vec<_>>().join(", ")}</td>
            </tr>
          )
        )
      }</table>
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
        &serde_json::from_str::<State>(state)?,
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

    request.open("GET", "http://localhost:2237/state")?;

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
