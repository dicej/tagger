//#![deny(warnings)]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate stdweb;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate im;
#[macro_use]
extern crate render;

use failure::Error;
use im::{OrdMap, OrdSet};
use render::dispatch::{apply, apply_all, Dispatcher, EventPair, Node, SubState};
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

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy)]
enum MenuType {
    Filter,
    Apply,
}

impl MenuType {
    fn to_string(&self) -> &'static str {
        match self {
            &MenuType::Filter => "Filter",
            &MenuType::Apply => "Apply",
        }
    }
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone)]
enum MenuKey {
    All,
    Untagged,
    Tag(Arc<String>),
}

impl MenuKey {
    fn to_string(&self) -> String {
        match self {
            &MenuKey::All => "All".into(),
            &MenuKey::Untagged => "Untagged".into(),
            &MenuKey::Tag(ref tag) => (**tag).clone(),
        }
    }
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy)]
enum MenuValue {
    Checked,
    Unchecked,
    Neither,
}

impl MenuValue {
    fn to_string(&self) -> &'static str {
        match self {
            &MenuValue::Checked => "✔",
            &MenuValue::Unchecked => " ",
            &MenuValue::Neither => "-",
        }
    }
}

impl MenuValue {
    fn toggle(self) -> Self {
        match self {
            MenuValue::Unchecked => MenuValue::Checked,
            _ => MenuValue::Unchecked,
        }
    }
}

#[derive(Clone, PartialEq)]
struct State {
    images: OrdMap<String, Image>,
    images_visible: OrdSet<String>,
    images_selected: OrdSet<String>,
    links_visible: OrdSet<MenuType>,
    menus: OrdMap<MenuType, OrdMap<MenuKey, MenuValue>>,
    menus_visible: OrdSet<MenuType>,
}

impl State {
    fn from(images: OrdMap<String, Image>) -> Self {
        State {
            images: images.clone(),
            images_visible: images.keys().collect(),
            images_selected: OrdSet::new(),
            links_visible: ordset![MenuType::Filter],
            menus: OrdMap::new(),
            menus_visible: OrdSet::new(),
        }
    }

    fn toggle_menu(self, menu: MenuType) -> Self {
        let mut s = self;
        if s.menus_visible.contains(&menu) {
            s.menus_visible.remove_mut(&menu);
        } else {
            s.menus_visible.insert_mut(menu);
        }
        s
    }

    fn toggle_menu_item(self, _menu: MenuType, _key: MenuKey, _value: MenuValue) -> Self {
        // todo
        self
    }

    fn toggle_selected(self, hash: Arc<String>) -> Self {
        let mut s = self;
        if s.images_selected.contains(&hash as &str) {
            s.images_selected.remove_mut(&hash as &str)
        } else {
            s.images_selected.insert_mut(hash.clone())
        }
        console!(
            error,
            format!("toggle_selected {}: {:?}!", hash, s.images_selected)
        );
        s
    }
}

fn join<T: IntoIterator<Item = Arc<String>>>(values: T, sep: &str) -> String {
    values
        .into_iter()
        .map(|s| String::from(&s as &str))
        .collect::<Vec<_>>()
        .join(sep)
}

fn links<D: dom::Document + 'static>() -> Box<Node<State, State, D>> {
    html!(
        <div>
            {apply_all(|s: State| s.links_visible,
                       html!(
                           <a href="#", onclick=|e: EventPair<SubState<Arc<MenuType>, _, _>, _>, s: State| {
                               s.toggle_menu(*e.state.key)
                           },>
                               {|s: SubState<Arc<MenuType>, _, _>| s.key.to_string()}
                           </a>
                       ))}
        </div>
    )
}

fn menus<D: dom::Document + 'static>() -> Box<Node<State, State, D>> {
    html!(
         <div>
             {apply_all(|s| s.menus_visible,
                        html!(
                            <table>
                                {apply_all(|s: SubState<_, _, State>| (*s.parent.menus.get(&s.key).unwrap()).clone(),
                                           html!(
                                               <tr onclick=|e: EventPair<SubState<Arc<MenuKey>, Arc<MenuValue>, SubState<Arc<MenuType>, _, _>>, _>, s: State| {
                                                   s.toggle_menu_item(*e.state.parent.key, (*e.state.key).clone(), *e.state.value)
                                               },>
                                                   <td>{|s: SubState<_, Arc<MenuValue>, _>| s.value.to_string()}</td>
                                                   <td>{|s: SubState<Arc<MenuKey>, _, _>| s.key.to_string()}</td>
                                               </tr>
                                           ))}
                            </table>
                        ))}
         </div>
    )
}

fn images<D: dom::Document + 'static>() -> Box<Node<State, State, D>> {
    html!(
         <div>
             {apply_all(|s| s.images_visible,
                        html!(
                            <div class="image",>
                                <img src=|s: SubState<Arc<String>, _, _>| format!("{}/images/small/{}", SERVER, s.key),
                                     class=|s: SubState<_, _, State>| if s.parent.images_selected.contains(&s.key as &str) {
                                         "selected"
                                     } else {
                                         "unselected"
                                     },
                                     onclick=|e: EventPair<SubState<Arc<String>, _, _>, _>, s: State| s.toggle_selected(e.state.key),/>
                                <br/>
                                {|s: SubState<_, _, State>| join(&s.parent.images.get(&s.key as &str).unwrap().tags, ", ")}
                            </div>
                        ))}
         </div>
    )
}

fn body<D: dom::Document + 'static>() -> Box<Node<State, State, D>> {
    html!(
        <div>
            {apply(|s| s, links())}
            {apply(|s| s, menus())}
            {apply(|s| s, images())}
        </div>
    )
}

fn render(state: &str) -> Result<(), Error> {
    Dispatcher::from(
        &body(),
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
