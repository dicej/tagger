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

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy)]
enum SelectionState {
    Selected,
    Unselected,
}

impl SelectionState {
    fn class(&self) -> &'static str {
        match self {
            &SelectionState::Selected => "selected",
            &SelectionState::Unselected => "unselected",
        }
    }
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy)]
enum Size {
    Small,
    Large,
}

impl Size {
    fn to_string(&self) -> &'static str {
        match self {
            &Size::Small => "small",
            &Size::Large => "large",
        }
    }
}

#[derive(Clone, PartialEq)]
struct Selection {
    state: SelectionState,
    size: Size,
    tags: OrdSet<String>,
}

#[derive(Clone, PartialEq)]
struct State {
    images: OrdMap<String, Image>,
    selections: OrdMap<(String, String), Selection>,
    links: OrdSet<MenuType>,
    menus: OrdMap<MenuType, OrdMap<MenuKey, MenuValue>>,
    menus_visible: OrdSet<MenuType>,
}

impl State {
    fn from(images: OrdMap<String, Image>) -> Self {
        State {
            images: images.clone(),
            selections: images
                .iter()
                .map(|(k, v)| {
                    (
                        (v.datetime.clone(), (*k).clone()),
                        Selection {
                            state: SelectionState::Unselected,
                            size: Size::Small,
                            tags: v.tags.clone(),
                        },
                    )
                })
                .collect(),
            links: OrdSet::new(),
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

    fn toggle_selected(self, key: Arc<(String, String)>) -> Self {
        let mut s = self;
        let mut selection = s.selections.get(&key).unwrap();
        if selection.state == SelectionState::Selected {
            Arc::make_mut(&mut selection).state = SelectionState::Unselected;
        } else {
            Arc::make_mut(&mut selection).state = SelectionState::Selected;
        }
        s.selections.insert_mut(key.clone(), selection);
        s
    }

    fn toggle_size(self, key: Arc<(String, String)>) -> Self {
        let mut s = self;
        let mut selection = s.selections.get(&key).unwrap();
        if selection.size == Size::Small {
            Arc::make_mut(&mut selection).size = Size::Large;
        } else {
            Arc::make_mut(&mut selection).size = Size::Small;
        }
        s.selections.insert_mut(key.clone(), selection);
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
            {apply_all(|s: State| s.links,
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
                                               <tr onclick=|e: EventPair<SubState<Arc<MenuKey>,
                                                                                  Arc<MenuValue>,
                                                                                  SubState<Arc<MenuType>, _, _>>,
                                                                         _>, s: State| {
                                                   s.toggle_menu_item(*e.state.parent.key,
                                                                      (*e.state.key).clone(),
                                                                      *e.state.value)
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
             {apply_all(|s: State| s.selections,
                        html!(
                            <div class="image",>
                                <img src=|s: SubState<Arc<(String, String)>, Arc<Selection>, _>| {
                                         format!("{}/images/{}/{}", SERVER, s.value.size.to_string(), s.key.1)
                                     },
                                     class=|s: SubState<_, Arc<Selection>, _>| {
                                         s.value.state.class()
                                     },
                                     onclick=|e: EventPair<SubState<Arc<(String, String)>, _, _>, _>, s: State| {
                                         s.toggle_selected(e.state.key)
                                     },
                                     ondoubleclick=|e: EventPair<SubState<Arc<(String, String)>, _, _>, _>, s: State| {
                                         s.toggle_size(e.state.key)
                                     },/>
                                <br/>
                                {|s: SubState<_, Arc<Selection>, _>| join(&s.value.tags, ", ")}
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
