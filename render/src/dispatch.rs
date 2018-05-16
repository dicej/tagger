use std::cell::RefCell;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::collections::Bound::{Excluded, Unbounded};
use std::marker::PhantomData;
use std::mem::swap;
use std::rc::Rc;

use dom::{self, ToNode as DomToNode};

fn identity<T>(t: T) -> T {
    t
}

pub struct Dispatcher<S, D: dom::Document> {
    update: Rc<RefCell<Option<Box<Update<S, D>>>>>,
    state: Rc<RefCell<S>>,
}

impl<S: Clone + 'static, D: dom::Document + 'static> Dispatcher<S, D> {
    pub fn from(node: &Node<S, S, D>, document: &D, parent: &D::Element, state: &S) -> Self {
        let state = Rc::new(RefCell::new(state.clone() as S));
        let update = Rc::new(RefCell::new(None)) as Rc<RefCell<Option<Box<Update<S, D>>>>>;

        *update.borrow_mut() = node.add(
            document,
            parent,
            None,
            {
                let state = state.clone();
                let update = update.clone(); // todo: should this be weak?

                &(Rc::new(move |fun: Box<Fn(S) -> S>| {
                    let s = state.borrow().clone();
                    *state.borrow_mut() = fun(s);

                    update
                        .borrow_mut()
                        .as_mut()
                        .map(|ref mut update| update.update(&state.borrow()));
                }) as Dispatch<S>)
            },
            &state.borrow(),
        ).update;

        Dispatcher { update, state }
    }

    pub fn dispatch(&self, fun: &Fn(S) -> S) {
        let s = self.state.borrow().clone();
        *self.state.borrow_mut() = fun(s);

        self.update
            .borrow_mut()
            .as_mut()
            .map(|ref mut update| update.update(&self.state.borrow()));
    }
}

pub trait Update<S, D: dom::Document> {
    fn update(&mut self, _state: &S) -> Option<dom::Node<D>> {
        None
    }
}

pub trait Remove {
    fn remove(&mut self);
}

pub type Dispatch<T> = Rc<Fn(Box<Fn(T) -> T>)>;

pub struct Added<S, D: dom::Document> {
    pub update: Option<Box<Update<S, D>>>,
    pub remove: Option<Box<Remove>>,
    pub first: Option<dom::Node<D>>,
}

pub trait Node<S, T, D: dom::Document> {
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        next: Option<&dom::ToNode<D>>,
        dispatch: &Dispatch<T>,
        state: &S,
    ) -> Added<S, D>;
}

impl<S, T, D: dom::Document> Node<S, T, D> for Box<Node<S, T, D>> {
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        next: Option<&dom::ToNode<D>>,
        dispatch: &Dispatch<T>,
        state: &S,
    ) -> Added<S, D> {
        self.as_ref().add(document, parent, next, dispatch, state)
    }
}

pub trait Value<S> {
    type R: Render<S>;

    fn render(&self, state: &S) -> (String, Option<Self::R>);
}

pub trait Render<S> {
    fn render(&self, state: &S) -> String;
}

pub struct Element<S, T, D: dom::Document> {
    pub name: String,
    pub handlers: Vec<Box<Handler<S, T, D>>>,
    pub children: Vec<Box<Node<S, T, D>>>,
}

impl<S, T, D: dom::Document> Element<S, T, D> {
    pub fn new<N: ToString>(name: N) -> Self {
        Element {
            name: name.to_string(),
            handlers: Vec::new(),
            children: Vec::new(),
        }
    }
}

impl<S: 'static, T, D: dom::Document + 'static> Node<S, T, D> for Element<S, T, D> {
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        next: Option<&dom::ToNode<D>>,
        dispatch: &Dispatch<T>,
        state: &S,
    ) -> Added<S, D> {
        let element = document.create_element(&self.name);
        let children = self.children
            .iter()
            .filter_map(|n| n.add(document, &element, None, dispatch, state).update)
            .collect::<Vec<_>>();
        let handlers = self.handlers
            .iter()
            .map(|handler| handler.attach(document, &element, state, dispatch))
            .collect();
        document.insert(parent, &element, next);

        struct MyUpdate<S, D: dom::Document> {
            element: D::Element,
            children: Vec<Box<Update<S, D>>>,
            handlers: Vec<Box<HandlerUpdate<S>>>,
        }

        impl<S, D: dom::Document> Update<S, D> for MyUpdate<S, D> {
            fn update(&mut self, state: &S) -> Option<dom::Node<D>> {
                self.children.iter_mut().for_each(|u| {
                    u.update(state);
                });
                self.handlers.iter_mut().for_each(|h| {
                    h.update(state);
                });
                Some(self.element.to_node())
            }
        }

        struct MyRemove<D: dom::Document> {
            document: D,
            parent: D::Element,
            element: D::Element,
        }

        impl<D: dom::Document> Remove for MyRemove<D> {
            fn remove(&mut self) {
                self.document.remove_child(&self.parent, &self.element);
            }
        }

        Added {
            update: if children.is_empty() {
                None
            } else {
                Some(Box::new(MyUpdate {
                    element: element.clone(),
                    children,
                    handlers,
                }))
            },
            remove: Some(Box::new(MyRemove {
                document: document.clone(),
                parent: parent.clone(),
                element: element.clone(),
            })),
            first: Some(element.to_node()),
        }
    }
}

pub trait HandlerUpdate<S> {
    fn update(&mut self, state: &S);
}

pub trait Handler<S, T, D: dom::Document> {
    fn attach(
        &self,
        document: &D,
        element: &D::Element,
        state: &S,
        dispatch: &Dispatch<T>,
    ) -> Box<HandlerUpdate<S>>;
}

pub struct EventPair<S, E> {
    pub state: S,
    pub event: E,
}

struct EventHandler<F> {
    make_handler: Box<F>,
}

impl<
        S: Clone + 'static,
        T: 'static,
        D: dom::Document,
        F: Fn(Rc<RefCell<S>>, Dispatch<T>) -> dom::Handler + 'static,
    > Handler<S, T, D> for EventHandler<F>
{
    fn attach(
        &self,
        document: &D,
        element: &D::Element,
        state: &S,
        dispatch: &Dispatch<T>,
    ) -> Box<HandlerUpdate<S>> {
        let state = Rc::new(RefCell::new(state.clone()));
        document.add_event_listener(
            element,
            (self.make_handler)(state.clone(), dispatch.clone()),
        );

        struct MyUpdate<S> {
            state: Rc<RefCell<S>>,
        }

        impl<S: Clone> HandlerUpdate<S> for MyUpdate<S> {
            fn update(&mut self, state: &S) {
                *self.state.borrow_mut() = (*state).clone();
            }
        }

        Box::new(MyUpdate { state })
    }
}

// todo: reduce code duplication below

pub fn on_click<
    S: Clone + 'static,
    T: 'static,
    D: dom::Document,
    F: Fn(EventPair<S, dom::ClickEvent>, T) -> T + 'static,
>(
    handle: F,
) -> Box<Handler<S, T, D>> {
    let handle = Rc::new(handle);
    Box::new(EventHandler {
        make_handler: Box::new(move |state: Rc<RefCell<S>>, dispatch: Dispatch<T>| {
            let handle = handle.clone();
            dom::Handler::Click(Rc::new(move |event| {
                let handle = handle.clone();
                let state = state.clone();
                dispatch(Box::new(move |top| {
                    let event = event.clone();
                    handle(
                        EventPair {
                            state: (*state.borrow()).clone(),
                            event,
                        },
                        top,
                    )
                }))
            }))
        }),
    })
}

pub fn on_double_click<
    S: Clone + 'static,
    T: 'static,
    D: dom::Document,
    F: Fn(EventPair<S, dom::DoubleClickEvent>, T) -> T + 'static,
>(
    handle: F,
) -> Box<Handler<S, T, D>> {
    let handle = Rc::new(handle);
    Box::new(EventHandler {
        make_handler: Box::new(move |state: Rc<RefCell<S>>, dispatch: Dispatch<T>| {
            let handle = handle.clone();
            dom::Handler::DoubleClick(Rc::new(move |event| {
                let handle = handle.clone();
                let state = state.clone();
                dispatch(Box::new(move |top| {
                    let event = event.clone();
                    handle(
                        EventPair {
                            state: (*state.borrow()).clone(),
                            event,
                        },
                        top,
                    )
                }))
            }))
        }),
    })
}

pub struct Attribute<V> {
    name: Rc<String>,
    value: V,
}

impl<S, T, D: dom::Document + 'static, V: Value<S>> Node<S, T, D> for Attribute<V>
where
    V::R: 'static,
{
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        _: Option<&dom::ToNode<D>>,
        _: &Dispatch<T>,
        state: &S,
    ) -> Added<S, D> {
        let (text, render) = self.value.render(state);
        document.set_attribute(&parent, &self.name, &text);

        struct MyUpdate<D: dom::Document, R> {
            document: D,
            parent: D::Element,
            name: Rc<String>,
            text: String,
            render: R,
        }

        impl<D: dom::Document, R: Render<S>, S> Update<S, D> for MyUpdate<D, R> {
            fn update(&mut self, state: &S) -> Option<dom::Node<D>> {
                let text = self.render.render(state);
                if text != self.text {
                    self.document.set_attribute(&self.parent, &self.name, &text);
                    self.text = text;
                }
                None
            }
        }

        struct MyRemove<D: dom::Document> {
            document: D,
            parent: D::Element,
            name: Rc<String>,
        }

        impl<D: dom::Document> Remove for MyRemove<D> {
            fn remove(&mut self) {
                self.document.remove_attribute(&self.parent, &self.name);
            }
        }

        Added {
            update: render.map(|render| {
                Box::new(MyUpdate {
                    document: document.clone(),
                    parent: parent.clone(),
                    name: self.name.clone(),
                    text,
                    render,
                }) as Box<Update<S, D>>
            }),
            remove: Some(Box::new(MyRemove {
                document: document.clone(),
                parent: parent.clone(),
                name: self.name.clone(),
            })),
            first: None,
        }
    }
}

pub trait ToNode<S, T, D: dom::Document> {
    type Node: Node<S, T, D>;

    fn to_node(self) -> Self::Node;
}

pub fn to_node<S, T, D: dom::Document, TN: ToNode<S, T, D>>(n: TN) -> Box<Node<S, T, D>>
where
    TN::Node: 'static,
{
    Box::new(n.to_node())
}

pub trait ToValue<S> {
    type Value: Value<S>;

    fn to_value(self) -> Self::Value;
}

pub fn attribute<S, T, D: dom::Document + 'static, TV: ToValue<S>>(
    name: &str,
    value: TV,
) -> Box<Node<S, T, D>>
where
    TV::Value: 'static,
    <TV::Value as Value<S>>::R: 'static,
{
    Box::new(Attribute {
        name: Rc::new(name.to_string()),
        value: value.to_value(),
    })
}

impl<S, T, D: dom::Document + 'static> Node<S, T, D> for String
where
    D::TextNode: 'static,
{
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        next: Option<&dom::ToNode<D>>,
        _: &Dispatch<T>,
        _: &S,
    ) -> Added<S, D> {
        let node = document.create_text_node(&self);
        document.insert(parent, &node, next);

        struct MyRemove<D: dom::Document> {
            document: D,
            parent: D::Element,
            node: D::TextNode,
        }

        impl<D: dom::Document> Remove for MyRemove<D> {
            fn remove(&mut self) {
                self.document.remove_child(&self.parent, &self.node);
            }
        }

        Added {
            update: None,
            remove: Some(Box::new(MyRemove {
                document: document.clone(),
                parent: parent.clone(),
                node: node.clone(),
            })),
            first: Some(node.to_node()),
        }
    }
}

impl<S> Value<S> for String {
    type R = ();

    fn render(&self, _state: &S) -> (String, Option<Self::R>) {
        (self.clone(), None)
    }
}

impl<S> Render<S> for () {
    fn render(&self, _state: &S) -> String {
        unimplemented!()
    }
}

// once Rust supports specialization, we can implement ToNode for all ToString here instead of just &str
impl<'a, S, T, D: dom::Document + 'static> ToNode<S, T, D> for &'a str
where
    D::TextNode: 'static,
{
    type Node = String;

    fn to_node(self) -> Self::Node {
        self.to_string()
    }
}

impl<'a, S> ToValue<S> for &'a str {
    type Value = String;

    fn to_value(self) -> Self::Value {
        self.to_string()
    }
}

impl<S: Clone, T, D: dom::Document + 'static, TS: ToString, F: Fn(S) -> TS + 'static> Node<S, T, D>
    for Rc<F>
{
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        next: Option<&dom::ToNode<D>>,
        _: &Dispatch<T>,
        state: &S,
    ) -> Added<S, D> {
        let text = self(state.clone()).to_string();
        let node = document.create_text_node(&text);
        document.insert(parent, &node, next);

        struct Tracker<D: dom::Document, F> {
            text: String,
            document: D,
            parent: D::Element,
            node: D::TextNode,
            function: Rc<F>,
        }

        impl<D: dom::Document, TS: ToString, F: Fn(S) -> TS, S: Clone> Update<S, D>
            for Rc<RefCell<Tracker<D, F>>>
        {
            fn update(&mut self, state: &S) -> Option<dom::Node<D>> {
                let mut t = self.borrow_mut();
                let text = (t.function)(state.clone()).to_string();
                if text != t.text {
                    let node = t.document.create_text_node(&text);

                    t.document.replace_child(&t.parent, &node, &t.node);
                    t.text = text;
                    t.node = node;
                }
                Some(t.node.to_node())
            }
        }

        impl<D: dom::Document, F> Remove for Rc<RefCell<Tracker<D, F>>> {
            fn remove(&mut self) {
                let t = self.borrow();
                t.document.remove_child(&t.parent, &t.node);
            }
        }

        let tracker = Rc::new(RefCell::new(Tracker {
            text,
            parent: parent.clone(),
            document: document.clone(),
            node: node.clone(),
            function: self.clone(),
        }));

        Added {
            update: Some(Box::new(tracker.clone())),
            remove: Some(Box::new(tracker)),
            first: Some(node.to_node()),
        }
    }
}

impl<S: Clone, T: ToString, F: Fn(S) -> T> Value<S> for Rc<F> {
    type R = Self;

    fn render(&self, state: &S) -> (String, Option<Self::R>) {
        (self(state.clone()).to_string(), Some(self.clone()))
    }
}

impl<S: Clone, T: ToString, F: Fn(S) -> T> Render<S> for Rc<F> {
    fn render(&self, state: &S) -> String {
        self(state.clone()).to_string()
    }
}

impl<S: Clone, T: ToString, F: Fn(S) -> T> ToValue<S> for F {
    type Value = Rc<F>;

    fn to_value(self) -> Self::Value {
        Rc::new(self)
    }
}

impl<S: Clone, T, D: dom::Document + 'static, TS: ToString, F: Fn(S) -> TS + 'static>
    ToNode<S, T, D> for F
{
    type Node = Rc<F>;

    fn to_node(self) -> Self::Node {
        Rc::new(self)
    }
}

pub fn apply<
    S: Clone,
    SS: PartialEq + 'static,
    T,
    D: dom::Document,
    F: Fn(S) -> SS + 'static,
    N: Node<SS, T, D>,
>(
    function: F,
    node: N,
) -> Apply<F, N> {
    Apply {
        node,
        function: Rc::new(function),
    }
}

pub struct Apply<F, N> {
    node: N,
    function: Rc<F>,
}

impl<
        S: Clone,
        SS: PartialEq + 'static,
        T,
        D: dom::Document + 'static,
        F: Fn(S) -> SS + 'static,
        N: Node<SS, T, D>,
    > ToNode<S, T, D> for Apply<F, N>
{
    type Node = Self;

    fn to_node(self) -> Self::Node {
        self
    }
}

impl<
        S: Clone,
        SS: PartialEq + 'static,
        T,
        D: dom::Document + 'static,
        F: Fn(S) -> SS + 'static,
        N: Node<SS, T, D>,
    > Node<S, T, D> for Apply<F, N>
{
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        next: Option<&dom::ToNode<D>>,
        dispatch: &Dispatch<T>,
        state: &S,
    ) -> Added<S, D> {
        let substate = (self.function)(state.clone());
        let Added {
            update,
            remove,
            first,
        } = self.node.add(document, parent, next, dispatch, &substate);

        struct MyUpdate<SS, F, D: dom::Document> {
            substate: SS,
            update: Box<Update<SS, D>>,
            first: Option<dom::Node<D>>,
            function: Rc<F>,
        }

        impl<SS: PartialEq, F: Fn(S) -> SS, S: Clone, D: dom::Document> Update<S, D>
            for MyUpdate<SS, F, D>
        {
            fn update(&mut self, state: &S) -> Option<dom::Node<D>> {
                let substate = (self.function)(state.clone());
                if self.substate != substate {
                    self.substate = substate;
                    self.first = self.update.update(&self.substate);
                }
                self.first.clone()
            }
        }

        Added {
            update: update.map(|update| {
                Box::new(MyUpdate {
                    substate,
                    update,
                    first: first.clone(),
                    function: self.function.clone(),
                }) as Box<Update<S, D>>
            }),
            remove: remove,
            first: first,
        }
    }
}

pub enum DiffEvent<K, V> {
    Add { key: K, new_value: V },
    Update { key: K, old_value: V, new_value: V },
    Remove { key: K, old_value: V },
}

pub trait Diff<K, V> {
    type Iterator: Iterator<Item = (K, V)>;
    type DiffIterator: Iterator<Item = DiffEvent<K, V>>;

    fn iter(&self) -> Self::Iterator;

    fn diff(&self, new: &Self) -> Self::DiffIterator;
}

#[derive(Clone)]
pub struct SubState<K, V, P> {
    pub key: K,
    pub value: V,
    pub parent: P,
}

pub fn apply_all<
    S: Clone,
    K: Ord + 'static,
    SS: 'static,
    DIF: Diff<K, SS> + 'static,
    T,
    D: dom::Document + 'static,
    F: Fn(S) -> DIF + 'static,
    N: Node<SubState<K, SS, S>, T, D> + 'static,
>(
    function: F,
    node: N,
) -> ApplyAll<S, K, SS, DIF, F, N> {
    ApplyAll {
        _s: PhantomData,
        _k: PhantomData,
        _subs: PhantomData,
        node: Rc::new(node),
        function: Rc::new(function),
    }
}

pub struct ApplyAll<S, K, SS, DIF: Diff<K, SS>, F: Fn(S) -> DIF, N> {
    _s: PhantomData<S>,
    _k: PhantomData<K>,
    _subs: PhantomData<SS>,
    node: Rc<N>,
    function: Rc<F>,
}

impl<
        S: Clone + 'static,
        K: Ord + Clone + 'static,
        SS: Clone + 'static,
        DIF: Diff<K, SS> + 'static,
        T: 'static,
        D: dom::Document + 'static,
        F: Fn(S) -> DIF + 'static,
        N: Node<SubState<K, SS, S>, T, D> + 'static,
    > ToNode<S, T, D> for ApplyAll<S, K, SS, DIF, F, N>
{
    type Node = Self;

    fn to_node(self) -> Self::Node {
        self
    }
}

impl<
        S: Clone + 'static,
        K: Ord + Clone + 'static,
        SS: Clone + 'static,
        DIF: Diff<K, SS> + 'static,
        T: 'static,
        D: dom::Document + 'static,
        F: Fn(S) -> DIF + 'static,
        N: Node<SubState<K, SS, S>, T, D> + 'static,
    > Node<S, T, D> for ApplyAll<S, K, SS, DIF, F, N>
{
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        next: Option<&dom::ToNode<D>>,
        dispatch: &Dispatch<T>,
        state: &S,
    ) -> Added<S, D> {
        let substate = (self.function)(state.clone());
        let map = substate
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    self.node.as_ref().add(
                        document,
                        parent,
                        next,
                        dispatch,
                        &SubState {
                            key: k,
                            value: v.clone(),
                            parent: state.clone(),
                        },
                    ),
                )
            })
            .collect();

        struct Tracker<DIF: Diff<K, SS>, T, D: dom::Document, N, K, SS, F, S> {
            document: D,
            parent: D::Element,
            dispatch: Dispatch<T>,
            node: Rc<N>,
            substate: DIF,
            map: BTreeMap<K, Added<SubState<K, SS, S>, D>>,
            function: Rc<F>,
        }

        impl<
                DIF: Diff<K, SS>,
                T,
                D: dom::Document,
                N: Node<SubState<K, SS, S>, T, D>,
                K: Ord + Clone,
                SS: Clone,
                F: Fn(S) -> DIF,
                S: Clone,
            > Update<S, D> for Rc<RefCell<Tracker<DIF, T, D, N, K, SS, F, S>>>
        {
            fn update(&mut self, state: &S) -> Option<dom::Node<D>> {
                let mut t = self.borrow_mut();
                let substate = (t.function)(state.clone());
                t.substate.diff(&substate).for_each(|event| match event {
                    DiffEvent::Add { key, new_value } => {
                        let added = t.node.as_ref().add(
                            &t.document,
                            &t.parent,
                            t.map
                                .range((Excluded(key.clone()), Unbounded))
                                .filter_map(|(_, added)| added.first.clone())
                                .next()
                                .as_ref()
                                .map(|n| n as &dom::ToNode<D>),
                            &t.dispatch,
                            &SubState {
                                key: key.clone(),
                                value: new_value.clone(),
                                parent: state.clone(),
                            },
                        );
                        t.map.insert(key, added);
                    }
                    DiffEvent::Update { key, new_value, .. } => {
                        if let Entry::Occupied(mut e) = t.map.entry(key.clone()) {
                            let added = e.get_mut();
                            added.first = added
                                .update
                                .as_mut()
                                .map(|u| {
                                    u.update(&SubState {
                                        key,
                                        value: new_value,
                                        parent: state.clone(),
                                    })
                                })
                                .and_then(identity);
                        }
                    }
                    DiffEvent::Remove { key, .. } => {
                        t.map
                            .remove(&key)
                            .map(|added| added.remove.map(|mut r| r.remove()));
                    }
                });
                t.substate = substate;
                t.map
                    .iter()
                    .filter_map(|(_, added)| added.first.clone())
                    .next()
            }
        }

        impl<DIF: Diff<K, SS>, T, D: dom::Document, N, K: Ord, SS, F, S> Remove
            for Rc<RefCell<Tracker<DIF, T, D, N, K, SS, F, S>>>
        {
            fn remove(&mut self) {
                let mut map = BTreeMap::new();
                swap(&mut map, &mut self.borrow_mut().map);
                map.into_iter().for_each(|(_, added)| {
                    added.remove.map(|mut r| r.remove());
                });
            }
        }

        let tracker = Rc::new(RefCell::new(Tracker {
            document: document.clone(),
            parent: parent.clone(),
            dispatch: dispatch.clone(),
            node: self.node.clone(),
            substate,
            map,
            function: self.function.clone(),
        }));

        let first = tracker
            .borrow()
            .map
            .iter()
            .filter_map(|(_, added)| added.first.clone())
            .next();

        Added {
            update: Some(Box::new(tracker.clone())),
            remove: Some(Box::new(tracker)),
            first,
        }
    }
}
