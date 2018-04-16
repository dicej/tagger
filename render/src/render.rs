#![deny(warnings)]

use std::cell::RefCell;
use std::marker::PhantomData;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::rc::Rc;

use dom;

pub trait Update<S> {
    fn update(&mut self, _state: &S) {
        // ignore
    }
}

pub trait Remove {
    fn remove(&mut self);
}

pub type Dispatch<T> = Rc<Fn(Box<Fn(T) -> T>)>;

pub trait Node<S, T, D: dom::Document> {
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        dispatch: &Dispatch<T>,
        state: &S,
    ) -> (Option<Box<Update<S>>>, Option<Box<Remove>>);
}

impl<S, T, D: dom::Document> Node<S, T, D> for Box<Node<S, T, D>> {
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        dispatch: &Dispatch<T>,
        state: &S,
    ) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
        self.as_ref().add(document, parent, dispatch, state)
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
    pub handlers: Vec<Box<Handler<T, D>>>,
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
        dispatch: &Dispatch<T>,
        state: &S,
    ) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
        let element = document.create_element(&self.name);
        let children = self.children
            .iter()
            .filter_map(|n| n.add(document, &element, dispatch, state).0)
            .collect::<Vec<_>>();
        self.handlers
            .iter()
            .for_each(|handler| handler.attach(document, &element, dispatch));
        document.append_child(parent, &element);

        struct MyUpdate<S> {
            children: Vec<Box<Update<S>>>,
        }

        impl<S> Update<S> for MyUpdate<S> {
            fn update(&mut self, state: &S) {
                self.children.iter_mut().for_each(|u| u.update(state))
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

        (
            if children.is_empty() {
                None
            } else {
                Some(Box::new(MyUpdate { children }))
            },
            Some(Box::new(MyRemove {
                document: document.clone(),
                parent: parent.clone(),
                element: element.clone(),
            })),
        )
    }
}

pub trait Handler<T, D: dom::Document> {
    fn attach(&self, document: &D, element: &D::Element, dispatch: &Dispatch<T>);
}

pub fn on_click<T: 'static, D: dom::Document, F: Fn(dom::ClickEvent, T) -> T + 'static>(
    handle: F,
) -> Box<Handler<T, D>> {
    struct MyHandler<F> {
        handle: Rc<F>,
    }

    impl<T: 'static, D: dom::Document, F: Fn(dom::ClickEvent, T) -> T + 'static> Handler<T, D> for MyHandler<F> {
        fn attach(&self, document: &D, element: &D::Element, dispatch: &Dispatch<T>) {
            let handle = self.handle.clone();
            let dispatch = dispatch.clone();
            document.on_click(element, move |event| {
                let handle = handle.clone();
                dispatch(Box::new(move |state| handle(event.clone(), state)))
            });
        }
    }

    Box::new(MyHandler {
        handle: Rc::new(handle),
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
        _: &Dispatch<T>,
        state: &S,
    ) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
        let (text, render) = self.value.render(state);
        document.set_attribute(&parent, &self.name, &text);

        struct MyUpdate<D: dom::Document, R> {
            document: D,
            parent: D::Element,
            name: Rc<String>,
            text: String,
            render: R,
        }

        impl<D: dom::Document, R: Render<S>, S> Update<S> for MyUpdate<D, R> {
            fn update(&mut self, state: &S) {
                let text = self.render.render(state);
                if text != self.text {
                    self.document.set_attribute(&self.parent, &self.name, &text);
                    self.text = text;
                }
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

        (
            render.map(|render| {
                Box::new(MyUpdate {
                    document: document.clone(),
                    parent: parent.clone(),
                    name: self.name.clone(),
                    text,
                    render,
                }) as Box<Update<S>>
            }),
            Some(Box::new(MyRemove {
                document: document.clone(),
                parent: parent.clone(),
                name: self.name.clone(),
            })),
        )
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

pub fn attribute<S, T, D: dom::Document + 'static, TV: ToValue<S>>(name: &str, value: TV) -> Box<Node<S, T, D>>
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
        _: &Dispatch<T>,
        _: &S,
    ) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
        let node = document.create_text_node(&self);
        document.append_child(parent, &node);

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

        (
            None,
            Some(Box::new(MyRemove {
                document: document.clone(),
                parent: parent.clone(),
                node: node,
            })),
        )
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

impl<S: Clone, T, D: dom::Document + 'static, TS: ToString, F: Fn(S) -> TS + 'static> Node<S, T, D> for Rc<F> {
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        _: &Dispatch<T>,
        state: &S,
    ) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
        let text = self(state.clone()).to_string();
        let node = document.create_text_node(&text);
        document.append_child(parent, &node);

        struct Tracker<D: dom::Document, F> {
            text: String,
            document: D,
            parent: D::Element,
            node: D::TextNode,
            function: Rc<F>,
        }

        impl<D: dom::Document, TS: ToString, F: Fn(S) -> TS, S: Clone> Update<S> for Rc<RefCell<Tracker<D, F>>> {
            fn update(&mut self, state: &S) {
                let mut t = self.borrow_mut();
                let text = (t.function)(state.clone()).to_string();
                if text != t.text {
                    t.document.remove_child(&t.parent, &t.node);
                    let node = t.document.create_text_node(&text);
                    t.document.append_child(&t.parent, &node);
                    t.text = text;
                    t.node = node;
                }
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
            node,
            function: self.clone(),
        }));

        (Some(Box::new(tracker.clone())), Some(Box::new(tracker)))
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

impl<S: Clone, T, D: dom::Document + 'static, TS: ToString, F: Fn(S) -> TS + 'static> ToNode<S, T, D> for F {
    type Node = Rc<F>;

    fn to_node(self) -> Self::Node {
        Rc::new(self)
    }
}

pub fn apply<S: Clone, SS: PartialEq + 'static, T, D: dom::Document, F: Fn(S) -> SS + 'static, N: Node<SS, T, D>>(
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
    D: dom::Document,
    F: Fn(S) -> SS + 'static,
    N: Node<SS, T, D>,
> ToNode<S, T, D> for Apply<F, N>
{
    type Node = Self;

    fn to_node(self) -> Self::Node {
        self
    }
}

impl<S: Clone, SS: PartialEq + 'static, T, D: dom::Document, F: Fn(S) -> SS + 'static, N: Node<SS, T, D>> Node<S, T, D>
    for Apply<F, N>
{
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        dispatch: &Dispatch<T>,
        state: &S,
    ) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
        let substate = (self.function)(state.clone());
        let (update, remove) = self.node.add(document, parent, dispatch, &substate);

        struct MyUpdate<SS, F> {
            substate: SS,
            update: Box<Update<SS>>,
            function: Rc<F>,
        }

        impl<SS: PartialEq, F: Fn(S) -> SS, S: Clone> Update<S> for MyUpdate<SS, F> {
            fn update(&mut self, state: &S) {
                let substate = (self.function)(state.clone());
                if self.substate != substate {
                    self.substate = substate;
                    self.update.update(&self.substate);
                }
            }
        }

        (
            update.map(|update| {
                Box::new(MyUpdate {
                    substate,
                    update,
                    function: self.function.clone(),
                }) as Box<Update<S>>
            }),
            remove,
        )
    }
}

pub enum DiffEvent<K, V> {
    Add(K, V),
    Update(K, V),
    Remove(K),
}

pub trait Diff<K, V> {
    type Iterator: Iterator<Item = (K, V)>;
    type DiffIterator: Iterator<Item = DiffEvent<K, V>>;

    fn iter(&self) -> Self::Iterator;

    fn diff(&self, new: &Self) -> Self::DiffIterator;
}

pub fn apply_all<
    S: Clone,
    K: Ord + 'static,
    SS: 'static,
    DIF: Diff<K, SS> + 'static,
    T,
    D: dom::Document + 'static,
    F: Fn(S) -> DIF + 'static,
    N: Node<SS, T, D> + 'static,
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
    S: Clone,
    K: Ord + 'static,
    SS: 'static,
    DIF: Diff<K, SS> + 'static,
    T: 'static,
    D: dom::Document + 'static,
    F: Fn(S) -> DIF + 'static,
    N: Node<SS, T, D> + 'static,
> ToNode<S, T, D> for ApplyAll<S, K, SS, DIF, F, N>
{
    type Node = Self;

    fn to_node(self) -> Self::Node {
        self
    }
}

impl<
    S: Clone,
    K: Ord + 'static,
    SS: 'static,
    DIF: Diff<K, SS> + 'static,
    T: 'static,
    D: dom::Document + 'static,
    F: Fn(S) -> DIF + 'static,
    N: Node<SS, T, D> + 'static,
> Node<S, T, D> for ApplyAll<S, K, SS, DIF, F, N>
{
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        dispatch: &Dispatch<T>,
        state: &S,
    ) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
        let substate = (self.function)(state.clone());
        let map = substate
            .iter()
            .map(|(k, v)| {
                let add = self.node.as_ref().add(document, parent, dispatch, &v);
                (k, (v, add))
            })
            .collect::<BTreeMap<_, _>>();

        struct Tracker<DIF: Diff<K, SS>, T, D: dom::Document, N, SS, K, F> {
            document: D,
            parent: D::Element,
            dispatch: Dispatch<T>,
            node: Rc<N>,
            substate: DIF,
            map: BTreeMap<K, (SS, (Option<Box<Update<SS>>>, Option<Box<Remove>>))>,
            function: Rc<F>,
        }

        impl<DIF: Diff<K, SS>, T, D: dom::Document, N: Node<SS, T, D>, SS, K: Ord, F: Fn(S) -> DIF, S: Clone> Update<S>
            for Rc<RefCell<Tracker<DIF, T, D, N, SS, K, F>>>
        {
            fn update(&mut self, state: &S) {
                let mut t = self.borrow_mut();
                let substate = (t.function)(state.clone());
                t.substate.diff(&substate).for_each(|event| match event {
                    DiffEvent::Add(k, v) => {
                        let add = t.node.as_ref().add(&t.document, &t.parent, &t.dispatch, &v);
                        t.map.insert(k, (v, add));
                    }
                    DiffEvent::Update(k, v) => if let Entry::Occupied(mut e) = t.map.entry(k) {
                        let &mut (ref mut old, (ref mut update, _)) = e.get_mut();
                        update.as_mut().map(|u| u.update(&v));
                        *old = v;
                    },
                    DiffEvent::Remove(k) => {
                        t.map.remove(&k).map(|(_, (_, remove))| remove.map(|mut r| r.remove()));
                    }
                });
                t.substate = substate;
            }
        }

        impl<DIF: Diff<K, SS>, T, D: dom::Document, N, SS, K, F> Remove for Rc<RefCell<Tracker<DIF, T, D, N, SS, K, F>>> {
            fn remove(&mut self) {
                self.borrow_mut()
                    .map
                    .iter_mut()
                    .for_each(|(_, &mut (_, (_, ref mut remove)))| {
                        remove.as_mut().map(|r| r.remove());
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

        (Some(Box::new(tracker.clone())), Some(Box::new(tracker)))
    }
}
