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

pub trait Node<S, D: dom::Document> {
    fn add(&self, document: &D, parent: &D::Element, state: &S) -> (Option<Box<Update<S>>>, Option<Box<Remove>>);
}

pub trait Value<S> {
    type R: Render<S>;

    fn render(&self, state: &S) -> (String, Option<Self::R>);
}

pub trait Render<S> {
    fn render(&self, state: &S) -> String;
}

pub struct Element<S, D: dom::Document> {
    name: String,
    pub handlers: Vec<Box<Handler<D>>>,
    pub children: Vec<Box<Node<S, D>>>,
}

impl<S, D: dom::Document> Element<S, D> {
    pub fn new<N: ToString>(name: N) -> Self {
        Element {
            name: name.to_string(),
            handlers: Vec::new(),
            children: Vec::new(),
        }
    }
}

impl<S: 'static, D: dom::Document + 'static> Node<S, D> for Element<S, D> {
    fn add(&self, document: &D, parent: &D::Element, state: &S) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
        let element = document.create_element(&self.name);
        let children = self.children
            .iter()
            .filter_map(|n| n.add(document, &element, state).0)
            .collect::<Vec<_>>();
        self.handlers.iter().for_each(|handler| handler.attach(&element));
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

pub trait Handler<D: dom::Document> {
    fn attach(&self, element: &D::Element);
}

pub struct Attribute<V> {
    name: Rc<String>,
    value: V,
}

impl<S, D: dom::Document + 'static, V: Value<S>> Node<S, D> for Attribute<V>
where
    V::R: 'static,
{
    fn add(&self, document: &D, parent: &D::Element, state: &S) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
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
            if let Some(render) = render {
                Some(Box::new(MyUpdate {
                    document: document.clone(),
                    parent: parent.clone(),
                    name: self.name.clone(),
                    text,
                    render,
                }))
            } else {
                None
            },
            Some(Box::new(MyRemove {
                document: document.clone(),
                parent: parent.clone(),
                name: self.name.clone(),
            })),
        )
    }
}

pub trait ToNode<S, D: dom::Document> {
    type Node: Node<S, D>;

    fn to_node(self) -> Self::Node;
}

pub fn to_node<S, D: dom::Document, T: ToNode<S, D>>(n: T) -> Box<Node<S, D>>
where
    T::Node: 'static,
{
    Box::new(n.to_node())
}

pub trait ToValue<S> {
    type Value: Value<S>;

    fn to_value(self) -> Self::Value;
}

pub fn attribute<S, D: dom::Document + 'static, T: ToValue<S>>(name: &str, value: T) -> Box<Node<S, D>>
where
    T::Value: 'static,
    <T::Value as Value<S>>::R: 'static,
{
    Box::new(Attribute {
        name: Rc::new(name.to_string()),
        value: value.to_value(),
    })
}

impl<S, D: dom::Document + 'static> Node<S, D> for String
where
    D::TextNode: 'static,
{
    fn add(&self, document: &D, parent: &D::Element, _state: &S) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
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

impl<'a, S, D: dom::Document + 'static> ToNode<S, D> for &'a str
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

impl<S, D: dom::Document + 'static, T: ToString, F: Fn(&S) -> T + 'static> Node<S, D> for Rc<F> {
    fn add(&self, document: &D, parent: &D::Element, state: &S) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
        let text = self(state).to_string();
        let node = document.create_text_node(&text);
        document.append_child(parent, &node);

        struct Tracker<D: dom::Document, F> {
            text: String,
            document: D,
            parent: D::Element,
            node: D::TextNode,
            function: Rc<F>,
        }

        impl<D: dom::Document, T: ToString, F: Fn(&S) -> T, S> Update<S> for Rc<RefCell<Tracker<D, F>>> {
            fn update(&mut self, state: &S) {
                let mut t = self.borrow_mut();
                let text = (t.function)(state).to_string();
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

impl<S, T: ToString, F: Fn(&S) -> T> Value<S> for Rc<F> {
    type R = Self;

    fn render(&self, state: &S) -> (String, Option<Self::R>) {
        (self(state).to_string(), Some(self.clone()))
    }
}

impl<S, T: ToString, F: Fn(&S) -> T> Render<S> for Rc<F> {
    fn render(&self, state: &S) -> String {
        self(state).to_string()
    }
}

impl<S, T: ToString, F: Fn(&S) -> T> ToValue<S> for F {
    type Value = Rc<F>;

    fn to_value(self) -> Self::Value {
        Rc::new(self)
    }
}

impl<S, D: dom::Document + 'static, T: ToString, F: Fn(&S) -> T + 'static> ToNode<S, D> for F {
    type Node = Rc<F>;

    fn to_node(self) -> Self::Node {
        Rc::new(self)
    }
}

pub struct Apply<F, N> {
    node: N,
    function: Rc<F>,
}

impl<S, SubS: PartialEq + 'static, D: dom::Document, F: Fn(&S) -> SubS + 'static, N: Node<SubS, D>> ToNode<S, D>
    for Apply<F, N>
{
    type Node = Self;

    fn to_node(self) -> Self::Node {
        self
    }
}

impl<S, SubS: PartialEq + 'static, D: dom::Document, F: Fn(&S) -> SubS + 'static, N: Node<SubS, D>> Node<S, D>
    for Apply<F, N>
{
    fn add(&self, document: &D, parent: &D::Element, state: &S) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
        let substate = (self.function)(state);
        let (update, remove) = self.node.add(document, parent, &substate);

        struct MyUpdate<SubS, F> {
            substate: SubS,
            update: Box<Update<SubS>>,
            function: Rc<F>,
        }

        impl<SubS: PartialEq, F: Fn(&S) -> SubS, S> Update<S> for MyUpdate<SubS, F> {
            fn update(&mut self, state: &S) {
                let substate = (self.function)(state);
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

pub struct ApplyAll<S, K, SubS, Di: Diff<K, SubS>, F: Fn(&S) -> Di, N> {
    _s: PhantomData<S>,
    _k: PhantomData<K>,
    _subs: PhantomData<SubS>,
    node: Rc<N>,
    function: Rc<F>,
}

impl<
    S,
    K: Ord + 'static,
    SubS: 'static,
    Di: Diff<K, SubS> + 'static,
    D: dom::Document + 'static,
    F: Fn(&S) -> Di + 'static,
    N: Node<SubS, D> + 'static,
> ToNode<S, D> for ApplyAll<S, K, SubS, Di, F, N>
{
    type Node = Self;

    fn to_node(self) -> Self::Node {
        self
    }
}

impl<
    S,
    K: Ord + 'static,
    SubS: 'static,
    Di: Diff<K, SubS> + 'static,
    D: dom::Document + 'static,
    F: Fn(&S) -> Di + 'static,
    N: Node<SubS, D> + 'static,
> Node<S, D> for ApplyAll<S, K, SubS, Di, F, N>
{
    fn add(&self, document: &D, parent: &D::Element, state: &S) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
        let substate = (self.function)(state);
        let map = substate
            .iter()
            .map(|(k, v)| {
                let add = self.node.as_ref().add(document, parent, &v);
                (k, (v, add))
            })
            .collect::<BTreeMap<_, _>>();

        struct Tracker<Di: Diff<K, SubS>, D: dom::Document, N, SubS, K, F> {
            document: D,
            parent: D::Element,
            node: Rc<N>,
            substate: Di,
            map: BTreeMap<K, (SubS, (Option<Box<Update<SubS>>>, Option<Box<Remove>>))>,
            function: Rc<F>,
        }

        impl<Di: Diff<K, SubS>, D: dom::Document, N: Node<SubS, D>, SubS, K: Ord, F: Fn(&S) -> Di, S> Update<S>
            for Rc<RefCell<Tracker<Di, D, N, SubS, K, F>>>
        {
            fn update(&mut self, state: &S) {
                let mut t = self.borrow_mut();
                let substate = (t.function)(state);
                t.substate.diff(&substate).for_each(|event| match event {
                    DiffEvent::Add(k, v) => {
                        let add = t.node.as_ref().add(&t.document, &t.parent, &v);
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

        impl<Di: Diff<K, SubS>, D: dom::Document, N, SubS, K, F> Remove for Rc<RefCell<Tracker<Di, D, N, SubS, K, F>>> {
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
            node: self.node.clone(),
            substate,
            map,
            function: self.function.clone(),
        }));

        (Some(Box::new(tracker.clone())), Some(Box::new(tracker)))
    }
}
