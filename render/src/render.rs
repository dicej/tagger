#![deny(warnings)]

use std::cell::RefCell;
use std::marker::PhantomData;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::rc::Rc;

mod dom {
    pub enum Node<E, T> {
        Element(E),
        TextNode(T),
    }

    pub trait ToNode<E, T> {
        fn to_node(&self) -> Node<E, T>;
    }

    pub trait Document: Clone {
        type Element: ToNode<Self::Element, Self::TextNode> + Clone;

        type TextNode: ToNode<Self::Element, Self::TextNode> + Clone;

        fn create_element(&self, name: &str) -> Self::Element;

        fn create_text_node(&self, value: &str) -> Self::TextNode;

        fn set_attribute(&self, element: &Self::Element, name: &str, value: &str);

        fn remove_attribute(&self, element: &Self::Element, name: &str);

        fn append_child(&self, element: &Self::Element, child: &ToNode<Self::Element, Self::TextNode>);

        fn remove_child(&self, element: &Self::Element, child: &ToNode<Self::Element, Self::TextNode>);
    }

    // mod server {
    //     struct Element {
    //         name: String;
    //         attributes: BTreeMap<String, String>,
    //         children: Vec<Box<dom::Node>>,
    //     }

    //     impl dom::Element for Rc<RefCell<Element>> {
    //         fn copy(&self) -> Box<dom::Node> {
    //             Box::new(self.clone())
    //         }

    //         fn set_attribute(&self, name: &str, value: &str) {
    //             self.borrow_mut().attributes.insert(name, value.to_string());
    //         }

    //         fn remove_attribute(&self, name: &str, value: &str) {
    //             self.borrow_mut().attributes.remove(name);
    //         }

    //         fn append_child(&self, child: &dom::Node) {
    //             self.borrow_mut().children.push(child.copy());
    //         }

    //         fn remove_child(&self, child: &dom::Node) {
    //             self.borrow_mut().children.retain(|c| (c as &Node as *const _) != (child as *const _));
    //         }
    //     }

    //     struct TextNode {
    //         value: String
    //     }

    //     impl dom::TextNode for Rc<RefCell<TextNode>> {
    //         fn copy(&self) -> Box<dom::Node> {
    //             Box::new(self.clone())
    //         }
    //     }

    //     struct Document {

    //     }

    //     impl dom::Document for Document {
    //         type Element = Rc<RefCell<Element>>;
    //         type TextNode = Rc<RefCell<TextNode>>;

    //         fn create_element(&self, name: &str) -> Self::Element {
    //             Rc::new(RefCell::new(Element {
    //                 name: name.to_string(),
    //                 attributes: BTreeMap::new(),
    //                 children: Vec::new()
    //             }))
    //         }

    //         fn create_text_node(&self, value: &str) -> Self::TextNode {
    //             Rc::new(RefCell::new(TextNode {
    //                 value: value.to_string()
    //             }))
    //         }

    //     }
    // }
}

pub trait Update<S> {
    fn update(&mut self, _state: &S) {
        // ignore
    }
}

pub trait Remove {
    fn remove(&mut self);
}

pub trait Node<S, M, D: dom::Document> {
    fn add(&self, document: &D, parent: &D::Element, state: &S) -> (Option<Box<Update<S>>>, Option<Box<Remove>>);
}

pub trait Value<S> {
    type R: Render<S>;

    fn render(&self, state: &S) -> (String, Option<Self::R>);
}

pub trait Render<S> {
    fn render(&self, state: &S) -> String;
}

pub struct Element<S, M, D: dom::Document> {
    name: String,
    handlers: Vec<Box<Handler<M, D>>>,
    children: Vec<Box<Node<S, M, D>>>,
}

impl<S, M, D: dom::Document> Element<S, M, D> {
    pub fn new<N: ToString>(name: N) -> Self {
        Element {
            name: name.to_string(),
            handlers: Vec::new(),
            children: Vec::new(),
        }
    }
}

impl<S: 'static, M, D: dom::Document + 'static> Node<S, M, D> for Element<S, M, D> {
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

pub trait Handler<M, D: dom::Document> {
    fn attach(&self, element: &D::Element);
}

pub struct Attribute<V> {
    name: Rc<String>,
    value: V,
}

impl<S, M, D: dom::Document + 'static, V: Value<S>> Node<S, M, D> for Attribute<V>
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

pub trait ToNode<S, M, D: dom::Document> {
    type Node: Node<S, M, D>;

    fn to_node(self) -> Self::Node;
}

pub fn to_node<S, M, D: dom::Document, T: ToNode<S, M, D>>(n: T) -> Box<Node<S, M, D>>
where
    T::Node: 'static,
{
    Box::new(n.to_node())
}

pub trait ToValue<S> {
    type Value: Value<S>;

    fn to_value(self) -> Self::Value;
}

pub fn attribute<S, M, D: dom::Document + 'static, T: ToValue<S>>(name: &str, value: T) -> Box<Node<S, M, D>>
where
    T::Value: 'static,
    <T::Value as Value<S>>::R: 'static,
{
    Box::new(Attribute {
        name: Rc::new(name.to_string()),
        value: value.to_value(),
    })
}

impl<S, M, D: dom::Document + 'static> Node<S, M, D> for String
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

impl<'a, S, M, D: dom::Document + 'static> ToNode<S, M, D> for &'a str
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

impl<S, M, D: dom::Document + 'static, T: ToString, F: Fn(&S) -> T + 'static> Node<S, M, D> for Rc<F> {
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

impl<S, M, D: dom::Document + 'static, T: ToString, F: Fn(&S) -> T + 'static> ToNode<S, M, D> for F {
    type Node = Rc<F>;

    fn to_node(self) -> Self::Node {
        Rc::new(self)
    }
}

pub struct Apply<F, N> {
    node: N,
    function: Rc<F>,
}

impl<
    S,
    SubS: PartialEq + 'static,
    M,
    D: dom::Document,
    F: Fn(&S) -> SubS + 'static,
    N: Node<SubS, M, D>,
> ToNode<S, M, D> for Apply<F, N>
{
    type Node = Self;

    fn to_node(self) -> Self::Node {
        self
    }
}

impl<S, SubS: PartialEq + 'static, M, D: dom::Document, F: Fn(&S) -> SubS + 'static, N: Node<SubS, M, D>> Node<S, M, D>
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
    M: 'static,
    D: dom::Document + 'static,
    F: Fn(&S) -> Di + 'static,
    N: Node<SubS, M, D> + 'static,
> ToNode<S, M, D> for ApplyAll<S, K, SubS, Di, F, N>
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
    M: 'static,
    D: dom::Document + 'static,
    F: Fn(&S) -> Di + 'static,
    N: Node<SubS, M, D> + 'static,
> Node<S, M, D> for ApplyAll<S, K, SubS, Di, F, N>
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

        struct Tracker<Di: Diff<K, SubS>, M, D: dom::Document, N, SubS, K, F> {
            _m: PhantomData<M>,
            document: D,
            parent: D::Element,
            node: Rc<N>,
            substate: Di,
            map: BTreeMap<K, (SubS, (Option<Box<Update<SubS>>>, Option<Box<Remove>>))>,
            function: Rc<F>,
        }

        impl<Di: Diff<K, SubS>, M, D: dom::Document, N: Node<SubS, M, D>, SubS, K: Ord, F: Fn(&S) -> Di, S> Update<S>
            for Rc<RefCell<Tracker<Di, M, D, N, SubS, K, F>>>
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

        impl<Di: Diff<K, SubS>, M, D: dom::Document, N, SubS, K, F> Remove for Rc<RefCell<Tracker<Di, M, D, N, SubS, K, F>>> {
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
            _m: PhantomData,
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
