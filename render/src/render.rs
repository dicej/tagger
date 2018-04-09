use std::cell::RefCell;
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

        fn append_child(
            &self,
            element: &Self::Element,
            child: &ToNode<Self::Element, Self::TextNode>,
        );

        fn remove_child(
            &self,
            element: &Self::Element,
            child: &ToNode<Self::Element, Self::TextNode>,
        );
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

trait Update<S> {
    fn update(&mut self, _state: &S) {
        // ignore
    }
}

trait Remove {
    fn remove(&mut self);
}

pub trait Node<S, M, D: dom::Document> {
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        state: &S,
    ) -> (Option<Box<Update<S>>>, Option<Box<Remove>>);
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
    fn new<N: ToString>(name: N) -> Self {
        Element {
            name: name.to_string(),
            handlers: Vec::new(),
            children: Vec::new(),
        }
    }
}

impl<S: 'static, M, D: dom::Document + 'static> Node<S, M, D> for Element<S, M, D> {
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        state: &S,
    ) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
        let element = document.create_element(&self.name);
        let children = self.children
            .iter()
            .filter_map(|n| n.add(document, &element, state).0)
            .collect::<Vec<_>>();
        self.handlers
            .iter()
            .for_each(|handler| handler.attach(&element));
        document.append_child(parent, &element);

        struct MyUpdate<E, S> {
            element: E,
            children: Vec<Box<Update<S>>>,
        }

        impl<E, S> Update<S> for MyUpdate<E, S> {
            fn update(&mut self, state: &S) {
                self.children.iter().for_each(|u| u.update(state))
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
                Some(Box::new(MyUpdate {
                    element: element.clone(),
                    children,
                }))
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
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
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

pub fn attribute<S, M, D: dom::Document + 'static, T: ToValue<S>>(
    name: &str,
    value: T,
) -> Box<Node<S, M, D>>
where
    T::Value: 'static,
    <T::Value as Value<S>>::R: 'static,
{
    Box::new(Attribute {
        name: Rc::new(name.to_string()),
        value: value.to_value(),
    })
}

impl<S, M, D: dom::Document> Node<S, M, D> for String {
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        state: &S,
    ) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
        let node = document.create_text_node(&self);
        parent.append_child(&node);

        struct MyRemove<E, T> {
            parent: E,
            node: T,
        }

        impl<E, T> Remove for MyRemove<E, T> {
            fn remove(&mut self) {
                self.parent.remove_child(&self.node);
            }
        }

        (
            None,
            Some(Box::new(MyRemove {
                parent: parent.clone(),
                node: node.clone(),
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

impl<'a, S, M, D: dom::Document> ToNode<S, M, D> for &'a str {
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

impl<S, M, D: dom::Document, T: ToString, F: Fn(S) -> T> Node<S, M, D> for Rc<F> {
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        state: &S,
    ) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
        let text = self(state).to_string();
        let node = document.create_text_node(&text);
        parent.append_child(&node);

        struct Tracker<D, E, T, F> {
            text: String,
            document: D,
            parent: E,
            node: T,
            function: Rc<F>,
        }

        impl<D, E, T, F, S> Update<S> for Rc<RefCell<Tracker<D, E, T, F>>> {
            fn update(&mut self, state: &S) {
                let t = self.borrow_mut();
                let text = t.function(state).to_string();
                if text != t.text {
                    t.parent.remove_child(&t.node);
                    let node = t.document.create_text_node(&text);
                    t.parent.append_child(&node);
                    t.text = text;
                    t.node = node;
                }
            }
        }

        impl<D, E, T, F> Remove for Rc<RefCell<Tracker<D, E, T, F>>> {
            fn remove(&mut self) {
                let t = self.borrow();
                t.parent.remove_child(&t.node);
            }
        }

        let tracker = Rc::new(Tracker {
            text,
            parent: parent.clone(),
            document: document.clone(),
            node,
            function: self.clone(),
        });

        (Some(Box::new(tracker.clone())), Some(Box::new(tracker)))
    }
}

impl<S, T: ToString, F: Fn(S) -> T> Value<S> for Rc<F> {
    type R = Self;

    fn render(&self, state: &S) -> (String, Option<Self::R>) {
        (self(state).to_string(), Some(self.clone()))
    }
}

impl<S, T: ToString, F: Fn(S) -> T> Render<S> for Rc<F> {
    fn render(&self, state: &S) -> String {
        self(state).to_string();
    }
}

impl<S, T: ToString, F: Fn(S) -> T> ToValue<S> for F {
    type Value = Rc<F>;

    fn to_value(self) -> Self::Value {
        Rc::new(self)
    }
}

impl<S, M, D: dom::Document, T: ToString, F: Fn(S) -> T> ToNode<S, M, D> for F {
    type Node = Rc<F>;

    fn to_node(self) -> Self::Node {
        Rc::new(self)
    }
}

struct Apply<F, N> {
    node: N,
    function: Rc<F>,
}

impl<S, SubS, M, D: dom::Document, F: Fn(S) -> SubS, N: Node<SubS, M, D>> ToNode<S, M, D>
    for Apply<F, N>
{
    type Node = Self;

    fn to_node(self) -> Self::Node {
        self
    }
}

impl<S, SubS, M, D: dom::Document, F: Fn(S) -> SubS, N: Node<SubS, M, D>> Node<S, M, D>
    for Apply<F, N>
{
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        state: &S,
    ) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
        let substate = self.function(state);
        let (update, remove) = self.node.add(document, parent, &substate);

        struct MyUpdate<SubS, F> {
            substate: SubS,
            update: Box<Update<SubS>>,
            function: Rc<F>,
        }

        impl<SubS, F, S> Update<S> for MyUpdate<SubS, F> {
            fn update(&mut self, state: &S) {
                let substate = self.function(state);
                if self.substate != substate {
                    self.substate = substate;
                    self.update.update(&substate);
                }
            }
        }

        (
            update.map(|update| {
                Box::new(MyUpdate {
                    substate,
                    update,
                    function: self.function.clone(),
                })
            }),
            remove,
        )
    }
}

enum DiffEvent<K, V> {
    Add(K, V),
    Update(K, V),
    Remove(K),
}

trait Diff<K, V> {
    type Iterator: Iterator<Item = (K, V)>;
    type DiffIterator: Iterator<Item = DiffEvent<K, V>>;

    fn iter(&self) -> Self::Iterator;

    fn diff(&self, new: &Self) -> Self::DiffIterator;
}

struct ApplyAll<F, N> {
    node: Rc<N>,
    function: Rc<F>,
}

impl<S, M, D: dom::Document, F, N> ToNode<S, M, D> for ApplyAll<F, N> {
    type Node = Self;

    fn to_node(self) -> Self::Node {
        self
    }
}

impl<S, M, D: dom::Document, F, N> Node<S, M, D> for ApplyAll<F, N> {
    fn add(
        &self,
        document: &D,
        parent: &D::Element,
        state: &S,
    ) -> (Option<Box<Update<S>>>, Option<Box<Remove>>) {
        let substate = self.function(state);
        let map = substate
            .iter()
            .map(|(k, v)| (k, (v, self.node.add(document, parent, &v))))
            .collect::<BTreeMap<_>>();

        struct Tracker<D, E, N, SubS, K, V, F> {
            document: D,
            parent: E,
            node: Rc<N>,
            substate: SubS,
            map: BTreeMap<K, (V, (Option<Box<Update<SubS>>>, Option<Box<Remove>>))>,
            function: Rc<F>,
        }

        impl<D, E, N, SubS, K, V, F, S> Update<S> for Rc<RefCell<Tracker<D, E, N, SubS, K, V, F>>> {
            fn update(&mut self, state: &S) {
                let t = self.borrow_mut();
                let substate = t.function(state);
                t.substate.diff(&substate).for_each(|event| match event {
                    DiffEvent::Add(k, v) => t.map
                        .insert(k, (v, t.node.add(self.document, self.parent, &v))),
                    DiffEvent::Update(k, v) => if let Entry::Occupied(e) = t.map.entry(&k) {
                        let (old, (update, _)) = e.get_mut();
                        update.map(|u| u.update(v));
                        *old = v;
                    },
                    DiffEvent::Remove(k) => t.map
                        .remove()
                        .map(|(k, (_, (_, remove)))| remove.map(|r| r.remove())),
                });
                t.substate = substate;
            }
        }

        impl<D, E, N, SubS, K, V, F> Remove for Rc<RefCell<Tracker<D, E, N, SubS, K, V, F>>> {
            fn remove(&mut self) {
                self.borrow_mut()
                    .iter()
                    .for_each(|(_, (_, (_, remove)))| remove.map(|r| r.remove()));
            }
        }

        let tracker = Rc::new(Tracker {
            document: document.clone(),
            parent: parent.clone(),
            substate,
            map,
            function: self.function.clone(),
        });

        (Some(Box::new(tracker.clone())), Some(Box::new(tracker)))
    }
}
