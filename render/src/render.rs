mod dom {
    pub trait Element {
        fn set_attribute(&self, name: &str, value: &str);

        fn append_child(&self, child: &Element);
    }

    pub trait TextNode {

    }
    
    pub trait Document {
        type Element: Element;

        type TextNode: TextNode;

        fn create_element(&self, name: &str) -> Self::Element;

        fn create_text_node(&self, value: &str) -> Self::TextNode;
    }
}

trait Update<D: dom::Document, S, M> {
    fn update(&mut self, _state: &S) {
        // ignore
    }
}

pub trait Node<S, M> {
    fn render<D: dom::Document>(&self, document: &D; parent: &D::Element, state: &S) -> Option<Box<Update<D, S, M>>>;
}

pub trait Value<S> {
    type R: Render<S>;
    
    fn render(&self, state: &S) -> (String, Option<R<S>>);
}

pub trait Render<S> {
    fn render(&self, state: &S) -> String
}

pub struct Element<S, M> {
    name: String,
    handlers: Vec<Box<Handler<M>>>,
    children: Vec<Box<Node<S, M>>>,
}

impl<S, M> Element<S, M> {
    fn new<N: ToString>(name: N) -> Element<S, M> {
        Element {
            name: name.to_string(),
            handlers: Vec::new(),
            children: Vec::new(),
        }
    }
}

impl<S, M> Node for Element<S, M> {
    fn render<D: dom::Document>(&self, document: &D, parent: &D::Element, state: &S) -> Option<Box<Update<D, S, M>>> {
        let element = document.create_element(&self.name);
        let children = self.children.iter().filter_map(|n| n.render(element, state)).collect::<Vec<_>>();
        for handler in self.handlers.iter() {
            handler.attach(&element);
        }
        parent.append_child(&element);

        struct MyUpdate {
            element: D::Element,
            children: Vec<Box<Update<D, S, M>>>,
        }

        impl Update<D, S, M> for MyUpdate {
            fn update(&mut self, state: &S) {
                self.children.for_each(|u| u.update(state))
            }            
        }
        
        if children.is_empty() {
            None
        } else {
            Some(Box::new(MyUpdate {
                element: element.clone(),
                children
            }))
        }
    }
}

pub trait Handler<M> {
    fn attach<D: dom::Document>(&self, element: &D::Element);
}

pub struct Attribute<S, V: Value<S>> {
    name: Rc<String>,
    value: V<S>,
}

impl<S, M, V: Value<S>> Node<S, M> for Attribute<S, V> {
    fn render<D: dom::Document>(&self, document: &D, parent: &D::Element, state: &S) -> Option<Box<Update<D, S, M>>> {
        let (text, render) = self.value.render(state);
        parent.set_attribute(&self.name, &text);

        struct MyUpdate {
            name: Rc<String>,
            text: String,
            render: V::R<S>,
        }

        impl Update<D, S, M> for MyUpdate {
            fn update(&mut self, state: &S) {
                text = self.render.render(state);
                if text != self.text {
                    parent.set_attribute(&self.name, &text);
                    self.text = text;
                }
            }
        }

        if let Some(render) = render {
            Some(MyUpdate {
                name: self.name.clone(),
                text,
                render
            })
        } else {
            None
        }
    }    
}

pub trait ToNode<S, M> {
    type Node: Node<S, M>;
    
    fn to_node(self) -> Self::Node;
}

pub fn to_node<S, M, T: ToNode<S, M>>(n: T) -> Box<Node<S, M>> {
    Box::new(n.to_node())
}

pub trait ToValue<S> {
    type Value: Value<S>;
    
    fn to_value(self) -> Self::Value;
}

pub fn attribute<S, T: ToValue<S>>(name: &str, value: T) -> Box<Node<S, M>> {
    Box::new(Attribute {
        name: name.to_string(),
        value: value.to_value(),
    })
}

impl<S, M> Node<S, M> for String {
    fn render<D: dom::Document>(&self, document: &D, parent: &D::Element, state: &S) -> Option<Box<Update<D, S, M>>> {
        parent.append_child(document.create_text_node(&self.0));

        None
    }
}

impl<S> Value<S> for String {
    type Render = ();
    
    fn render(&self, _state: &S) -> (String, Option<Self::Render>) {
        (self.clone(), None)
    }
}

impl<S> Render<S> for () {
    fn render(&self, _state: &S) -> String {
        unimplemented!()
    }
}

impl<S, M, T: ToString> ToNode<S, M> for T {
    fn to_node(self) -> Box<Node<S, M>> {
        Box::new(self.to_string())
    }
}

impl<S, T: ToString> ToValue<S> for T {
    type Value = String;
    
    fn to_value(self) -> Self::Value {
        self.to_string()
    }
}

impl<S, M, T: ToString, F: Fn(S) -> T> Node<S, M> for Rc<F> {
    fn render<D: dom::Document>(&self, document: &D, parent: &D::Element, state: &S) -> Option<Box<Update<D, S, M>>> {
        let text = self(state).to_string();
        let node = document.create_text_node(&text);
        parent.append_child(&node);

        struct MyUpdate {
            text: String,
            document: D,
            parent: D::Element,
            node: D::TextNode,
            function: Rc<F>
        }

        impl Update<D, S, M> for MyUpdate {
            fn update(&mut self, state: &S) {
                let text = self.function(state).to_string();
                if text != self.text {
                    self.parent.remove_child(&self.node);
                    let node = self.document.create_text_node(&text);
                    self.parent.append_child(&node);
                    self.text = text;
                    self.node = node;
                }
            }            
        }

        Some(Box::new(MyUpdate {
            text,
            parent: parent.clone(),
            document: document.clone(),
            element,
            function: self.clone(),
        }))
    }    
}

impl<S, T: ToString, F: Fn(S) -> T> Value<S> for Rc<F> {
    type Render = Self;
    
    fn render(&self, state: &S) -> (String, Option<Self::Render>>) {
        (self(state).to_string(), Some(self.clone()))
    }
}

impl<S, T: ToString, F: Fn(S) -> T> Render<S> for Rc<F> {
    fn render(&self, state: &S) -> String {
        self(state).to_string();
    }
}

impl<S, T: ToString, F: Fn(S) -> T> ToValue<S> for T {
    type Value = Rc<F>;
    
    fn to_value(self) -> Self::Value {
        Rc::new(self)
    }
}

impl<S, M, T: ToString, F: Fn(&S) -> T> ToNode<S, M> for F {
    type Node = Rc<F>;

    fn to_node(self) -> Self::Node {
        Rc::new(self)
    }    
}

struct Apply<S, SubS, M, F: Fn(&S) -> SubS, N: Node<SubS, M>> {
    node: N;
    function: Rc<F>;
}

impl<S, SubS, M, F: Fn(S) -> SubS, N: Node<SubS, M>> ToNode<S, M> for Apply<S, SubS, M, F, N> {
    type Node = Self;

    fn to_node(self) -> Self::Node {
        self
    }
}

impl<S, SubS, M, F: Fn(&S) -> SubS> Node<S, M> for Apply<S, SubS, M, F> {
    fn render<D: dom::Document>(&self, document: &D, parent: &D::Element, state: &S) -> Option<Box<Update<D, S, M>>> {
        let substate = self.function(state);
        let update = self.node.render(document, parent, &substate);

        struct MyUpdate {
            substate: SubS;
            update: Box<Update<D, SubS, M>>;
            function: Rc<F>,
        }

        impl Update<D, S, M> for MyUpdate {
            fn update(&mut self, state: &S) {
                let substate = self.function(state);
                if self.substate != substate {
                    self.substate = substate;
                    self.update.update(&substate);
                }
            }            
        }
        
        update.map(|update| Box::new(MyUpdate {
            substate,
            update,
            function: function.clone(),
        }))
    }
}

enum DiffEvent<K, V> {
    Add(K, V),
    Update(K, V),
    Remove(K),
}

trait Diff<K, V> {
    type Iterator: Iterator<(K, V)>;
    type DiffIterator: Iterator<DiffEvent<K, V>>;        
        
    fn iter(&self) -> Iterator;

    fn diff(&self, new: &Self) -> DiffIterator;
}

struct ApplyAll<S, K: Ord, V, SubS: Diff<K, V>, M, F: Fn(&S) -> SubS, N: Node<V, M>> {
    node: Rc<N>;
    function: Rc<F>;
}

impl<S, K: Ord, V, SubS: Diff<K, V>>, M, F: Fn(S) -> SubS, N: Node<V, M>> ToNode<S, M> for ApplyAll<S, K, V, SubS, M, F> {
    type Node = Self;

    fn to_node(self) -> Self::Node {
        self
    }
}

impl<S, K: Ord, V, SubS: Diff<K, V>>, M, F: Fn(S) -> SubS, N: Node<V, M>> Node<S, M> for ApplyAll<S, K, V, SubS, M, F> {
    fn render<D: dom::Document>(&self, document: &D, parent: &D::Element, state: &S) -> Option<Box<Update<D, S, M>>> {
        let substate = self.function(state);
        let updates = substate.iter().map(|(k, v)| (k, (v, self.node.render(document, parent, &v)))).collect::BTreeMap<_>();

        struct MyUpdate {
            node: Rc<N>
            substate: SubS;
            updates: BTreeMap<K, (V, Option<Box<Update<D, SubS, M>>>)>;
            function: Rc<F>
        }

        impl Update<D, S, M> for MyUpdate {
            fn update(&mut self, state: &S) {
                let substate = self.function(state);
                self.substate.diff(&substate).for_each(|event| match event {
                    Add(k, v) => self.updates.insert(k, (v, self.node.render(document, parent, &v)));, 
                    Update(k, v) => if let Entry::Occupied(e) = self.updates.entry(&k) {
                        let (old, update) = e.get_mut();
                        update.map(|u| u.update(v));
                        *old = v;
                    },
                    Remove(k) => todo(), // how do we do this?  Might need to have render return both and Option<Box<Update>> and an Option<Box<Remove>>
                });
                self.substate = substate;
            }            
        }

        Some(Box::new(MyUpdate {
            substate,
            updates,
            function: function.clone(),
        }))
    }
}
