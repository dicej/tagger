#![deny(warnings)]

pub enum Node<E, T> {
    Element(E),
    TextNode(T),
}

pub trait ToNode<E, T> {
    fn to_node(&self) -> Node<E, T>;
}

#[derive(Clone)]
pub struct ClickEvent;

pub trait Document: Clone {
    type Element: ToNode<Self::Element, Self::TextNode> + Clone;

    type TextNode: ToNode<Self::Element, Self::TextNode> + Clone;

    fn create_element(&self, name: &str) -> Self::Element;

    fn create_text_node(&self, value: &str) -> Self::TextNode;

    fn set_attribute(&self, element: &Self::Element, name: &str, value: &str);

    fn remove_attribute(&self, element: &Self::Element, name: &str);

    fn append_child(&self, element: &Self::Element, child: &ToNode<Self::Element, Self::TextNode>);

    fn remove_child(&self, element: &Self::Element, child: &ToNode<Self::Element, Self::TextNode>);

    fn on_click<F: Fn(ClickEvent) + 'static>(&self, element: &Self::Element, handle: F);
}

pub mod server {
    use std::collections::{BTreeMap, HashMap};
    use std::rc::Rc;
    use std::fmt;
    use std::cell::RefCell;
    use super::{ClickEvent, Node, ToNode};

    #[derive(Clone)]
    pub enum Handler {
        Click(Rc<Fn(ClickEvent)>),
        None,
    }

    pub struct Element {
        pub name: String,
        pub attributes: BTreeMap<String, String>,
        pub children: Vec<Node<Rc<RefCell<Element>>, Rc<String>>>,
        pub handlers: Vec<Handler>,
    }

    impl ToNode<Rc<RefCell<Element>>, Rc<String>> for Rc<RefCell<Element>> {
        fn to_node(&self) -> Node<Rc<RefCell<Element>>, Rc<String>> {
            Node::Element(self.clone())
        }
    }

    impl ToNode<Rc<RefCell<Element>>, Rc<String>> for Rc<String> {
        fn to_node(&self) -> Node<Rc<RefCell<Element>>, Rc<String>> {
            Node::TextNode(self.clone())
        }
    }

    fn same(a: &Node<Rc<RefCell<Element>>, Rc<String>>, b: &Node<Rc<RefCell<Element>>, Rc<String>>) -> bool {
        match (a, b) {
            (&Node::Element(ref a), &Node::Element(ref b)) => {
                &a.borrow() as &Element as *const Element == &b.borrow() as &Element as *const Element
            }
            (&Node::TextNode(ref a), &Node::TextNode(ref b)) => {
                a.as_ref() as *const String == b.as_ref() as *const String
            }
            _ => false,
        }
    }

    impl fmt::Display for Node<Rc<RefCell<Element>>, Rc<String>> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                &Node::Element(ref e) => {
                    let e = e.borrow();
                    write!(f, "<{}", e.name)?;
                    for (k, v) in &e.attributes {
                        write!(f, " {}=\"{}\"", k, v)?;
                    }
                    if e.children.is_empty() {
                        write!(f, "/>")?;
                    } else {
                        write!(f, ">")?;
                        for child in &e.children {
                            write!(f, "{}", child)?;
                        }
                        write!(f, "</{}>", e.name)?;
                    }
                    Ok(())
                }
                &Node::TextNode(ref t) => write!(f, "{}", t.as_ref()),
            }
        }
    }

    #[derive(Clone)]
    pub struct Document {
        by_id: RefCell<HashMap<String, Rc<RefCell<Element>>>>,
    }

    impl Document {
        pub fn new() -> Document {
            Document {
                by_id: RefCell::new(HashMap::new()),
            }
        }

        pub fn get_element_by_id(&self, id: &str) -> Option<Rc<RefCell<Element>>> {
            self.by_id.borrow().get(id).map(Clone::clone)
        }
    }

    impl super::Document for Document {
        type Element = Rc<RefCell<Element>>;
        type TextNode = Rc<String>;

        fn create_element(&self, name: &str) -> Self::Element {
            Rc::new(RefCell::new(Element {
                name: name.to_string(),
                attributes: BTreeMap::new(),
                children: Vec::new(),
                handlers: Vec::new(),
            }))
        }

        fn create_text_node(&self, value: &str) -> Self::TextNode {
            Rc::new(value.to_string())
        }

        fn set_attribute(&self, element: &Self::Element, name: &str, value: &str) {
            self.remove_attribute(element, name);

            element
                .borrow_mut()
                .attributes
                .insert(name.to_string(), value.to_string());

            if name == "id" {
                self.by_id.borrow_mut().insert(value.to_string(), element.clone());
            }
        }

        fn remove_attribute(&self, element: &Self::Element, name: &str) {
            if name == "id" {
                element
                    .borrow()
                    .attributes
                    .get(name)
                    .map(|value| self.by_id.borrow_mut().remove(value));
            }

            element.borrow_mut().attributes.remove(name);
        }

        fn append_child(&self, element: &Self::Element, child: &ToNode<Self::Element, Self::TextNode>) {
            element.borrow_mut().children.push(child.to_node());
        }

        fn remove_child(&self, element: &Self::Element, child: &ToNode<Self::Element, Self::TextNode>) {
            let child = child.to_node();
            element.borrow_mut().children.retain(|c| !same(c, &child));
        }

        fn on_click<F: Fn(ClickEvent) + 'static>(&self, element: &Self::Element, handle: F) {
            element.borrow_mut().handlers.push(Handler::Click(Rc::new(handle)));
        }
    }
}
