#![deny(warnings)]

#[macro_use]
pub mod macros;
pub mod dom;
pub mod render;

#[cfg(test)]
mod tests {
    use std::fmt::Write;
    use dom::{server, Document};
    use render;

    fn render<S>(node: &Box<render::Node<S, server::Document>>, state: &S) -> String {
        let document = server::Document;
        let root = document.create_element("root");
        node.add(&document, &root, state);
        let mut s = String::new();
        for child in &root.borrow().children {
            write!(s, "{}", child).unwrap();
        }
        s
    }

    #[test]
    fn it_works() {
        assert_eq!("<foo/>", &render(&html!(<foo/>), &()));
    }
}
