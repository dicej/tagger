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
    fn simple() {
        assert_eq!("<foo/>", &render(&html!(<foo/>), &()));
    }

    #[test]
    fn string_attribute() {
        assert_eq!("<foo bar=\"baz\"/>", &render(&html!(<foo bar="baz",/>), &()));
    }

    #[test]
    fn function_attribute() {
        assert_eq!(
            "<foo bar=\"baz\"/>",
            &render(&html!(<foo bar=|s| s,/>), &"baz".to_string())
        );
    }

    #[test]
    fn string_node() {
        assert_eq!("<foo>baz</foo>", &render(&html!(<foo>{"baz"}</foo>), &()));
    }

    #[test]
    fn function_node() {
        assert_eq!(
            "<foo>baz</foo>",
            &render(&html!(<foo>{|s| s}</foo>), &"baz".to_string())
        );
    }

    #[test]
    fn nested() {
        assert_eq!(
            "<foo><bar um=\"bim\"/>baz</foo>",
            &render(
                &html!(<foo><bar um=|(_, s)| s,/>{|(s, _)| s}</foo>),
                &("baz".to_string(), "bim".to_string())
            )
        );
    }
}
