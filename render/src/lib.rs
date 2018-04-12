#![deny(warnings)]

#[macro_use]
pub mod macros;
pub mod dom;
pub mod render;

#[cfg(test)]
mod tests {
    use std::vec::IntoIter;
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

    #[test]
    fn apply() {
        assert_eq!(
            "<foo><bar um=\"bim\"/></foo>",
            &render(
                &html!(<foo>{render::apply(|(_, s)| s, html!(<bar um=|s| s,/>))}</foo>),
                &("baz".to_string(), "bim".to_string())
            )
        );
    }

    #[test]
    fn apply_all() {
        impl render::Diff<char, char> for Vec<char> {
            type Iterator = IntoIter<(char, char)>;
            type DiffIterator = IntoIter<render::DiffEvent<char, char>>;

            fn iter(&self) -> Self::Iterator {
                self.into_iter()
                    .cloned()
                    .zip(self.into_iter().cloned())
                    .collect::<Vec<_>>()
                    .into_iter()
            }

            fn diff(&self, _new: &Self) -> Self::DiffIterator {
                unimplemented!()
            }
        }

        assert_eq!(
            "<foo><bar um=\"a\"/><bar um=\"b\"/><bar um=\"c\"/><bar um=\"d\"/></foo>",
            &render(
                &html!(<foo>{render::apply_all(|s| s, html!(<bar um=|s| s,/>))}</foo>),
                &vec!['a', 'b', 'c', 'd']
            )
        );
    }
}
