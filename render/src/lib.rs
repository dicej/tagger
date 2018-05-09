#![deny(warnings)]

#[cfg(test)]
#[macro_use]
extern crate maplit;
extern crate stdweb;

#[macro_use]
pub mod macros;
pub mod dispatch;
pub mod dom;

#[cfg(test)]
mod tests {
    use dispatch;
    use dom::{self, server, Document};
    use std::collections::btree_map;
    use std::collections::BTreeMap;
    use std::fmt::Write;
    use std::vec;

    fn render<S: Clone + 'static>(
        node: &dispatch::Node<S, S, server::Document>,
        state: &S,
    ) -> String {
        render_with_updates(node, state, &Vec::new())
            .into_iter()
            .next()
            .unwrap()
    }

    fn render_children(e: &<server::Document as Document>::Element) -> String {
        let mut s = String::new();
        for child in &e.borrow().children {
            write!(s, "{}", child).unwrap();
        }
        s
    }

    fn render_with_updates<S: Clone + 'static>(
        node: &dispatch::Node<S, S, server::Document>,
        state: &S,
        updates: &[&Fn(S) -> S],
    ) -> Vec<String> {
        let document = server::Document::new();
        let root = document.create_element("root");
        let dispatcher = dispatch::Dispatcher::from(node, &document, &root, state);
        let mut v = vec![render_children(&root)];
        for u in updates {
            dispatcher.dispatch(u);
            v.push(render_children(&root));
        }
        v
    }

    fn render_with_inputs<S: Clone + 'static>(
        node: &dispatch::Node<S, S, server::Document>,
        state: &S,
        inputs: &[(&str, &Fn(server::Handler))],
    ) -> Vec<String> {
        let document = server::Document::new();
        let root = document.create_element("root");
        dispatch::Dispatcher::from(node, &document, &root, state);
        let mut v = vec![render_children(&root)];
        for i in inputs {
            if let Some(e) = document.get_element_by_id(i.0) {
                let handlers = e.borrow().handlers.clone();
                for h in handlers {
                    i.1(h);
                }
            }
            v.push(render_children(&root));
        }
        v
    }

    #[test]
    fn simple() {
        assert_eq!("<foo/>", &render(&html!(<foo/>), &()));
    }

    #[test]
    fn string_attribute() {
        assert_eq!(
            "<foo bar=\"baz\"/>",
            &render(&html!(<foo bar="baz",/>), &())
        );
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
                &html!(<foo>{dispatch::apply(|(_, s)| s, html!(<bar um=|s| s,/>))}</foo>),
                &("baz".to_string(), "bim".to_string())
            )
        );
    }

    impl dispatch::Diff<u32, char> for BTreeMap<u32, char> {
        type Iterator = btree_map::IntoIter<u32, char>;
        type DiffIterator = vec::IntoIter<dispatch::DiffEvent<u32, char>>;

        fn iter(&self) -> Self::Iterator {
            self.clone().into_iter()
        }

        fn diff(&self, new: &Self) -> Self::DiffIterator {
            self.into_iter()
                .filter_map(|(k, v)| {
                    if let Some(c) = new.get(k) {
                        if c == v {
                            None
                        } else {
                            Some(dispatch::DiffEvent::Update(*k, *c))
                        }
                    } else {
                        Some(dispatch::DiffEvent::Remove(*k))
                    }
                })
                .chain(new.into_iter().filter_map(|(k, v)| {
                    if self.get(k).is_some() {
                        None
                    } else {
                        Some(dispatch::DiffEvent::Add(*k, *v))
                    }
                }))
                .collect::<Vec<_>>()
                .into_iter()
        }
    }

    #[test]
    fn apply_all() {
        assert_eq!(
            "<foo>abcd</foo>",
            &render(
                &html!(<foo>{dispatch::apply_all(|s| s, html!({|s| s}))}</foo>),
                &btreemap![1 => 'a', 2 => 'b', 3 => 'c', 4 => 'd']
            )
        );
    }

    #[test]
    fn apply_all_with_updates() {
        assert_eq!(
            &vec!["<foo>abcd</foo>", "<foo>zbCde</foo>"],
            &render_with_updates(
                &html!(<foo>{dispatch::apply_all(|s| s, html!({|s| s}))}</foo>),
                &btreemap![1 => 'a', 2 => 'b', 3 => 'c', 4 => 'd'],
                &[&|mut s| {
                    s.insert(0, 'z');
                    s.remove(&1);
                    s.insert(3, 'C');
                    s.insert(5, 'e');
                    s
                }],
            )
        );
    }

    #[test]
    fn apply_all_with_inputs() {
        let click = |handler| {
            if let server::Handler::Click(handle) = handler {
                handle(dom::ClickEvent)
            }
        };

        assert_eq!(
            &vec![
                "<foo id=\"42\"><bar id=\"43\"/>abcd</foo>",
                "<foo id=\"42\"><bar id=\"43\"/>aBcd</foo>",
                "<foo id=\"42\"><bar id=\"43\"/>aBcD</foo>",
            ],
            &render_with_inputs(
                &html!(<foo id="42", onclick=|_, mut s: BTreeMap<_, _>| {
                    s.insert(2, 'B');
                    s
                },><bar id="43", onclick=|_, mut s: BTreeMap<_, _>| {
                    s.insert(4, 'D');
		                s
		            },/>{dispatch::apply_all(|s| s, html!({|s| s}))}</foo>),
                &btreemap![1 => 'a', 2 => 'b', 3 => 'c', 4 => 'd'],
                &[("42", &click), ("43", &click)],
            )
        );
    }
}
