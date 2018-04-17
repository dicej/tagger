#![deny(warnings)]

// make onclick inferable

// fix failures

// implement dom::client

// implement tagger front end

#[cfg(test)]
#[macro_use]
extern crate maplit;

#[macro_use]
pub mod macros;
pub mod dom;
pub mod render;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::collections::btree_map;
    use std::vec;
    use std::fmt::Write;
    use std::rc::Rc;
    use std::cell::RefCell;
    use dom::{self, server, Document};
    use render;

    fn render<S: Clone>(node: &Box<render::Node<S, S, server::Document>>, state: &S) -> String {
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

    fn render_with_updates<S: Clone>(
        node: &Box<render::Node<S, S, server::Document>>,
        state: &S,
        updates: &[&Fn(S) -> S],
    ) -> Vec<String> {
        let document = server::Document::new();
        let root = document.create_element("root");
        let (mut update, _) = node.add(
            &document,
            &root,
            &(Rc::new(|_| unimplemented!()) as render::Dispatch<S>),
            state,
        );
        let mut v = vec![render_children(&root)];
        let mut state = state.clone() as S;
        for u in updates {
            state = u(state);
            update.as_mut().map(|ref mut update| update.update(&state));
            v.push(render_children(&root));
        }
        v
    }

    fn render_with_inputs<S: Clone + 'static>(
        node: &Box<render::Node<S, S, server::Document>>,
        state: &S,
        inputs: &[(&str, &Fn(server::Handler))],
    ) -> Vec<String> {
        let document = server::Document::new();
        let root = document.create_element("root");
        let state = Rc::new(RefCell::new(state.clone() as S));
        let state2 = state.clone();
        let (mut update, _) = node.add(
            &document,
            &root,
            &(Rc::new(move |update: Box<Fn(S) -> S>| {
                let new = update(state2.borrow().clone());
                *state2.borrow_mut() = new;
            }) as render::Dispatch<S>),
            &state.borrow(),
        );
        let mut v = vec![render_children(&root)];
        for i in inputs {
            if let Some(e) = document.get_element_by_id(i.0) {
                for h in &e.borrow().handlers {
                    i.1(h.clone());
                }
            }
            update.as_mut().map(|ref mut update| update.update(&state.borrow()));
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

    impl render::Diff<u32, char> for BTreeMap<u32, char> {
        type Iterator = btree_map::IntoIter<u32, char>;
        type DiffIterator = vec::IntoIter<render::DiffEvent<u32, char>>;

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
                            Some(render::DiffEvent::Update(*k, *c))
                        }
                    } else {
                        Some(render::DiffEvent::Remove(*k))
                    }
                })
                .chain(new.into_iter().filter_map(|(k, v)| {
                    if self.get(k).is_some() {
                        None
                    } else {
                        Some(render::DiffEvent::Add(*k, *v))
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
                &html!(<foo>{render::apply_all(|s| s, html!({|s| s}))}</foo>),
                &btreemap![1 => 'a', 2 => 'b', 3 => 'c', 4 => 'd']
            )
        );
    }

    #[test]
    fn apply_all_with_updates() {
        assert_eq!(
            &vec!["<foo>abcd</foo>", "<foo>zbCde</foo>"],
            &render_with_updates(
                &html!(<foo>{render::apply_all(|s| s, html!({|s| s}))}</foo>),
                &btreemap![1 => 'a', 2 => 'b', 3 => 'c', 4 => 'd'],
                &[
                    &|mut s| {
                        s.insert(0, 'z');
                        s.remove(&1);
                        s.insert(3, 'C');
                        s.insert(5, 'e');
                        s
                    }
                ],
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
                },><bar id="43", onclick=|_, mut s:	BTreeMap<_, _>| {
      	      	    s.insert(4, 'D');
		                s
		            },/>{render::apply_all(|s| s, html!({|s| s}))}</foo>),
                &btreemap![1 => 'a', 2 => 'b', 3 => 'c', 4 => 'd'],
                &[("42", &click), ("43", &click)],
            )
        );
    }
}
