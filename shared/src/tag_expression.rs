use {
    crate::tag_expression_grammar::TagExpressionParser,
    crate::tag_tree_grammar::TagTreeParser,
    anyhow::{anyhow, Error, Result},
    lazy_static::lazy_static,
    serde::{Deserializer, Serializer},
    std::{
        collections::BTreeMap,
        fmt::{self, Display},
        str::FromStr,
        sync::Arc,
    },
};

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Hash)]
pub struct Tag {
    pub category: Option<Arc<str>>,
    pub value: Arc<str>,
}

impl FromStr for Tag {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let TagExpression::Tag(tag) = s.parse::<TagExpression>()? {
            Ok(tag)
        } else {
            Err(anyhow!("expected tag, got {}", s))
        }
    }
}

impl Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(category) = &self.category {
            write!(f, "{}:{}", category, self.value)
        } else {
            write!(f, "{}", self.value)
        }
    }
}

impl<'de> serde::Deserialize<'de> for Tag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for Tag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum TagExpression {
    Or(Box<TagExpression>, Box<TagExpression>),
    And(Box<TagExpression>, Box<TagExpression>),
    Not(Box<TagExpression>),
    Tag(Tag),
}

impl TagExpression {
    pub fn fold_tags<'a, T>(
        &'a self,
        value: T,
        fold: impl Fn(T, Option<&'a str>, &'a str) -> T + Copy,
    ) -> T {
        match self {
            TagExpression::Or(a, b) | TagExpression::And(a, b) => {
                b.fold_tags(a.fold_tags(value, fold), fold)
            }
            TagExpression::Not(a) => a.fold_tags(value, fold),
            TagExpression::Tag(tag) => fold(value, tag.category.as_deref(), &tag.value),
        }
    }
}

impl FromStr for TagExpression {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            static ref PARSER: TagExpressionParser = TagExpressionParser::new();
        }

        PARSER
            .parse(s)
            .map(|tags| *tags)
            .map_err(|e| anyhow!("{}", e))
    }
}

impl Display for TagExpression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TagExpression::Tag(tag) => write!(f, "{}", tag),
            TagExpression::Not(a) => write!(f, "(not {})", a),
            TagExpression::And(a, b) => write!(f, "({} and {})", a, b),
            TagExpression::Or(a, b) => write!(f, "({} or {})", a, b),
        }
    }
}

impl<'de> serde::Deserialize<'de> for TagExpression {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for TagExpression {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub(crate) enum TagList {
    Cons(Box<(TagAndState, TagList)>),
    Nil,
}

pub(crate) struct TagAndState {
    pub tag: Tag,
    pub state: TagState,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TagState {
    Excluded,
    Included(TagTree),
}

impl Default for TagState {
    fn default() -> Self {
        Self::Included(TagTree::default())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct TagTree(pub BTreeMap<Tag, TagState>);

impl From<TagList> for TagTree {
    fn from(mut list: TagList) -> Self {
        let mut map = BTreeMap::new();

        TagTree(loop {
            match list {
                TagList::Cons(cons) => {
                    map.insert(cons.0.tag, cons.0.state);
                    list = cons.1;
                }
                TagList::Nil => break map,
            }
        })
    }
}

impl FromStr for TagTree {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            static ref PARSER: TagTreeParser = TagTreeParser::new();
        }

        PARSER.parse(s).map_err(|e| anyhow!("{}", e))
    }
}

impl Display for TagTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(")?;
        let mut first = true;
        for (tag, state) in &self.0 {
            if first {
                first = false;
            } else {
                f.write_str(",")?;
            }
            write!(f, "{}=>", tag)?;
            if let TagState::Included(tree) = state {
                write!(f, "{}", tree)?;
            } else {
                f.write_str("excluded")?;
            }
        }
        f.write_str(")")?;

        Ok(())
    }
}

impl<'de> serde::Deserialize<'de> for TagTree {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for TagTree {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl From<&TagTree> for Option<TagExpression> {
    fn from(tree: &TagTree) -> Self {
        let included = tree
            .0
            .iter()
            .filter_map(|(tag, state)| {
                if let TagState::Included(subtree) = state {
                    let tag = TagExpression::Tag(tag.clone());

                    Some(
                        if let Some(expression) = Option::<TagExpression>::from(subtree) {
                            TagExpression::And(Box::new(tag), Box::new(expression))
                        } else {
                            tag
                        },
                    )
                } else {
                    None
                }
            })
            .fold(None, |acc, expression| {
                Some(if let Some(acc) = acc {
                    TagExpression::Or(Box::new(acc), Box::new(expression))
                } else {
                    expression
                })
            });

        tree.0
            .iter()
            .filter_map(|(tag, state)| {
                if let TagState::Excluded = state {
                    Some(TagExpression::Not(Box::new(TagExpression::Tag(
                        tag.clone(),
                    ))))
                } else {
                    None
                }
            })
            .fold(included, |acc, expression| {
                Some(if let Some(acc) = acc {
                    TagExpression::And(Box::new(acc), Box::new(expression))
                } else {
                    expression
                })
            })
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        anyhow::{anyhow, Result},
        maplit::btreemap,
    };

    fn parse_te(s: &str) -> Result<TagExpression> {
        s.parse().map_err(|e| anyhow!("{:?}", e))
    }

    fn raw_cat_tag(category: &str, tag: &str) -> Tag {
        Tag {
            category: Some(category.into()),
            value: tag.into(),
        }
    }

    fn cat_tag(category: &str, tag: &str) -> TagExpression {
        TagExpression::Tag(raw_cat_tag(category, tag))
    }

    fn raw_tag(tag: &str) -> Tag {
        Tag {
            category: None,
            value: tag.into(),
        }
    }

    fn tag(tag: &str) -> TagExpression {
        TagExpression::Tag(raw_tag(tag))
    }

    fn and(a: TagExpression, b: TagExpression) -> TagExpression {
        TagExpression::And(Box::new(a), Box::new(b))
    }

    fn or(a: TagExpression, b: TagExpression) -> TagExpression {
        TagExpression::Or(Box::new(a), Box::new(b))
    }

    fn not(a: TagExpression) -> TagExpression {
        TagExpression::Not(Box::new(a))
    }

    #[test]
    fn expressions() -> Result<()> {
        assert_eq!(tag("foo"), parse_te("foo")?);
        assert_eq!(tag("foo-bar"), parse_te("foo-bar")?);
        assert_eq!(tag("foo"), parse_te("(foo)")?);
        assert_eq!(cat_tag("um", "foo"), parse_te("um:foo")?);
        assert_eq!(and(tag("foo"), tag("bar")), parse_te("foo and bar")?);
        assert_eq!(or(tag("foo"), tag("bar")), parse_te("foo or bar")?);
        assert_eq!(not(tag("foo")), parse_te("not foo")?);
        assert_eq!(
            or(tag("foo"), and(tag("bar"), tag("baz"))),
            parse_te("foo or (bar and baz)")?
        );
        assert_eq!(
            or(tag("foo"), and(tag("bar"), tag("baz"))),
            parse_te("foo or bar and baz")?
        );
        assert_eq!(
            and(or(tag("foo"), cat_tag("wat", "bar")), tag("baz")),
            parse_te("(foo or wat:bar) and baz")?
        );
        assert_eq!(
            and(or(tag("foo"), tag("bar")), tag("baz")),
            parse_te("((foo or bar) and baz)")?
        );
        assert_eq!(
            not(and(or(tag("foo"), tag("bar")), tag("baz"))),
            parse_te("not ((foo or bar) and baz)")?
        );
        assert_eq!(
            and(or(tag("foo"), tag("bar")), not(tag("baz"))),
            parse_te("((foo or bar) and not baz)")?
        );
        assert_eq!(
            and(not(or(tag("foo"), tag("bar"))), tag("baz")),
            parse_te("(not (foo or bar) and baz)")?
        );
        assert_eq!(
            and(or(not(tag("foo")), tag("bar")), tag("baz")),
            parse_te("((not foo or bar) and baz)")?
        );

        Ok(())
    }

    fn test_tree(expression: Option<TagExpression>, tree: TagTree) {
        assert_eq!(expression, (&tree).into());

        assert_eq!(tree, tree.to_string().parse().unwrap());
    }

    #[test]
    fn trees() {
        test_tree(None, TagTree::default());
        test_tree(
            Some(tag("foo")),
            TagTree(btreemap![
                raw_tag("foo") => TagState::default()
            ]),
        );
        test_tree(
            Some(not(tag("foo"))),
            TagTree(btreemap![
                raw_tag("foo") => TagState::Excluded,
            ]),
        );
        test_tree(
            Some(and(tag("bar"), not(tag("foo")))),
            TagTree(btreemap![
                raw_tag("foo") => TagState::Excluded,
                raw_tag("bar") => TagState::default(),
            ]),
        );
        test_tree(
            Some(and(or(tag("bar"), tag("baz")), not(tag("foo")))),
            TagTree(btreemap![
                raw_tag("foo") => TagState::Excluded,
                raw_tag("bar") => TagState::default(),
                raw_tag("baz") => TagState::default(),
            ]),
        );
        test_tree(
            Some(and(and(tag("bar"), tag("baz")), not(tag("foo")))),
            TagTree(btreemap![
                raw_tag("foo") => TagState::Excluded,
                raw_tag("bar") => TagState::Included(TagTree(btreemap![
                    raw_tag("baz") => TagState::default(),
                ]))
            ]),
        );
        test_tree(
            Some(and(tag("foo"), tag("bar"))),
            TagTree(btreemap![
                raw_tag("foo") => TagState::Included(TagTree(btreemap![
                    raw_tag("bar") => TagState::default()
                ]))
            ]),
        );
        test_tree(
            Some(or(tag("baz"), and(tag("foo"), tag("bar")))),
            TagTree(btreemap![
                raw_tag("foo") => TagState::Included(TagTree(btreemap![
                    raw_tag("bar") => TagState::default()
                ])),
                raw_tag("baz") => TagState::default()
            ]),
        );
        test_tree(
            Some(or(and(tag("baz"), tag("wat")), and(tag("foo"), tag("bar")))),
            TagTree(btreemap![
                raw_tag("foo") => TagState::Included(TagTree(btreemap![
                    raw_tag("bar") => TagState::default()
                ])),
                raw_tag("baz") => TagState::Included(TagTree(btreemap![
                    raw_tag("wat") => TagState::default()
                ]))
            ]),
        );
        test_tree(
            Some(or(
                and(tag("bar"), or(tag("baz"), tag("wat"))),
                and(tag("foo"), or(tag("baz"), tag("wat"))),
            )),
            TagTree(btreemap![
                raw_tag("foo") => TagState::Included(TagTree(btreemap![
                    raw_tag("baz") => TagState::default(),
                    raw_tag("wat") => TagState::default()
                ])),
                raw_tag("bar") => TagState::Included(TagTree(btreemap![
                    raw_tag("baz") => TagState::default(),
                    raw_tag("wat") => TagState::default()
                ]))
            ]),
        );
        test_tree(
            Some(or(
                and(tag("bar"), or(tag("baz"), and(tag("wat"), tag("umm")))),
                and(tag("foo"), or(tag("baz"), and(tag("wat"), tag("umm")))),
            )),
            TagTree(btreemap![
                raw_tag("foo") => TagState::Included(TagTree(btreemap![
                    raw_tag("baz") => TagState::default(),
                    raw_tag("wat") => TagState::Included(TagTree(btreemap![
                        raw_tag("umm") => TagState::default()
                    ]))
                ])),
                raw_tag("bar") => TagState::Included(TagTree(btreemap![
                    raw_tag("baz") => TagState::default(),
                    raw_tag("wat") => TagState::Included(TagTree(btreemap![
                        raw_tag("umm") => TagState::default()
                    ]))
                ]))
            ]),
        );
    }
}
