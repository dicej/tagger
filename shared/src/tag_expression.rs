use crate::tag_expression_grammar::TagExpressionParser;
use anyhow::{anyhow, Error};
use serde::{Deserializer, Serializer};
use std::{
    collections::BTreeMap,
    fmt::{self, Display},
    str::FromStr,
};

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Hash)]
pub struct Tag {
    pub category: Option<String>,
    pub value: String,
}

impl FromStr for Tag {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if let Some((a, b)) = s.split_once(':') {
            Tag {
                category: Some(a.into()),
                value: b.into(),
            }
        } else {
            Tag {
                category: None,
                value: s.into(),
            }
        })
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
            TagExpression::Tag(tag) => fold(value, tag.category.as_deref(), &tag.value),
        }
    }
}

impl FromStr for TagExpression {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        TagExpressionParser::new()
            .parse(s)
            .map(|tags| *tags)
            .map_err(|e| anyhow!("{}", e))
    }
}

impl Display for TagExpression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TagExpression::Tag(tag) => write!(f, "{}", tag),
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

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct TagTree(pub BTreeMap<Tag, TagTree>);

fn insert(map: &mut BTreeMap<Tag, TagTree>, expression: &TagExpression, subtree: TagTree) {
    match expression {
        TagExpression::Or(a, b) => {
            insert(map, &a, subtree.clone());
            insert(map, &b, subtree);
        }
        TagExpression::And(a, b) => {
            let mut submap = BTreeMap::new();
            insert(&mut submap, &b, subtree);
            insert(map, &a, TagTree(submap));
        }
        TagExpression::Tag(tag) => {
            map.insert(tag.clone(), subtree);
        }
    }
}

impl From<Option<&TagExpression>> for TagTree {
    fn from(expression: Option<&TagExpression>) -> Self {
        let mut map = BTreeMap::new();
        if let Some(expression) = expression {
            insert(&mut map, expression, TagTree::default());
        }
        TagTree(map)
    }
}

impl From<&TagTree> for Option<TagExpression> {
    fn from(tree: &TagTree) -> Self {
        tree.0.iter().fold(None, |acc, (tag, subtree)| {
            let tag = TagExpression::Tag(tag.clone());

            let subexpression = if let Some(subexpression) = subtree.into() {
                TagExpression::And(Box::new(tag), Box::new(subexpression))
            } else {
                tag
            };

            Some(if let Some(acc) = acc {
                TagExpression::Or(Box::new(acc), Box::new(subexpression))
            } else {
                subexpression
            })
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::{anyhow, Result};
    use maplit::btreemap;

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

    #[test]
    fn parse() -> Result<()> {
        assert_eq!(tag("foo"), parse_te("foo")?);
        assert_eq!(tag("foo"), parse_te("(foo)")?);
        assert_eq!(cat_tag("um", "foo"), parse_te("um:foo")?);
        assert_eq!(and(tag("foo"), tag("bar")), parse_te("foo and bar")?);
        assert_eq!(or(tag("foo"), tag("bar")), parse_te("foo or bar")?);
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

        Ok(())
    }

    fn assert_into(tree: TagTree, expression: Option<TagExpression>) {
        let tree_from_expression = TagTree::from(expression.as_ref());
        assert_eq!(tree, tree_from_expression);
        assert_eq!(
            Option::<TagExpression>::from(&tree),
            Option::<TagExpression>::from(&tree_from_expression)
        );
    }

    #[test]
    fn trees() {
        assert_into(TagTree::default(), None::<TagExpression>);
        assert_into(
            TagTree(btreemap![
                raw_tag("foo") => TagTree::default()
            ]),
            Some(tag("foo")),
        );
        assert_into(
            TagTree(btreemap![
                raw_tag("foo") => TagTree(btreemap![
                    raw_tag("bar") => TagTree::default()
                ])
            ]),
            Some(and(tag("foo"), tag("bar"))),
        );
        assert_into(
            TagTree(btreemap![
                raw_tag("foo") => TagTree(btreemap![
                    raw_tag("bar") => TagTree::default()
                ]),
                raw_tag("baz") => TagTree::default()
            ]),
            Some(or(and(tag("foo"), tag("bar")), tag("baz"))),
        );
        assert_into(
            TagTree(btreemap![
                raw_tag("foo") => TagTree(btreemap![
                    raw_tag("bar") => TagTree::default()
                ]),
                raw_tag("baz") => TagTree(btreemap![
                    raw_tag("wat") => TagTree::default()
                ])
            ]),
            Some(or(and(tag("foo"), tag("bar")), and(tag("baz"), tag("wat")))),
        );
        assert_into(
            TagTree(btreemap![
                raw_tag("foo") => TagTree(btreemap![
                    raw_tag("baz") => TagTree::default(),
                    raw_tag("wat") => TagTree::default()
                ]),
                raw_tag("bar") => TagTree(btreemap![
                    raw_tag("baz") => TagTree::default(),
                    raw_tag("wat") => TagTree::default()
                ])
            ]),
            Some(and(or(tag("foo"), tag("bar")), or(tag("baz"), tag("wat")))),
        );
        assert_into(
            TagTree(btreemap![
                raw_tag("foo") => TagTree(btreemap![
                    raw_tag("baz") => TagTree::default(),
                    raw_tag("wat") => TagTree(btreemap![
                        raw_tag("umm") => TagTree::default()
                    ])
                ]),
                raw_tag("bar") => TagTree(btreemap![
                    raw_tag("baz") => TagTree::default(),
                    raw_tag("wat") => TagTree(btreemap![
                        raw_tag("umm") => TagTree::default()
                    ])
                ])
            ]),
            Some(and(
                or(tag("foo"), tag("bar")),
                or(tag("baz"), and(tag("wat"), tag("umm"))),
            )),
        );
    }
}
