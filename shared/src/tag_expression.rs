use crate::tag_expression_grammar::TagExpressionParser;
use anyhow::{anyhow, Error, Result};
use lazy_static::lazy_static;
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

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct TagData {
    pub not: bool,
    pub subtree: TagTree,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct TagTree(pub BTreeMap<Tag, TagData>);

impl From<&TagTree> for Option<TagExpression> {
    fn from(tree: &TagTree) -> Self {
        tree.0.iter().fold(None, |acc, (tag, data)| {
            let mut tag = TagExpression::Tag(tag.clone());

            if data.not {
                tag = TagExpression::Not(Box::new(tag));
            }

            let subexpression =
                if let Some(subexpression) = Option::<TagExpression>::from(&data.subtree) {
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

    fn not(a: TagExpression) -> TagExpression {
        TagExpression::Not(Box::new(a))
    }

    #[test]
    fn parse() -> Result<()> {
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

    #[test]
    fn trees() {
        assert_eq!(
            None::<TagExpression>,
            Option::<TagExpression>::from(&TagTree::default())
        );
        assert_eq!(
            Some(tag("foo")),
            Option::<TagExpression>::from(&TagTree(btreemap![
                raw_tag("foo") => TagData::default()
            ]))
        );
        assert_eq!(
            Some(not(tag("foo"))),
            Option::<TagExpression>::from(&TagTree(btreemap![
                raw_tag("foo") => TagData {
                    not: true,
                    subtree: TagTree::default(),
                }
            ])),
        );
        assert_eq!(
            Some(and(tag("foo"), tag("bar"))),
            Option::<TagExpression>::from(&TagTree(btreemap![
                raw_tag("foo") => TagData {
                    not: false,
                    subtree: TagTree(btreemap![
                        raw_tag("bar") => TagData::default()
                    ])
                }
            ])),
        );
        assert_eq!(
            Some(and(not(tag("foo")), tag("bar"))),
            Option::<TagExpression>::from(&TagTree(btreemap![
                raw_tag("foo") => TagData {
                    not: true,
                    subtree: TagTree(btreemap![
                        raw_tag("bar") => TagData::default()
                    ])
                }
            ]))
        );
        assert_eq!(
            Some(or(tag("baz"), and(tag("foo"), tag("bar")))),
            Option::<TagExpression>::from(&TagTree(btreemap![
                raw_tag("foo") => TagData {
                    not: false,
                    subtree: TagTree(btreemap![
                        raw_tag("bar") => TagData::default()
                    ])
                },
                raw_tag("baz") => TagData::default()
            ])),
        );
        assert_eq!(
            Some(or(and(tag("baz"), tag("wat")), and(tag("foo"), tag("bar")))),
            Option::<TagExpression>::from(&TagTree(btreemap![
                raw_tag("foo") => TagData {
                    not: false,
                    subtree: TagTree(btreemap![
                        raw_tag("bar") => TagData::default()
                    ])
                },
                raw_tag("baz") => TagData {
                    not: false,
                    subtree: TagTree(btreemap![
                        raw_tag("wat") => TagData::default()
                    ])
                }
            ])),
        );
        assert_eq!(
            Some(or(
                and(tag("bar"), or(tag("baz"), tag("wat"))),
                and(tag("foo"), or(tag("baz"), tag("wat")))
            )),
            Option::<TagExpression>::from(&TagTree(btreemap![
                raw_tag("foo") => TagData {
                    not: false,
                    subtree: TagTree(btreemap![
                        raw_tag("baz") => TagData::default(),
                        raw_tag("wat") => TagData::default()
                    ])
                },
                raw_tag("bar") => TagData {
                    not: false,
                    subtree: TagTree(btreemap![
                        raw_tag("baz") => TagData::default(),
                        raw_tag("wat") => TagData::default()
                    ])
                }
            ])),
        );
        assert_eq!(
            Some(or(
                and(tag("bar"), or(tag("baz"), and(tag("wat"), tag("umm")))),
                and(tag("foo"), or(tag("baz"), and(tag("wat"), tag("umm"))))
            )),
            Option::<TagExpression>::from(&TagTree(btreemap![
                raw_tag("foo") => TagData {
                    not: false,
                    subtree: TagTree(btreemap![
                        raw_tag("baz") => TagData::default(),
                        raw_tag("wat") => TagData {
                            not: false,
                            subtree: TagTree(btreemap![
                                raw_tag("umm") => TagData::default()
                            ])
                        }
                    ])
                },
                raw_tag("bar") => TagData {
                    not: false,
                    subtree: TagTree(btreemap![
                        raw_tag("baz") => TagData::default(),
                        raw_tag("wat") => TagData {
                            not: false,
                            subtree: TagTree(btreemap![
                                raw_tag("umm") => TagData::default()
                            ])
                        }
                    ])
                }
            ]))
        );
    }
}
