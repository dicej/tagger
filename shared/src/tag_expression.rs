use crate::tag_expression_grammar::TagExpressionParser;
use serde::{Deserializer, Serializer};
use std::{
    fmt::{self, Display},
    str::FromStr,
};

#[derive(Debug, Eq, PartialEq)]
pub enum TagExpression {
    Or(Box<TagExpression>, Box<TagExpression>),
    And(Box<TagExpression>, Box<TagExpression>),
    Tag {
        category: Option<String>,
        tag: String,
    },
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
            TagExpression::Tag { category, tag } => fold(value, category.as_deref(), tag),
        }
    }
}

impl FromStr for TagExpression {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        TagExpressionParser::new()
            .parse(s)
            .map(|tags| *tags)
            .map_err(|e| e.to_string())
    }
}

impl Display for TagExpression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TagExpression::Tag { category, tag } => {
                if let Some(category) = category {
                    write!(f, "{}:{}", category, tag)
                } else {
                    write!(f, "{}", tag)
                }
            }
            TagExpression::And(a, b) => write!(f, "({} AND {})", a, b),
            TagExpression::Or(a, b) => write!(f, "({} OR {})", a, b),
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
