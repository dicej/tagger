#![deny(warnings)]

use {
    anyhow::{anyhow, Error},
    chrono::{DateTime, SecondsFormat, Utc},
    lalrpop_util::lalrpop_mod,
    serde::{Deserializer, Serializer},
    serde_derive::{Deserialize, Serialize},
    std::{
        collections::{HashMap, HashSet},
        fmt::{self, Display},
        str::FromStr,
        sync::Arc,
    },
    tag_expression::{Tag, TagExpression},
};

pub mod tag_expression;

lalrpop_mod!(
    #[allow(clippy::all)]
    tag_expression_grammar
);

lalrpop_mod!(
    #[allow(clippy::all)]
    tag_tree_grammar
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    Password,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRequest {
    pub grant_type: GrantType,
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Jwt,
}

#[derive(Serialize, Deserialize)]
pub struct TokenSuccess {
    pub access_token: String,
    pub token_type: TokenType,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenErrorType {
    UnauthorizedClient,
}

#[derive(Serialize, Deserialize)]
pub struct TokenError {
    pub error: TokenErrorType,
    pub error_description: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TagsQuery {
    pub filter: Option<TagExpression>,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Default, Clone)]
pub struct TagsResponse {
    pub immutable: Option<bool>,
    pub categories: HashMap<Arc<str>, TagsResponse>,
    pub tags: HashMap<Arc<str>, u32>,
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct ImageKey {
    pub datetime: DateTime<Utc>,
    pub hash: Option<Arc<str>>,
}

impl FromStr for ImageKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split_inclusive('Z');

        Ok(if let (Some(a), Some(b)) = (split.next(), split.next()) {
            ImageKey {
                datetime: a.parse()?,
                hash: Some(Arc::from(b)),
            }
        } else {
            ImageKey {
                datetime: s.parse()?,
                hash: None,
            }
        })
    }
}

impl Display for ImageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}",
            self.datetime.to_rfc3339_opts(SecondsFormat::Secs, true),
            if let Some(hash) = &self.hash {
                hash
            } else {
                ""
            }
        )
    }
}

impl<'de> serde::Deserialize<'de> for ImageKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for ImageKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ImagesQuery {
    pub start: Option<ImageKey>,
    pub limit: Option<u32>,
    pub filter: Option<TagExpression>,
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum Medium {
    Image,
    ImageWithVideo,
    Video,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ImageData {
    pub hash: Arc<str>,
    pub datetime: DateTime<Utc>,
    pub medium: Medium,
    pub tags: HashSet<Tag>,
}

impl ImageData {
    pub fn key(&self) -> ImageKey {
        ImageKey {
            datetime: self.datetime,
            hash: Some(self.hash.clone()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ImagesResponse {
    pub start: u32,
    pub total: u32,
    pub later_start: Option<ImageKey>,
    pub earliest_start: Option<ImageKey>,
    pub images: Vec<ImageData>,
}

#[derive(Debug, Copy, Clone)]
pub enum Size {
    Small,
    Large,
}

impl Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Size::Small => write!(f, "small"),
            Size::Large => write!(f, "large"),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Variant {
    Still(Size),
    Video(Size),
    Original,
}

impl FromStr for Variant {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "small-image" => Self::Still(Size::Small),
            "large-image" => Self::Still(Size::Large),
            "small-video" => Self::Video(Size::Small),
            "large-video" => Self::Video(Size::Large),
            "original" => Self::Original,
            _ => return Err(anyhow!("unrecognized variant: {}", s)),
        })
    }
}

#[derive(Serialize, Deserialize, Copy, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Add,
    Remove,
}

#[derive(Serialize, Deserialize)]
pub struct Patch {
    pub hash: String,
    pub tag: Tag,
    pub action: Action,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Authorization {
    #[serde(rename = "exp")]
    pub expiration: Option<u64>,

    #[serde(rename = "sub")]
    pub subject: String,

    #[serde(rename = "fil")]
    pub filter: Option<TagExpression>,

    #[serde(rename = "pat")]
    pub may_patch: bool,
}
