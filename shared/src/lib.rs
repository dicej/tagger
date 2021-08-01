#![deny(warnings)]

use {
    chrono::{DateTime, Utc},
    lalrpop_util::lalrpop_mod,
    serde_derive::{Deserialize, Serialize},
    std::{
        collections::{HashMap, HashSet},
        fmt::{self, Display},
        sync::Arc,
    },
    tag_expression::{Tag, TagExpression},
};

pub mod tag_expression;

lalrpop_mod!(
    #[allow(clippy::all)]
    tag_expression_grammar
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

#[derive(Serialize, Deserialize, Debug)]
pub struct ImagesQuery {
    pub start: Option<DateTime<Utc>>,
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

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ImagesResponse {
    pub start: u32,
    pub total: u32,
    pub later_start: Option<DateTime<Utc>>,
    pub earliest_start: Option<DateTime<Utc>>,
    pub images: Vec<ImageData>,
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(rename_all = "snake_case")]
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

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Variant {
    Still,
    Video,
}

impl Display for Variant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Variant::Still => write!(f, "still"),
            Variant::Video => write!(f, "video"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ImageQuery {
    pub size: Option<Size>,
    pub variant: Option<Variant>,
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
