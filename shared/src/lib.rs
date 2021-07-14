#![deny(warnings)]

use chrono::{DateTime, Utc};
use lalrpop_util::lalrpop_mod;
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tag_expression::TagExpression;

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
    pub categories: HashMap<String, TagsResponse>,
    pub tags: HashMap<String, u32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ImagesQuery {
    pub start: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
    pub filter: Option<TagExpression>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ImageData {
    pub datetime: DateTime<Utc>,
    pub tags: HashSet<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ImagesResponse {
    pub start: u32,
    pub total: u32,
    pub images: HashMap<String, ImageData>,
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ThumbnailSize {
    Small,
    Large,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ImageQuery {
    pub size: Option<ThumbnailSize>,
    pub token: Option<String>,
}
