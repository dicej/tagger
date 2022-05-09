//! Tagger shared (e.g. protocol) code
//!
//! This crate contains code shared between the Tagger server and client crates.  Currently, it consists of the
//! [serde](https://crates.io/crates/serde)-enabled structs and enums which define the client/server protocol.
//!
//! The `tag_expression` submodule defines the expression language used to query for media items by tag using
//! boolean algebra (e.g. AND, OR, and NOT).

#![deny(warnings)]

use {
    anyhow::{anyhow, Error},
    chrono::{DateTime, SecondsFormat, Utc},
    lalrpop_util::lalrpop_mod,
    serde::{Deserializer, Serializer},
    serde_derive::{Deserialize, Serialize},
    std::{
        collections::{HashMap, HashSet, VecDeque},
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

/// OAuth 2 grant type (we currently only support the "password" type)
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    Password,
}

/// OAuth 2 "password" type authentication request
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRequest {
    pub grant_type: GrantType,
    pub username: String,
    pub password: String,
}

/// OAuth 2 access token type (we currently only support the "jwt" type)
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Jwt,
}

/// OAuth 2 authentication success response
#[derive(Serialize, Deserialize)]
pub struct TokenSuccess {
    pub access_token: String,
    pub token_type: TokenType,
}

/// OAuth 2 authentication error type
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenErrorType {
    UnauthorizedClient,
}

/// OAuth 2 authentication error response
#[derive(Serialize, Deserialize)]
pub struct TokenError {
    pub error: TokenErrorType,
    pub error_description: Option<String>,
}

/// Represents a query string included in a GET /tags request to the Tagger server
#[derive(Serialize, Deserialize, Debug)]
pub struct TagsQuery {
    /// An optional expression to filter the tags by
    ///
    /// For example, if the server database contains items with some mix of tags "foo", "bar", and "baz", and some
    /// items tagged "foo" also have tag "baz", but no items tagged "foo" also have tag "bar", then a filter
    /// expression of "foo" will elicit a response that includes "foo" and "baz", but not "bar".
    pub filter: Option<TagExpression>,
}

/// Represents a response to a GET /tags request from the Tagger server
///
/// This has a recursive structure which mirrors the filter (if any) provided in the `TagsQuery` of the request.
/// See `TagsQuery::filter` for details.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Default, Clone)]
pub struct TagsResponse {
    /// Indicates whether the category under which this `TagsResponse` appears (if any) is considered immutable by
    /// the server, i.e. whether tags in that category can be added to or removed from media items
    ///
    /// `None` means `false`.
    pub immutable: Option<bool>,

    /// Categorized tags and subcategories
    pub categories: HashMap<Arc<str>, TagsResponse>,

    /// Uncategorized tags and the number of media items with each of those tags.
    ///
    /// Note that the count will vary for a given tag depending on the request filter.  For example, if there are 5
    /// items with tag "foo", and 3 of those items also have tag "baz", then the server will say "foo" has 5 items
    /// if the client specifies no filter, but it will say "foo" has 3 items if the client specifies "baz" as the
    /// filter.
    pub tags: HashMap<Arc<str>, u32>,
}

/// Pairs a timestamp with a media item hash to establish a meaningful total order for items
///
/// A timestamp alone is not sufficient, since two items may share the same timestamp, and a hash alone would not
/// result in a meaningful ordering.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct ImageKey {
    /// The timestamp associated with the item (presumably when the photo or video was recorded)
    pub datetime: DateTime<Utc>,

    /// The SHA-256 hash of the contents of the file
    pub hash: Option<Arc<str>>,
}

impl FromStr for ImageKey {
    type Err = Error;

    /// Parse an `ImageKey` from a string of the form
    /// "2019-05-30T12:52:30Z0f3625bdd61372a91d43d34f5f57c6ad529cd4f78c546f1d94a09a20291ce25d" or just
    /// "2019-05-30T12:52:30Z" if there is no hash.
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
    /// Format an `ImageKey` using the format described in `ImageKey::from_str`.
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
    /// Deserialize an `ImageKey` using `ImageKey::from_str`.
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
    /// Serialize an `ImageKey` using `ImageKey::fmt`.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Represents the body of a GET /images request to a Tagger server
#[derive(Serialize, Deserialize, Debug)]
pub struct ImagesQuery {
    /// `ImageKey` representing the start of the desired sequence
    ///
    /// Items are ordered from "greatest" to "least", i.e. from most recent to least recent.  Thus, the response is
    /// expected to contain no item more recent than the timestamp specified here.
    ///
    /// If this is `None`, the server is expected to return the earliest item it has which matches the query.
    pub start: Option<ImageKey>,

    /// Maximum number of items requested
    ///
    /// If this is `None`, the server may choose its own limit.
    pub limit: Option<u32>,

    /// Expression used to filter media items, e.g. "year:2019 and month:3 and not city:boston"
    ///
    /// The server may add to this filter according to the access control rules which apply to the requesting user.
    /// For example, if the user is only allowed to see items tagged "public", then the actual filter used in the
    /// example above would be "public and year:2019 and month:3 and not city:boston".  See `Authorization::filter`
    /// for more details.
    ///
    /// If this is `None`, then no filter will be used besides any needed to enforce access control.
    pub filter: Option<TagExpression>,
}

/// Represents the currently supported media item formats
#[derive(Serialize, Deserialize, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Medium {
    /// Simple static image (e.g. JPEG)
    Image,

    /// Image with embedded video clip (e.g. "motion photo" images produced by some Android phones)
    ImageWithVideo,

    /// Video (e.g. MPEG-4)
    Video,
}

/// Metadata associated with a given media item
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct ImageData {
    /// The SHA-256 hash of the contents of the file
    pub hash: Arc<str>,

    /// The timestamp associated with the item (presumably when the photo or video was recorded)
    pub datetime: DateTime<Utc>,

    /// Format of the item
    pub medium: Medium,

    /// The hashes of any other items which have been identified as inexact duplicates of this item (e.g. resampled
    /// copies)
    ///
    /// The server may attempt to identify duplicates and only send full `ImageData` to the client for the one it
    /// considers to be of highest quality, with the hashes of the others reported using this field.
    pub duplicates: Vec<Arc<str>>,

    /// The set of all tags currently attached to this item
    pub tags: HashSet<Tag>,
}

impl ImageData {
    /// Create an `ImageKey` from the `hash` and `datetime` of this `ImageData`.
    ///
    /// TODO: It would be more idiomatic to implement `From<&ImageData>` for `ImageKey` instead.
    pub fn key(&self) -> ImageKey {
        ImageKey {
            datetime: self.datetime,
            hash: Some(self.hash.clone()),
        }
    }
}

/// Represents the response to a GET /images request from a Tagger server
#[derive(Serialize, Deserialize, Debug, Default, Eq, PartialEq)]
pub struct ImagesResponse {
    /// Number of items which preceed this sequence of items (i.e. how many items the server knows about which
    /// are more recent than what the client requested via `ImagesQuery::start`)
    pub start: u32,

    /// Total number of items matching the `ImagesQuery::filter` specified by the request
    pub total: u32,

    /// `ImageKey` which may be used to "page backward" to the newer items which precede this sequence (such that
    /// each page contains at most the `ImagesQuery::limit` specified by the request, or else the server default if
    /// the request left it unspecified)
    ///
    /// This will be `None` if there are no items preceding this sequence.
    pub later_start: Option<ImageKey>,

    /// `ImageKey` which may be used to skip to the last page of the sequence
    ///
    /// This will be `None` if there are no more items following this sequence.
    pub earliest_start: Option<ImageKey>,

    /// The sequence of items requested
    ///
    /// This may be empty if the server could find no items matching the request, or if the user does not have
    /// access to any items matching the request.
    pub images: Vec<ImageData>,
}

pub struct ImagesResponseBuilder {
    start_key: Option<ImageKey>,
    limit: usize,
    images: Vec<ImageData>,
    later: VecDeque<ImageKey>,
    total: u32,
    start: u32,
    previous: Option<ImageKey>,
    earliest_start: Option<ImageKey>,
    earlier_count: usize,
}

impl ImagesResponseBuilder {
    pub fn new(start_key: Option<ImageKey>, limit: usize) -> Self {
        Self {
            start_key,
            limit,
            images: Vec::with_capacity(limit),
            later: VecDeque::with_capacity(limit + 1),
            total: 0,
            start: 0,
            previous: None,
            earliest_start: None,
            earlier_count: 0,
        }
    }

    pub fn consider<E, F: FnOnce() -> Result<ImageData, E>>(
        &mut self,
        key: &ImageKey,
        fun: F,
    ) -> Result<(), E> {
        self.total += 1;

        if self
            .start_key
            .as_ref()
            .map(|start| key < start)
            .unwrap_or(true)
        {
            if self.images.len() < self.limit {
                self.images.push(fun()?);
            } else {
                if self.earlier_count == 0 {
                    self.earliest_start = self.previous.clone();
                }

                self.earlier_count = (self.earlier_count + 1) % self.limit;
            }
        } else {
            self.start += 1;

            if self.later.len() > self.limit {
                self.later.pop_front();
            }

            self.later.push_back(key.clone());
        }

        self.previous = Some(key.clone());

        Ok(())
    }

    pub fn build(mut self) -> ImagesResponse {
        ImagesResponse {
            start: self.start,
            total: self.total,
            later_start: if self.later.len() > self.limit {
                self.later.pop_front()
            } else {
                None
            },
            earliest_start: self.earliest_start,
            images: self.images,
        }
    }
}

/// Represents different resolutions available for a given media item in addition to the original resolution
#[derive(Debug, Copy, Clone)]
pub enum Size {
    /// Low resolution thumbnail
    ///
    /// In the case of a video, it will generally be truncated to at most five seconds or so.
    Small,

    /// High resolution view
    ///
    /// In the case of a video, the length will be the same as the original, but possibly resampled and reencoded
    /// to minimize the file size.
    Large,
}

impl Display for Size {
    /// Convert a `Size` to a string (e.g. "small" or "large").
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Size::Small => write!(f, "small"),
            Size::Large => write!(f, "large"),
        }
    }
}

/// Represents different versions available for a given media item
///
/// Note that not every item will support every version; e.g. a still image will not have a `Video` version.
#[derive(Debug, Copy, Clone)]
pub enum Variant {
    /// A still image view of the item, e.g. a resampled version of an image or the first frame of a video
    Still(Size),

    /// The video view of the item, e.g. the embedded video clip of a "motion photo" image or a resampled version
    /// of a video
    Video(Size),

    /// The original, unaltered media file
    Original,
}

impl FromStr for Variant {
    type Err = Error;

    /// Parse a `Variant` from a string (e.g. "small", "large", "small-video", etc.).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "small" => Self::Still(Size::Small),
            "large" => Self::Still(Size::Large),
            "small-video" => Self::Video(Size::Small),
            "large-video" => Self::Video(Size::Large),
            "original" => Self::Original,
            _ => return Err(anyhow!("unrecognized variant: {s}")),
        })
    }
}

impl Display for Variant {
    /// Convert a `Variant` to a string (e.g. "small", "large", "small-video", etc.).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Still(Size::Small) => write!(f, "small"),
            Self::Still(Size::Large) => write!(f, "large"),
            Self::Video(Size::Small) => write!(f, "small-video"),
            Self::Video(Size::Large) => write!(f, "large-video"),
            Self::Original => write!(f, "original"),
        }
    }
}

/// Represents the kind of edit operation to be applied to the set of tags for a media item
#[derive(Serialize, Deserialize, Copy, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Add a tag to the item
    Add,

    /// Remove a tag from the item
    Remove,
}

/// Represents an edit operation to be applied to the set of tags for a media item
#[derive(Serialize, Deserialize)]
pub struct Patch {
    /// Hash of the item whose tag set is to be edited
    pub hash: String,

    /// Tag to add or remove
    pub tag: Tag,

    /// Whether to add or remove the tag
    pub action: Action,
}

/// JSON web token claims which may be embedded in access tokens issued by a Tagger server
#[derive(Serialize, Deserialize, Debug)]
pub struct Authorization {
    /// When this token expires (in seconds since the start of 1970 UTC)
    ///
    /// `None` means it never expires
    #[serde(rename = "exp")]
    pub expiration: Option<u64>,

    /// The name of the user this token represents, if any
    ///
    /// The server may be configured to allow anonymous logins, in which case this will be `None`.
    #[serde(rename = "sub")]
    pub subject: Option<String>,

    /// Access control filter applied to every request from this user
    ///
    /// For example, if this is "public and year:2020", then the user will only be able to see (and modify, if
    /// applicable) media items with those tags.  If the user specifies an additional filter, e.g. via
    /// `ImagesQuery::filter`, it will be ANDed with this filter by the server.
    #[serde(rename = "fil")]
    pub filter: Option<TagExpression>,

    /// Whether this user may add and remove tags to/from items to which they have access
    #[serde(rename = "pat")]
    pub may_patch: bool,
}

/// If the specified `auth` claims include a non-empty `Authorization::filter` field, modify the supplied `filter`
/// in place, either replacing it with the one from `auth` if the former is empty, or combining them together using
/// the AND operator.
///
/// This ensures that whatever filter was provided by the user is constrained to what that user has permission to
/// access.
pub fn maybe_wrap_filter(filter: &mut Option<TagExpression>, auth: &Authorization) {
    if let Some(user_filter) = &auth.filter {
        if let Some(inner) = filter.take() {
            *filter = Some(TagExpression::And(
                Box::new(inner),
                Box::new(user_filter.clone()),
            ));
        } else {
            *filter = Some(user_filter.clone());
        }
    }
}
