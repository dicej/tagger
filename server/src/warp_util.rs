//! This module provides miscellaneous types and functions useful when building a Warp-based web server.

use {
    anyhow::{anyhow, Error, Result},
    chrono::{DateTime, Utc},
    hyper::StatusCode,
    serde_derive::Serialize,
    std::{borrow::Cow, convert::Infallible, str::FromStr},
    warp::{
        reject::{MethodNotAllowed, Reject},
        reply, Rejection, Reply,
    },
};

/// Newtype wrapper for `u16` used for indirect serialization of `hyper::StatusCode` instances
#[derive(Serialize)]
#[serde(remote = "StatusCode")]
struct StatusCodeU16(#[serde(getter = "StatusCode::as_u16")] u16);

/// Simple error type which may be trivially converted to an HTTP response
#[derive(Clone, Serialize, Debug, thiserror::Error)]
#[error("HTTP {}: {}", status, message)]
pub struct HttpError {
    /// Error message to be used as the HTTP response body
    pub message: Cow<'static, str>,

    /// Status code to be used in the HTTP response
    #[serde(with = "StatusCodeU16")]
    pub status: StatusCode,
}

impl HttpError {
    /// Zero-copy constructor for static strings
    pub fn from_slice(status: StatusCode, message: &'static str) -> Self {
        Self {
            status,
            message: Cow::Borrowed(message),
        }
    }

    /// Convenience constructor for 500 errors
    pub fn internal_server_error() -> Self {
        HttpError::from_slice(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
    }

    /// Convert an `anyhow::Error` to an `HttpError`.
    ///
    /// TODO: It would be more idiomatic to implement `From<&Error>` for `HttpError`.
    pub fn from(error: Error) -> Self {
        if let Some(e) = error.root_cause().downcast_ref::<HttpError>() {
            e.clone()
        } else {
            Self::internal_server_error()
        }
    }

    /// Convert this `HttpError` to a Warp `Reply`, i.e. an HTTP response.
    pub fn as_reply(&self) -> impl Reply {
        reply::with_status(reply::json(&self), self.status)
    }
}

/// Implementing `Reject` allows us to return `Result<_, HttpError>` from closures passed to various Warp
/// combinators.
impl Reject for HttpError {}

/// Represents the HTTP Bearer Authorization request header
pub struct Bearer {
    pub body: String,
}

impl FromStr for Bearer {
    type Err = Error;

    // Parse the value of an HTTP Bearer Authorization request header.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let prefix = "Bearer ";
        if let Some(body) = s.strip_prefix(prefix) {
            Ok(Self { body: body.into() })
        } else {
            Err(anyhow!("expected prefix \"{prefix}\""))
        }
    }
}

/// Represents a date parsed from e.g. an HTTP if-modified-since request header
#[derive(Copy, Clone)]
pub struct HttpDate(DateTime<Utc>);

impl FromStr for HttpDate {
    type Err = Error;

    /// Parse a date from e.g. an HTTP if-modified-since request header.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(HttpDate(DateTime::<Utc>::from(
            DateTime::parse_from_rfc2822(s)?,
        )))
    }
}

/// Represents a range from an HTTP Range request header
pub struct Range {
    pub start: Option<u64>,
    pub end: Option<u64>,
}

/// Represents a sequence of ranges from an HTTP Range request header
pub struct Ranges(pub Vec<Range>);

impl FromStr for Ranges {
    type Err = Error;

    /// Parse a sequence of ranges from an HTTP Range request header
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parse = |s: Option<&str>| {
            let s = s.ok_or_else(|| anyhow!("missing separator"))?;
            Ok::<_, Error>(if s.is_empty() {
                None
            } else {
                Some(u64::from_str(s)?)
            })
        };

        let prefix = "bytes=";
        if let Some(body) = s.strip_prefix(prefix) {
            Ok(Ranges(
                body.split(',')
                    .map(|s| {
                        let mut split = s.trim().split('-');

                        let start = parse(split.next())?;
                        let end = parse(split.next())?;

                        Ok(Range { start, end })
                    })
                    .collect::<Result<_>>()?,
            ))
        } else {
            Err(anyhow!("expected prefix \"{prefix}\""))
        }
    }
}

/// Handle a request rejection from a Warp filter, converting it to an appropriate HTTP response.
///
/// Rejections containing `HttpError`s are converted using `HttpError::as_reply`.  Otherwise, we respond according
/// to the type of rejection.
pub async fn handle_rejection(rejection: Rejection) -> Result<impl Reply, Infallible> {
    let error = if rejection.is_not_found() {
        HttpError::from_slice(StatusCode::NOT_FOUND, "not found")
    } else if let Some(error) = rejection.find::<HttpError>() {
        error.clone()
    } else if rejection.find::<MethodNotAllowed>().is_some() {
        HttpError::from_slice(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
    } else {
        HttpError::internal_server_error()
    };

    Ok(error.as_reply())
}
