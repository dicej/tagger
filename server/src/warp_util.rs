#![deny(warnings)]

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

#[derive(Serialize)]
#[serde(remote = "StatusCode")]
struct StatusCodeU16(#[serde(getter = "StatusCode::as_u16")] u16);

#[derive(Clone, Serialize, Debug, thiserror::Error)]
#[error("HTTP {}: {}", status, message)]
pub struct HttpError {
    pub message: Cow<'static, str>,
    #[serde(with = "StatusCodeU16")]
    pub status: StatusCode,
}

impl HttpError {
    pub fn from_slice(status: StatusCode, message: &'static str) -> Self {
        Self {
            status,
            message: Cow::Borrowed(message),
        }
    }

    pub fn internal_server_error() -> Self {
        HttpError::from_slice(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
    }

    pub fn from(error: Error) -> Self {
        if let Some(e) = error.root_cause().downcast_ref::<HttpError>() {
            e.clone()
        } else {
            Self::internal_server_error()
        }
    }

    pub fn as_reply(&self) -> impl Reply {
        reply::with_status(reply::json(&self), self.status)
    }
}

impl Reject for HttpError {}

pub struct Bearer {
    pub body: String,
}

impl FromStr for Bearer {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let prefix = "Bearer ";
        if let Some(body) = s.strip_prefix(prefix) {
            Ok(Self { body: body.into() })
        } else {
            Err(anyhow!("expected prefix \"{}\"", prefix))
        }
    }
}

#[derive(Copy, Clone)]
pub struct HttpDate(DateTime<Utc>);

impl FromStr for HttpDate {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(HttpDate(DateTime::<Utc>::from(
            DateTime::parse_from_rfc2822(s)?,
        )))
    }
}

pub struct Range {
    pub start: Option<u64>,
    pub end: Option<u64>,
}

pub struct Ranges(pub Vec<Range>);

impl FromStr for Ranges {
    type Err = Error;

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
            Err(anyhow!("expected prefix \"{}\"", prefix))
        }
    }
}

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
