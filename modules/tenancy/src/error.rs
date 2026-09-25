use actix_web::{HttpResponse, ResponseError, body::BoxBody};
use sea_orm::DbErr;
use std::borrow::Cow;
use trustify_auth::authenticator::error::AuthorizationError;
use trustify_common::{
    db::{DatabaseErrors, DbError, limiter::LimiterError, pagination_cache::LimitError, query},
    error::ErrorInformation,
    resource_key::ResourceKeyError,
};

use crate::email::EmailError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Database(DbErr),
    #[error(transparent)]
    Query(#[from] query::Error),
    #[error(transparent)]
    Limit(#[from] LimitError),
    #[error(transparent)]
    Authorization(#[from] AuthorizationError),
    #[error(transparent)]
    Email(#[from] EmailError),
    #[error(transparent)]
    ResourceKey(#[from] ResourceKeyError),
    #[error("Bad request: {0}: {1:?}")]
    BadRequest(Cow<'static, str>, Option<Cow<'static, str>>),
    #[error("Conflict: {0}")]
    Conflict(Cow<'static, str>),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("revision not found")]
    RevisionNotFound,
    #[error("unavailable")]
    Unavailable,
    #[error("Internal Server Error: {0}")]
    Internal(String),
    #[error("{0} are disabled")]
    Disabled(&'static str),
}

impl Error {
    pub fn bad_request(
        message: impl Into<Cow<'static, str>>,
        details: Option<impl Into<Cow<'static, str>>>,
    ) -> Self {
        Self::BadRequest(message.into(), details.map(|d| d.into()))
    }
}

impl From<DbErr> for Error {
    fn from(value: DbErr) -> Self {
        if value.is_read_only() {
            Self::Unavailable
        } else if let DbErr::RecordNotFound(msg) = value {
            Self::NotFound(msg)
        } else {
            Self::Database(value)
        }
    }
}

impl From<DbError> for Error {
    fn from(value: DbError) -> Self {
        match value {
            DbError::Database(err) => err.into(),
            DbError::Unavailable => Self::Unavailable,
            DbError::ReadOnly => Self::Internal(value.to_string()),
        }
    }
}

impl From<LimiterError> for Error {
    fn from(value: LimiterError) -> Self {
        match value {
            LimiterError::Db(e) => e.into(),
            LimiterError::Limit(e) => e.into(),
        }
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::Query(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("QueryError", err))
            }
            Self::Limit(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("Limit", err))
            }
            Self::Email(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("InvalidEmail", err))
            }
            Self::ResourceKey(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("InvalidKey", err))
            }
            Self::BadRequest(message, details) => {
                HttpResponse::BadRequest().json(ErrorInformation {
                    error: "BadRequest".into(),
                    message: message.to_string(),
                    details: details.as_ref().map(|d| d.to_string()),
                })
            }
            Self::Authorization(err) => err.error_response(),
            Self::Conflict(message) => {
                HttpResponse::Conflict().json(ErrorInformation::new("Conflict", message))
            }
            Self::NotFound(message) => {
                HttpResponse::NotFound().json(ErrorInformation::new("NotFound", message))
            }
            Self::RevisionNotFound => HttpResponse::PreconditionFailed()
                .json(ErrorInformation::new("RevisionNotFound", self)),
            Self::Disabled(_) => {
                HttpResponse::ServiceUnavailable().json(ErrorInformation::new("Disabled", self))
            }
            Self::Unavailable => {
                HttpResponse::ServiceUnavailable().json(ErrorInformation::new("Unavailable", self))
            }
            Self::Database(_) | Self::Internal(_) => {
                log::warn!("Internal error: {self}");
                HttpResponse::InternalServerError().json(ErrorInformation::new("Internal", self))
            }
        }
    }
}
