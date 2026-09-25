//! Resolving the user, for an authenticated request.

mod sign_in;
#[cfg(test)]
mod test;

pub use sign_in::{Identity, SignIn, find_linked, sign_in};

use crate::{Error, user::model::UserState};
use actix_web::{
    Error as ActixError, FromRequest, HttpMessage, HttpRequest, HttpResponse,
    body::{BoxBody, MessageBody},
    dev::{Payload, ServiceRequest, ServiceResponse},
    http::Method,
    middleware::Next,
};
use moka::future::Cache;
use sea_orm::TransactionTrait;
use std::{
    future::{Ready, ready},
    sync::Arc,
    time::Duration,
};
use trustify_auth::authenticator::user::UserInformation;
use trustify_common::{db, error::ErrorInformation};
use uuid::Uuid;

/// Time an identity stays resolved, before it is looked up again.
const CACHE_TTL: Duration = Duration::from_secs(30);
const CACHE_CAPACITY: u64 = 10_000;

/// The user, an authenticated request is made by.
///
/// This is only present when the access token carried a verified e-mail address, and it could be
/// linked to a user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub id: Uuid,
    pub email: String,
}

impl FromRequest for Principal {
    type Error = ActixError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ready(
            req.extensions()
                .get::<Principal>()
                .cloned()
                .ok_or_else(|| actix_web::error::ErrorForbidden("No user linked to this identity")),
        )
    }
}

/// The cached outcome of resolving an identity.
#[derive(Clone, Debug)]
enum Resolved {
    Principal(Principal),
    Disabled,
    None,
}

impl From<SignIn> for Resolved {
    fn from(value: SignIn) -> Self {
        match value {
            SignIn::User(user) if user.state == UserState::Disabled => Self::Disabled,
            SignIn::User(user) => Self::Principal(Principal {
                id: user.id,
                email: user.email,
            }),
            SignIn::Unknown | SignIn::Conflict => Self::None,
        }
    }
}

/// Resolves authenticated identities to users.
#[derive(Clone)]
pub struct PrincipalResolver {
    db: db::ReadWrite,
    just_in_time: bool,
    cache: Cache<Identity, Resolved>,
}

impl PrincipalResolver {
    pub fn new(db: db::ReadWrite, just_in_time: bool) -> Self {
        Self {
            db,
            just_in_time,
            cache: Cache::builder()
                .max_capacity(CACHE_CAPACITY)
                .time_to_live(CACHE_TTL)
                .build(),
        }
    }

    /// Drop all cached information, e.g. after users have been changed.
    pub fn invalidate(&self) {
        self.cache.invalidate_all();
    }

    async fn resolve(&self, identity: Identity) -> Result<Resolved, Arc<Error>> {
        self.cache
            .try_get_with(identity.clone(), self.lookup(identity))
            .await
    }

    async fn lookup(&self, identity: Identity) -> Result<Resolved, Error> {
        // a concurrent first sign-in of the same identity may conflict, retry once
        for attempt in 0..2 {
            let tx = self.db.begin().await?;
            match sign_in(&identity, self.just_in_time, &tx).await {
                Ok(result) => {
                    tx.commit().await?;
                    return Ok(result.into());
                }
                Err(Error::Conflict(_)) if attempt == 0 => continue,
                Err(Error::Unavailable) => {
                    // read-only mode, we can only look up
                    drop(tx);
                    return Ok(find_linked(&identity, &self.db).await?.into());
                }
                Err(err) => return Err(err),
            }
        }

        Err(Error::Conflict("Unable to link identity".into()))
    }
}

/// Operations which may be performed using an API key, as method and path suffix.
const API_KEY_OPERATIONS: &[(Method, &str)] = &[(Method::POST, "/v3/sbom")];

/// Check if the request is not made using an API key, or is allowed for API keys.
fn api_key_allowed(req: &ServiceRequest) -> bool {
    let is_api_key = matches!(
        req.extensions().get::<UserInformation>(),
        Some(UserInformation::Authenticated(details)) if details.api_key.is_some()
    );

    !is_api_key
        || API_KEY_OPERATIONS
            .iter()
            .any(|(method, path)| req.method() == method && req.path().ends_with(path))
}

/// Middleware resolving the [`Principal`] of an authenticated request.
///
/// This must run after the authentication middleware. Requests by a disabled user will be
/// rejected with `401`. Requests using an API key are rejected with `403`, unless they perform an
/// operation allowed for API keys.
pub async fn resolve_principal(
    resolver: Arc<PrincipalResolver>,
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, ActixError> {
    if !api_key_allowed(&req) {
        let response = HttpResponse::Forbidden().json(ErrorInformation::new(
            "Forbidden",
            "API keys can only be used for uploading SBOMs",
        ));
        return Ok(req.into_response(response).map_into_boxed_body());
    }

    let identity = match req.extensions().get::<UserInformation>() {
        Some(UserInformation::Authenticated(details)) => match (&details.issuer, &details.email) {
            (Some(issuer), Some(email)) => Some(Identity {
                issuer: issuer.clone(),
                subject: details.id.clone(),
                email: email.clone(),
            }),
            _ => None,
        },
        _ => None,
    };

    if let Some(identity) = identity {
        match resolver.resolve(identity).await {
            Ok(Resolved::Principal(principal)) => {
                req.extensions_mut().insert(principal);
            }
            Ok(Resolved::Disabled) => {
                let response = HttpResponse::Unauthorized()
                    .json(ErrorInformation::new("Disabled", "The user is disabled"));
                return Ok(req.into_response(response).map_into_boxed_body());
            }
            Ok(Resolved::None) => {}
            Err(err) => {
                log::warn!("Failed to resolve principal: {err}");
                let response = HttpResponse::ServiceUnavailable().json(ErrorInformation::new(
                    "Unavailable",
                    "Unable to resolve the user",
                ));
                return Ok(req.into_response(response).map_into_boxed_body());
            }
        }
    }

    next.call(req)
        .await
        .map(ServiceResponse::map_into_boxed_body)
}
