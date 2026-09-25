//! Resolving the user, for an authenticated request.

mod sign_in;
#[cfg(test)]
mod test;

pub use sign_in::{Identity, SignIn, find_linked, sign_in};

use crate::{
    Error,
    scope::{AuthzMode, api_key_scope, current_revision, is_unrestricted, user_scope},
    user::model::UserState,
};
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
use trustify_auth::{authenticator::user::UserInformation, authorizer::AccessScope};
use trustify_common::{db, error::ErrorInformation};
use uuid::Uuid;

/// Time an identity, or scope, stays cached at most.
const CACHE_TTL: Duration = Duration::from_secs(30);
/// Time the authorization revision is cached, the maximum delay for changes to take effect.
const REVISION_TTL: Duration = Duration::from_secs(1);
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

/// Resolves authenticated identities to users, and computes their access scope.
///
/// Cached information is keyed by the authorization revision, which is bumped by the database
/// whenever something relevant for authorization changes. So changes take effect on all instances
/// within [`REVISION_TTL`].
#[derive(Clone)]
pub struct PrincipalResolver {
    db: db::ReadWrite,
    just_in_time: bool,
    mode: AuthzMode,
    revision: Cache<(), i64>,
    principals: Cache<(Identity, i64), Resolved>,
    scopes: Cache<(Uuid, i64), AccessScope>,
}

impl PrincipalResolver {
    pub fn new(db: db::ReadWrite, just_in_time: bool, mode: AuthzMode) -> Self {
        Self {
            db,
            just_in_time,
            mode,
            revision: Cache::builder().time_to_live(REVISION_TTL).build(),
            principals: Cache::builder()
                .max_capacity(CACHE_CAPACITY)
                .time_to_live(CACHE_TTL)
                .build(),
            scopes: Cache::builder()
                .max_capacity(CACHE_CAPACITY)
                .time_to_live(CACHE_TTL)
                .build(),
        }
    }

    /// Drop all cached information, e.g. after users have been changed.
    pub fn invalidate(&self) {
        self.revision.invalidate_all();
        self.principals.invalidate_all();
        self.scopes.invalidate_all();
    }

    async fn revision(&self) -> Result<i64, Arc<Error>> {
        self.revision
            .try_get_with((), current_revision(&self.db))
            .await
    }

    async fn resolve(&self, identity: Identity) -> Result<Resolved, Arc<Error>> {
        let revision = self.revision().await?;
        self.principals
            .try_get_with((identity.clone(), revision), self.lookup(identity))
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

    /// Compute the access scope of a request.
    ///
    /// Returns `None` when scoped authorization is disabled.
    async fn access_scope(
        &self,
        user: Option<&UserInformation>,
        principal: Option<&Principal>,
    ) -> Result<Option<AccessScope>, Arc<Error>> {
        if self.mode == AuthzMode::Global {
            return Ok(None);
        }

        let details = match user {
            // only possible with authentication disabled
            None | Some(UserInformation::Anonymous) => return Ok(Some(AccessScope::Unrestricted)),
            Some(UserInformation::Authenticated(details)) => details,
        };

        if let Some(api_key) = &details.api_key {
            return Ok(Some(api_key_scope(&api_key.groups)));
        }

        if is_unrestricted(details) {
            return Ok(Some(AccessScope::Unrestricted));
        }

        let Some(principal) = principal else {
            return Ok(Some(AccessScope::none()));
        };

        let revision = self.revision().await?;
        let scope = self
            .scopes
            .try_get_with((principal.id, revision), user_scope(principal.id, &self.db))
            .await?;

        Ok(Some(scope))
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

/// Middleware resolving the [`Principal`] and the [`AccessScope`] of a request.
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

    let user = req.extensions().get::<UserInformation>().cloned();
    let principal = req.extensions().get::<Principal>().cloned();
    match resolver
        .access_scope(user.as_ref(), principal.as_ref())
        .await
    {
        Ok(Some(scope)) => {
            req.extensions_mut().insert(scope);
        }
        Ok(None) => {}
        Err(err) => {
            log::warn!("Failed to compute the access scope: {err}");
            let response = HttpResponse::ServiceUnavailable().json(ErrorInformation::new(
                "Unavailable",
                "Unable to authorize the request",
            ));
            return Ok(req.into_response(response).map_into_boxed_body());
        }
    }

    next.call(req)
        .await
        .map(ServiceResponse::map_into_boxed_body)
}
