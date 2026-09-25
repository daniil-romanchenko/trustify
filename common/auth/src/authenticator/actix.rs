use super::Authenticator;
use super::{token::TokenValidator, user::UserInformation};
use actix_http::HttpMessage;
use actix_web::dev::ServiceRequest;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use std::sync::Arc;

pub async fn openid_validator(
    req: ServiceRequest,
    auth: BearerAuth,
    authenticator: Arc<Authenticator>,
) -> Result<ServiceRequest, (actix_web::Error, ServiceRequest)> {
    token_validator(req, auth, authenticator, Arc::new([])).await
}

/// Validate a bearer token, trying the additional validators before OIDC.
pub async fn token_validator(
    req: ServiceRequest,
    auth: BearerAuth,
    authenticator: Arc<Authenticator>,
    validators: Arc<[Arc<dyn TokenValidator>]>,
) -> Result<ServiceRequest, (actix_web::Error, ServiceRequest)> {
    for validator in validators.iter() {
        match validator.validate(auth.token()).await {
            None => continue,
            Some(Ok(details)) => {
                req.extensions_mut()
                    .insert(UserInformation::Authenticated(details));
                return Ok(req);
            }
            Some(Err(err)) => {
                log::debug!("Failed to validate token: {err}");
                return Err((err.into(), req));
            }
        }
    }

    match authenticator.validate_token(auth.token()).await {
        Ok(payload) => {
            req.extensions_mut()
                .insert(UserInformation::Authenticated(payload.into()));
            Ok(req)
        }

        Err(err) => {
            log::debug!("Failed to validate token: {err}");
            Err((err.into(), req))
        }
    }
}
