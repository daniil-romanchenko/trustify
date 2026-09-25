//! Information about the calling user.

#[cfg(test)]
mod test;

use crate::{
    Error,
    principal::Principal,
    user::{
        model::{Access, User},
        service::access_of,
    },
};
use actix_web::{HttpResponse, Responder, get, web};
use sea_orm::EntityTrait;
use serde::{Deserialize, Serialize};
use trustify_auth::authenticator::user::UserInformation;
use trustify_common::db;
use trustify_entity::principal_user;
use utoipa::ToSchema;

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig) {
    config.service(me);
}

/// Information about the calling user.
#[derive(Serialize, Deserialize, Debug, Clone, Default, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Me {
    /// The subject of the access token, absent for anonymous requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// The user linked to the access token, absent if there is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
    /// Global permissions, granted through the access token.
    pub permissions: Vec<String>,
    /// Roles on SBOM groups, granted to the user directly or through teams.
    pub access: Vec<Access>,
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "getMe",
    responses(
        (status = 200, description = "Information about the calling user", body = Me),
        (status = 401, description = "The user was not authenticated, or is disabled"),
    )
)]
#[get("/v3/me")]
/// Get information about the calling user
async fn me(
    db: web::Data<db::ReadOnly>,
    user: UserInformation,
    principal: Option<Principal>,
) -> Result<impl Responder, Error> {
    let UserInformation::Authenticated(details) = user else {
        return Ok(HttpResponse::Ok().json(Me::default()));
    };

    let mut me = Me {
        subject: Some(details.id),
        permissions: details.permissions,
        ..Default::default()
    };

    if let Some(principal) = principal {
        let tx = db.begin().await?;
        me.user = principal_user::Entity::find_by_id(principal.id)
            .one(&tx)
            .await?
            .map(Into::into);
        me.access = access_of(principal.id, &tx).await?;
    }

    Ok(HttpResponse::Ok().json(me))
}
