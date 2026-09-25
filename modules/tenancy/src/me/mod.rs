//! Information about the calling user.

#[cfg(test)]
mod test;

use crate::{
    Error,
    principal::Principal,
    scope::is_scoped_permission,
    user::{
        model::{Access, User},
        service::access_of,
    },
};
use actix_web::{HttpResponse, Responder, get, web};
use sea_orm::EntityTrait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use trustify_auth::{Permission, authenticator::user::UserInformation, authorizer::AccessScope};
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
    /// Whether access to SBOMs is limited to the groups in [`Self::groups`].
    pub scoped: bool,
    /// The permissions which can actually be used, in at least one group when scoped.
    ///
    /// This is intended for deciding which actions to offer. `None` means all permissions, e.g.
    /// when authentication is disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_permissions: Option<Vec<String>>,
    /// The groups accessible when scoped, including descendants of bound groups.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupPermissions>,
}

/// The permissions granted in a group.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GroupPermissions {
    /// The ID of the group.
    pub id: String,
    pub permissions: Vec<String>,
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
    scope: AccessScope,
) -> Result<impl Responder, Error> {
    let UserInformation::Authenticated(details) = user else {
        return Ok(HttpResponse::Ok().json(Me::default()));
    };

    let mut me = Me {
        subject: Some(details.id),
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

    match &scope {
        AccessScope::Unrestricted => {
            me.effective_permissions = Some(details.permissions.clone());
        }
        AccessScope::Scoped(scoped) => {
            me.scoped = true;

            let mut granted: HashSet<Permission> = HashSet::new();
            for (group, permissions) in scoped.groups() {
                granted.extend(permissions.iter().copied());
                let mut permissions: Vec<String> =
                    permissions.iter().map(ToString::to_string).collect();
                permissions.sort();
                me.groups.push(GroupPermissions {
                    id: group.to_string(),
                    permissions,
                });
            }
            me.groups.sort_by(|a, b| a.id.cmp(&b.id));

            // a scoped permission is only usable if granted in some group, others apply globally
            me.effective_permissions = Some(
                details
                    .permissions
                    .iter()
                    .filter(|permission| {
                        permission
                            .parse::<Permission>()
                            .map(|permission| {
                                !is_scoped_permission(permission) || granted.contains(&permission)
                            })
                            .unwrap_or(true)
                    })
                    .cloned()
                    .collect(),
            );
        }
    }
    me.permissions = details.permissions;

    Ok(HttpResponse::Ok().json(me))
}
