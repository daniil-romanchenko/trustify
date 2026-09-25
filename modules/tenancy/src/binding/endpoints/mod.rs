#[cfg(test)]
mod test;

use crate::{
    Error,
    audit::Actor,
    binding::{
        model::{Binding, BindingRequest, PrincipalRef, RoleRequest},
        service::BindingService,
    },
    user::service::UserService,
};
use actix_web::{
    HttpResponse, Responder, delete, get,
    http::header::{self, ETag, EntityTag, IfMatch},
    put, web,
};
use sea_orm::TransactionTrait;
use trustify_auth::{ManageTenancy, authenticator::user::UserInformation, authorizer::Require};
use trustify_common::{db, endpoints::extract_revision, model::Revisioned};

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig) {
    config
        .service(list)
        .service(replace)
        .service(set_user)
        .service(remove_user)
        .service(set_team)
        .service(remove_team);
}

fn etag(revision: String) -> (header::HeaderName, ETag) {
    (header::ETAG, ETag(EntityTag::new_strong(revision)))
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "listGroupBindings",
    params(
        ("group", Path, description = "The ID of the SBOM group, or `ext:<external id>`"),
    ),
    responses(
        (status = 200, description = "The role bindings directly on the group", body = Vec<Binding>, headers(("etag" = String, description = "Revision of the bindings"))),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The group was not found"),
    )
)]
#[get("/v3/group/sbom/{group}/binding")]
/// List the role bindings directly on an SBOM group
async fn list(
    service: web::Data<BindingService>,
    db: web::Data<db::ReadOnly>,
    group: web::Path<String>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    Ok(match service.list(&group, &tx).await? {
        Some(Revisioned { value, revision }) => {
            HttpResponse::Ok().append_header(etag(revision)).json(value)
        }
        None => HttpResponse::NotFound().finish(),
    })
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "replaceGroupBindings",
    request_body = Vec<BindingRequest>,
    params(
        ("group", Path, description = "The ID of the SBOM group, or `ext:<external id>`"),
        ("if-match" = Option<String>, Header, description = "The revision of the bindings to replace"),
    ),
    responses(
        (status = 204, description = "The role bindings were replaced", headers(("etag" = String, description = "Revision of the bindings"))),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The group was not found"),
        (status = 412, description = "The provided If-Match revision did not match the actual revision"),
    )
)]
#[put("/v3/group/sbom/{group}/binding")]
#[allow(clippy::too_many_arguments)]
/// Replace all role bindings directly on an SBOM group
///
/// Users which are not yet known will be created as invited.
async fn replace(
    service: web::Data<BindingService>,
    users: web::Data<UserService>,
    db: web::Data<db::ReadWrite>,
    group: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    user: UserInformation,
    web::Json(request): web::Json<Vec<BindingRequest>>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let Revisioned { revision, .. } = service
        .replace(
            &group,
            request,
            extract_revision(&if_match),
            &users,
            &Actor::from(&user),
            &tx,
        )
        .await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent()
        .append_header(etag(revision))
        .finish())
}

async fn set(
    service: &BindingService,
    users: &UserService,
    db: &db::ReadWrite,
    group: &str,
    principal: PrincipalRef,
    role: RoleRequest,
    user: &UserInformation,
) -> Result<HttpResponse, Error> {
    let tx = db.begin().await?;
    service
        .set(group, &principal, role.role, users, &Actor::from(user), &tx)
        .await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent().finish())
}

async fn remove(
    service: &BindingService,
    db: &db::ReadWrite,
    group: &str,
    principal: PrincipalRef,
    user: &UserInformation,
) -> Result<HttpResponse, Error> {
    let tx = db.begin().await?;
    service
        .remove(group, &principal, &Actor::from(user), &tx)
        .await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "setGroupUserBinding",
    request_body = RoleRequest,
    params(
        ("group", Path, description = "The ID of the SBOM group, or `ext:<external id>`"),
        ("email", Path, description = "The e-mail address of the user"),
    ),
    responses(
        (status = 204, description = "The role was granted"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The group was not found"),
    )
)]
#[put("/v3/group/sbom/{group}/binding/user/{email}")]
/// Grant a role to a user on an SBOM group
///
/// A user which is not yet known will be created as invited.
async fn set_user(
    service: web::Data<BindingService>,
    users: web::Data<UserService>,
    db: web::Data<db::ReadWrite>,
    path: web::Path<(String, String)>,
    user: UserInformation,
    web::Json(role): web::Json<RoleRequest>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let (group, email) = path.into_inner();
    set(
        &service,
        &users,
        &db,
        &group,
        PrincipalRef::User(email),
        role,
        &user,
    )
    .await
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "removeGroupUserBinding",
    params(
        ("group", Path, description = "The ID of the SBOM group, or `ext:<external id>`"),
        ("email", Path, description = "The e-mail address of the user"),
    ),
    responses(
        (status = 204, description = "The user holds no role on the group"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    )
)]
#[delete("/v3/group/sbom/{group}/binding/user/{email}")]
/// Remove the role of a user on an SBOM group
async fn remove_user(
    service: web::Data<BindingService>,
    db: web::Data<db::ReadWrite>,
    path: web::Path<(String, String)>,
    user: UserInformation,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let (group, email) = path.into_inner();
    remove(&service, &db, &group, PrincipalRef::User(email), &user).await
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "setGroupTeamBinding",
    request_body = RoleRequest,
    params(
        ("group", Path, description = "The ID of the SBOM group, or `ext:<external id>`"),
        ("team", Path, description = "The ID of the team, or `ext:<external id>`"),
    ),
    responses(
        (status = 204, description = "The role was granted"),
        (status = 400, description = "The request was not valid, or the team does not exist"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The group was not found"),
    )
)]
#[put("/v3/group/sbom/{group}/binding/team/{team}")]
/// Grant a role to a team on an SBOM group
async fn set_team(
    service: web::Data<BindingService>,
    users: web::Data<UserService>,
    db: web::Data<db::ReadWrite>,
    path: web::Path<(String, String)>,
    user: UserInformation,
    web::Json(role): web::Json<RoleRequest>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let (group, team) = path.into_inner();
    set(
        &service,
        &users,
        &db,
        &group,
        PrincipalRef::Team(team),
        role,
        &user,
    )
    .await
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "removeGroupTeamBinding",
    params(
        ("group", Path, description = "The ID of the SBOM group, or `ext:<external id>`"),
        ("team", Path, description = "The ID of the team, or `ext:<external id>`"),
    ),
    responses(
        (status = 204, description = "The team holds no role on the group"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    )
)]
#[delete("/v3/group/sbom/{group}/binding/team/{team}")]
/// Remove the role of a team on an SBOM group
async fn remove_team(
    service: web::Data<BindingService>,
    db: web::Data<db::ReadWrite>,
    path: web::Path<(String, String)>,
    user: UserInformation,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let (group, team) = path.into_inner();
    remove(&service, &db, &group, PrincipalRef::Team(team), &user).await
}
