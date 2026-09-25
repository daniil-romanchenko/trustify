#[cfg(test)]
mod test;

use crate::{
    Error,
    audit::Actor,
    team::{
        model::{Member, MembersPatch, MembersRequest, Team, TeamRequest},
        service::TeamService,
    },
    user::service::UserService,
};
use actix_web::{
    HttpRequest, HttpResponse, Responder, delete, get,
    http::header::{self, ETag, EntityTag, IfMatch},
    patch, post, put, web,
};
use sea_orm::TransactionTrait;
use trustify_auth::{ManageTenancy, authenticator::user::UserInformation, authorizer::Require};
use trustify_common::{
    db::{self, query::Query},
    endpoints::extract_revision,
    model::{Paginated, PaginatedResults, Revisioned},
    resource_key::ResourceKey,
};

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig) {
    config
        .service(list)
        .service(create)
        .service(read)
        .service(upsert)
        .service(delete)
        .service(list_members)
        .service(set_members)
        .service(patch_members)
        .service(add_member)
        .service(remove_member);
}

fn etag(revision: String) -> (header::HeaderName, ETag) {
    (header::ETAG, ETag(EntityTag::new_strong(revision)))
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "listTeams",
    params(Query, Paginated),
    responses(
        (status = 200, description = "Matching teams", body = PaginatedResults<Team>),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    )
)]
#[get("/v3/team")]
/// List teams
async fn list(
    service: web::Data<TeamService>,
    db: web::Data<db::ReadOnly>,
    web::Query(query): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    Ok(HttpResponse::Ok().json(service.list(query, paginated, &tx).await?))
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "createTeam",
    request_body = TeamRequest,
    responses(
        (status = 201, description = "The team was created", body = Team, headers(
            ("etag" = String, description = "Revision ID"),
            ("location" = String, description = "The relative URL to the created resource"),
        )),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 409, description = "The external ID is already in use"),
    )
)]
#[post("/v3/team")]
/// Create a team
async fn create(
    req: HttpRequest,
    service: web::Data<TeamService>,
    db: web::Data<db::ReadWrite>,
    user: UserInformation,
    web::Json(request): web::Json<TeamRequest>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let Revisioned { value, revision } = service.create(request, &Actor::from(&user), &tx).await?;
    tx.commit().await?;

    Ok(HttpResponse::Created()
        .append_header((header::LOCATION, format!("{}/{}", req.path(), value.id)))
        .append_header(etag(revision))
        .json(value))
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "getTeam",
    params(
        ("key", Path, description = "The ID of the team, or `ext:<external id>`"),
    ),
    responses(
        (status = 200, description = "The team", body = Team, headers(("etag" = String, description = "Revision ID"))),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The team was not found"),
    )
)]
#[get("/v3/team/{key}")]
/// Get a team
async fn read(
    service: web::Data<TeamService>,
    db: web::Data<db::ReadOnly>,
    key: web::Path<String>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let key: ResourceKey = key.parse()?;
    let tx = db.begin().await?;
    Ok(match service.read(&key, &tx).await? {
        Some(Revisioned { value, revision }) => {
            HttpResponse::Ok().append_header(etag(revision)).json(value)
        }
        None => HttpResponse::NotFound().finish(),
    })
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "putTeam",
    request_body = TeamRequest,
    params(
        ("key", Path, description = "The ID of the team, or `ext:<external id>`"),
        ("if-match" = Option<String>, Header, description = "The revision to update"),
    ),
    responses(
        (status = 200, description = "The team was updated", body = Team, headers(("etag" = String, description = "Revision ID"))),
        (status = 201, description = "The team was addressed by external ID and has been created", body = Team, headers(("etag" = String, description = "Revision ID"))),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The team was addressed by ID and was not found"),
        (status = 409, description = "The external ID is already in use"),
        (status = 412, description = "The provided If-Match revision did not match the actual revision"),
    )
)]
#[put("/v3/team/{key}")]
/// Update a team, or create it when addressed by an external ID
async fn upsert(
    service: web::Data<TeamService>,
    db: web::Data<db::ReadWrite>,
    key: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    user: UserInformation,
    web::Json(request): web::Json<TeamRequest>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let key: ResourceKey = key.parse()?;
    let tx = db.begin().await?;
    let (Revisioned { value, revision }, created) = service
        .upsert(
            &key,
            request,
            extract_revision(&if_match),
            &Actor::from(&user),
            &tx,
        )
        .await?;
    tx.commit().await?;

    let mut response = if created {
        HttpResponse::Created()
    } else {
        HttpResponse::Ok()
    };
    Ok(response.append_header(etag(revision)).json(value))
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "deleteTeam",
    params(
        ("key", Path, description = "The ID of the team, or `ext:<external id>`"),
        ("if-match" = Option<String>, Header, description = "The revision to delete"),
    ),
    responses(
        (status = 204, description = "The team was deleted, or did not exist"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 412, description = "The provided If-Match revision did not match the actual revision"),
    )
)]
#[delete("/v3/team/{key}")]
/// Delete a team, including its memberships and role bindings
async fn delete(
    service: web::Data<TeamService>,
    db: web::Data<db::ReadWrite>,
    key: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    user: UserInformation,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let key: ResourceKey = key.parse()?;
    let tx = db.begin().await?;
    service
        .delete(&key, extract_revision(&if_match), &Actor::from(&user), &tx)
        .await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "listTeamMembers",
    params(
        ("key", Path, description = "The ID of the team, or `ext:<external id>`"),
        Paginated,
    ),
    responses(
        (status = 200, description = "The members of the team", body = PaginatedResults<Member>, headers(("etag" = String, description = "Revision ID of the team"))),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The team was not found"),
    )
)]
#[get("/v3/team/{key}/member")]
/// List the members of a team
async fn list_members(
    service: web::Data<TeamService>,
    db: web::Data<db::ReadOnly>,
    key: web::Path<String>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let key: ResourceKey = key.parse()?;
    let tx = db.begin().await?;
    Ok(match service.members(&key, paginated, &tx).await? {
        Some(Revisioned { value, revision }) => {
            HttpResponse::Ok().append_header(etag(revision)).json(value)
        }
        None => HttpResponse::NotFound().finish(),
    })
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "setTeamMembers",
    request_body = MembersRequest,
    params(
        ("key", Path, description = "The ID of the team, or `ext:<external id>`"),
        ("if-match" = Option<String>, Header, description = "The revision of the team to update"),
    ),
    responses(
        (status = 204, description = "The members were replaced", headers(("etag" = String, description = "Revision ID of the team"))),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The team was not found"),
        (status = 412, description = "The provided If-Match revision did not match the actual revision"),
    )
)]
#[put("/v3/team/{key}/member")]
#[allow(clippy::too_many_arguments)]
/// Replace all members of a team
async fn set_members(
    service: web::Data<TeamService>,
    users: web::Data<UserService>,
    db: web::Data<db::ReadWrite>,
    key: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    user: UserInformation,
    web::Json(request): web::Json<MembersRequest>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let key: ResourceKey = key.parse()?;
    let tx = db.begin().await?;
    let Revisioned { revision, .. } = service
        .set_members(
            &key,
            request.emails,
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

#[utoipa::path(
    tag = "tenancy",
    operation_id = "patchTeamMembers",
    request_body = MembersPatch,
    params(
        ("key", Path, description = "The ID of the team, or `ext:<external id>`"),
        ("if-match" = Option<String>, Header, description = "The revision of the team to update"),
    ),
    responses(
        (status = 204, description = "The members were updated", headers(("etag" = String, description = "Revision ID of the team"))),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The team was not found"),
        (status = 412, description = "The provided If-Match revision did not match the actual revision"),
    )
)]
#[patch("/v3/team/{key}/member")]
#[allow(clippy::too_many_arguments)]
/// Add and remove members of a team
async fn patch_members(
    service: web::Data<TeamService>,
    users: web::Data<UserService>,
    db: web::Data<db::ReadWrite>,
    key: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    user: UserInformation,
    web::Json(request): web::Json<MembersPatch>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let key: ResourceKey = key.parse()?;
    let tx = db.begin().await?;
    let Revisioned { revision, .. } = service
        .patch_members(
            &key,
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

#[utoipa::path(
    tag = "tenancy",
    operation_id = "addTeamMember",
    params(
        ("key", Path, description = "The ID of the team, or `ext:<external id>`"),
        ("email", Path, description = "The e-mail address of the user"),
    ),
    responses(
        (status = 204, description = "The user is a member of the team", headers(("etag" = String, description = "Revision ID of the team"))),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The team was not found"),
    )
)]
#[put("/v3/team/{key}/member/{email}")]
/// Add a member to a team
async fn add_member(
    service: web::Data<TeamService>,
    users: web::Data<UserService>,
    db: web::Data<db::ReadWrite>,
    path: web::Path<(String, String)>,
    user: UserInformation,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let (key, email) = path.into_inner();
    let key: ResourceKey = key.parse()?;
    let patch = MembersPatch {
        add: vec![email],
        ..Default::default()
    };

    let tx = db.begin().await?;
    let Revisioned { revision, .. } = service
        .patch_members(&key, patch, None, &users, &Actor::from(&user), &tx)
        .await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent()
        .append_header(etag(revision))
        .finish())
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "removeTeamMember",
    params(
        ("key", Path, description = "The ID of the team, or `ext:<external id>`"),
        ("email", Path, description = "The e-mail address of the user"),
    ),
    responses(
        (status = 204, description = "The user is not a member of the team", headers(("etag" = String, description = "Revision ID of the team"))),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The team was not found"),
    )
)]
#[delete("/v3/team/{key}/member/{email}")]
/// Remove a member from a team
async fn remove_member(
    service: web::Data<TeamService>,
    users: web::Data<UserService>,
    db: web::Data<db::ReadWrite>,
    path: web::Path<(String, String)>,
    user: UserInformation,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let (key, email) = path.into_inner();
    let key: ResourceKey = key.parse()?;
    let patch = MembersPatch {
        remove: vec![email],
        ..Default::default()
    };

    let tx = db.begin().await?;
    let Revisioned { revision, .. } = service
        .patch_members(&key, patch, None, &users, &Actor::from(&user), &tx)
        .await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent()
        .append_header(etag(revision))
        .finish())
}
