#[cfg(test)]
mod test;

use crate::{
    Error,
    audit::Actor,
    user::{
        model::{Access, ChangeEmailRequest, User, UserRequest},
        service::UserService,
    },
};
use actix_web::{
    HttpRequest, HttpResponse, Responder, delete, get,
    http::header::{self, ETag, EntityTag, IfMatch},
    post, put, web,
};
use sea_orm::TransactionTrait;
use trustify_auth::{ManageTenancy, authenticator::user::UserInformation, authorizer::Require};
use trustify_common::{
    db::{self, query::Query},
    endpoints::extract_revision,
    model::{Paginated, PaginatedResults, Revisioned},
};

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig) {
    config
        .service(list)
        .service(read)
        .service(upsert)
        .service(delete)
        .service(change_email)
        .service(access);
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "listUsers",
    params(Query, Paginated),
    responses(
        (status = 200, description = "Matching users", body = PaginatedResults<User>),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    )
)]
#[get("/v3/user")]
/// List users
async fn list(
    service: web::Data<UserService>,
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
    operation_id = "getUser",
    params(
        ("email", Path, description = "The e-mail address of the user"),
    ),
    responses(
        (status = 200, description = "The user", body = User, headers(("etag" = String, description = "Revision ID"))),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The user was not found"),
    )
)]
#[get("/v3/user/{email}")]
/// Get a user
async fn read(
    service: web::Data<UserService>,
    db: web::Data<db::ReadOnly>,
    email: web::Path<String>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    Ok(match service.read(&email, &tx).await? {
        Some(Revisioned { value, revision }) => HttpResponse::Ok()
            .append_header((header::ETAG, ETag(EntityTag::new_strong(revision))))
            .json(value),
        None => HttpResponse::NotFound().finish(),
    })
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "putUser",
    request_body = UserRequest,
    params(
        ("email", Path, description = "The e-mail address of the user"),
        ("if-match" = Option<String>, Header, description = "The revision to update"),
    ),
    responses(
        (status = 200, description = "The user was updated", body = User, headers(("etag" = String, description = "Revision ID"))),
        (status = 201, description = "The user was created", body = User, headers(("etag" = String, description = "Revision ID"))),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 409, description = "The external ID is already in use"),
        (status = 412, description = "The provided If-Match revision did not match the actual revision"),
    )
)]
#[put("/v3/user/{email}")]
/// Create or update a user
async fn upsert(
    service: web::Data<UserService>,
    db: web::Data<db::ReadWrite>,
    email: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    user: UserInformation,
    web::Json(request): web::Json<UserRequest>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let (Revisioned { value, revision }, created) = service
        .upsert(
            &email,
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

    Ok(response
        .append_header((header::ETAG, ETag(EntityTag::new_strong(revision))))
        .json(value))
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "deleteUser",
    params(
        ("email", Path, description = "The e-mail address of the user"),
        ("if-match" = Option<String>, Header, description = "The revision to delete"),
    ),
    responses(
        (status = 204, description = "The user was deleted, or did not exist"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 412, description = "The provided If-Match revision did not match the actual revision"),
    )
)]
#[delete("/v3/user/{email}")]
/// Delete a user, including its team memberships and role bindings
async fn delete(
    service: web::Data<UserService>,
    db: web::Data<db::ReadWrite>,
    email: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    user: UserInformation,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    service
        .delete(
            &email,
            extract_revision(&if_match),
            &Actor::from(&user),
            &tx,
        )
        .await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "changeUserEmail",
    request_body = ChangeEmailRequest,
    params(
        ("email", Path, description = "The current e-mail address of the user"),
        ("if-match" = Option<String>, Header, description = "The revision to update"),
    ),
    responses(
        (status = 200, description = "The e-mail address was changed", body = User, headers(
            ("etag" = String, description = "Revision ID"),
            ("location" = String, description = "The new location of the user"),
        )),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The user was not found"),
        (status = 409, description = "The new e-mail address is already in use"),
        (status = 412, description = "The provided If-Match revision did not match the actual revision"),
    )
)]
#[post("/v3/user/{email}/change-email")]
#[allow(clippy::too_many_arguments)]
/// Change the e-mail address of a user
async fn change_email(
    req: HttpRequest,
    service: web::Data<UserService>,
    db: web::Data<db::ReadWrite>,
    email: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    user: UserInformation,
    web::Json(request): web::Json<ChangeEmailRequest>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let Revisioned { value, revision } = service
        .change_email(
            &email,
            &request.new_email,
            extract_revision(&if_match),
            &Actor::from(&user),
            &tx,
        )
        .await?;
    tx.commit().await?;

    let location = req
        .path()
        .rsplit_once('/')
        .and_then(|(base, _)| base.rsplit_once('/'))
        .map(|(base, _)| format!("{base}/{}", value.email))
        .unwrap_or_default();

    Ok(HttpResponse::Ok()
        .append_header((header::ETAG, ETag(EntityTag::new_strong(revision))))
        .append_header((header::LOCATION, location))
        .json(value))
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "getUserAccess",
    params(
        ("email", Path, description = "The e-mail address of the user"),
    ),
    responses(
        (status = 200, description = "The role bindings applying to the user", body = Vec<Access>),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The user was not found"),
    )
)]
#[get("/v3/user/{email}/access")]
/// Get the role bindings applying to a user, directly or through teams
async fn access(
    service: web::Data<UserService>,
    db: web::Data<db::ReadOnly>,
    email: web::Path<String>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    Ok(match service.access(&email, &tx).await? {
        Some(access) => HttpResponse::Ok().json(access),
        None => HttpResponse::NotFound().finish(),
    })
}
