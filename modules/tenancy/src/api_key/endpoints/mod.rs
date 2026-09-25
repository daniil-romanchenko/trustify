#[cfg(test)]
mod test;

use crate::{
    Error,
    api_key::{
        model::{ApiKey, ApiKeyPatch, ApiKeyRequest, IssuedApiKey, RotateRequest},
        service::{ApiKeyService, ListOptions},
        validator::ApiKeyValidator,
    },
    audit::Actor,
};
use actix_web::{
    HttpRequest, HttpResponse, Responder, delete, get, http::header, patch, post, web,
};
use sea_orm::TransactionTrait;
use trustify_auth::{ManageTenancy, authenticator::user::UserInformation, authorizer::Require};
use trustify_common::{
    db,
    model::{Paginated, PaginatedResults},
    resource_key::ResourceKey,
};

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig) {
    config
        .service(create)
        .service(list)
        .service(read)
        .service(update)
        .service(rotate)
        .service(revoke);
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "createApiKey",
    request_body = ApiKeyRequest,
    responses(
        (status = 201, description = "The API key was created. The response contains the token, which cannot be retrieved later.", body = IssuedApiKey, headers(
            ("location" = String, description = "The relative URL to the created resource"),
        )),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 409, description = "The external ID is already in use"),
        (status = 503, description = "API keys are disabled"),
    )
)]
#[post("/v3/api-key")]
/// Create an API key
async fn create(
    req: HttpRequest,
    service: web::Data<ApiKeyService>,
    db: web::Data<db::ReadWrite>,
    user: UserInformation,
    web::Json(request): web::Json<ApiKeyRequest>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let issued = service.create(request, &Actor::from(&user), &tx).await?;
    tx.commit().await?;

    Ok(HttpResponse::Created()
        .append_header((
            header::LOCATION,
            format!("{}/{}", req.path(), issued.key.id),
        ))
        .append_header((header::CACHE_CONTROL, "no-store"))
        .json(issued))
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "listApiKeys",
    params(ListOptions, Paginated),
    responses(
        (status = 200, description = "Matching API keys, without their tokens", body = PaginatedResults<ApiKey>),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    )
)]
#[get("/v3/api-key")]
/// List API keys
async fn list(
    service: web::Data<ApiKeyService>,
    db: web::Data<db::ReadOnly>,
    web::Query(options): web::Query<ListOptions>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    Ok(HttpResponse::Ok().json(service.list(options, paginated, &tx).await?))
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "getApiKey",
    params(
        ("key", Path, description = "The ID of the API key, or `ext:<external id>`"),
    ),
    responses(
        (status = 200, description = "The API key, without its token", body = ApiKey),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The API key was not found"),
    )
)]
#[get("/v3/api-key/{key}")]
/// Get an API key
async fn read(
    service: web::Data<ApiKeyService>,
    db: web::Data<db::ReadOnly>,
    key: web::Path<String>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let key: ResourceKey = key.parse()?;
    let tx = db.begin().await?;
    Ok(match service.read(&key, &tx).await? {
        Some(key) => HttpResponse::Ok().json(key),
        None => HttpResponse::NotFound().finish(),
    })
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "updateApiKey",
    request_body = ApiKeyPatch,
    params(
        ("key", Path, description = "The ID of the API key, or `ext:<external id>`"),
    ),
    responses(
        (status = 200, description = "The API key was updated", body = ApiKey),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The API key was not found"),
    )
)]
#[patch("/v3/api-key/{key}")]
/// Change the name or labels of an API key
async fn update(
    service: web::Data<ApiKeyService>,
    validator: web::Data<ApiKeyValidator>,
    db: web::Data<db::ReadWrite>,
    key: web::Path<String>,
    user: UserInformation,
    web::Json(patch): web::Json<ApiKeyPatch>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let key: ResourceKey = key.parse()?;
    let tx = db.begin().await?;
    let result = service.patch(&key, patch, &Actor::from(&user), &tx).await?;
    tx.commit().await?;
    validator.invalidate();

    Ok(HttpResponse::Ok().json(result))
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "rotateApiKey",
    request_body = RotateRequest,
    params(
        ("key", Path, description = "The ID of the API key, or `ext:<external id>`"),
    ),
    responses(
        (status = 201, description = "A new API key was created, replacing the old one after the grace period. The response contains the token, which cannot be retrieved later.", body = IssuedApiKey, headers(
            ("location" = String, description = "The relative URL to the created resource"),
        )),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The API key was not found"),
        (status = 409, description = "The API key is not active"),
        (status = 503, description = "API keys are disabled"),
    )
)]
#[post("/v3/api-key/{key}/rotate")]
#[allow(clippy::too_many_arguments)]
/// Rotate an API key
async fn rotate(
    req: HttpRequest,
    service: web::Data<ApiKeyService>,
    validator: web::Data<ApiKeyValidator>,
    db: web::Data<db::ReadWrite>,
    key: web::Path<String>,
    user: UserInformation,
    web::Json(request): web::Json<RotateRequest>,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let key: ResourceKey = key.parse()?;
    let tx = db.begin().await?;
    let issued = service
        .rotate(&key, request, &Actor::from(&user), &tx)
        .await?;
    tx.commit().await?;
    validator.invalidate();

    let location = req
        .path()
        .strip_suffix("/rotate")
        .and_then(|path| path.rsplit_once('/'))
        .map(|(base, _)| format!("{base}/{}", issued.key.id))
        .unwrap_or_default();

    Ok(HttpResponse::Created()
        .append_header((header::LOCATION, location))
        .append_header((header::CACHE_CONTROL, "no-store"))
        .json(issued))
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "revokeApiKey",
    params(
        ("key", Path, description = "The ID of the API key, or `ext:<external id>`"),
    ),
    responses(
        (status = 204, description = "The API key was revoked, or did not exist"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    )
)]
#[delete("/v3/api-key/{key}")]
/// Revoke an API key
async fn revoke(
    service: web::Data<ApiKeyService>,
    validator: web::Data<ApiKeyValidator>,
    db: web::Data<db::ReadWrite>,
    key: web::Path<String>,
    user: UserInformation,
    _: Require<ManageTenancy>,
) -> Result<impl Responder, Error> {
    let key: ResourceKey = key.parse()?;
    let tx = db.begin().await?;
    service.revoke(&key, &Actor::from(&user), &tx).await?;
    tx.commit().await?;
    validator.invalidate();

    Ok(HttpResponse::NoContent().finish())
}
