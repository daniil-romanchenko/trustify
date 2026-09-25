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
    authz::ManageAccess,
};
use actix_web::{
    HttpRequest, HttpResponse, Responder, delete, get, http::header, patch, post, web,
};
use sea_orm::{ConnectionTrait, TransactionTrait};
use trustify_auth::authenticator::user::UserInformation;
use trustify_common::{
    db,
    model::{Paginated, PaginatedResults},
    resource_key::ResourceKey,
};
use uuid::Uuid;

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
    manage: ManageAccess,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    for group in &request.groups {
        manage.require_group(group, &tx).await?;
    }
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
    manage: ManageAccess,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    // delegated admins must list the keys of a group they manage
    match &options.group {
        Some(group) => manage.require_group(group, &tx).await?,
        None => manage.require_global()?,
    }
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
    manage: ManageAccess,
) -> Result<impl Responder, Error> {
    let key: ResourceKey = key.parse()?;
    let tx = db.begin().await?;
    Ok(match service.read(&key, &tx).await? {
        Some(key) if require_key(&manage, &key).is_ok() => HttpResponse::Ok().json(key),
        _ => HttpResponse::NotFound().finish(),
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
    manage: ManageAccess,
) -> Result<impl Responder, Error> {
    let key: ResourceKey = key.parse()?;
    let tx = db.begin().await?;
    require_existing_key(&service, &manage, &key, &tx).await?;
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
    manage: ManageAccess,
) -> Result<impl Responder, Error> {
    let key: ResourceKey = key.parse()?;
    let tx = db.begin().await?;
    require_existing_key(&service, &manage, &key, &tx).await?;
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
    manage: ManageAccess,
) -> Result<impl Responder, Error> {
    let key: ResourceKey = key.parse()?;
    let tx = db.begin().await?;
    // an unknown, or unmanaged, key is handled like one which doesn't exist
    match service.read(&key, &tx).await? {
        Some(existing) if require_key(&manage, &existing).is_ok() => {
            service.revoke(&key, &Actor::from(&user), &tx).await?;
        }
        _ => return Ok(HttpResponse::NoContent().finish()),
    }
    tx.commit().await?;
    validator.invalidate();

    Ok(HttpResponse::NoContent().finish())
}

/// Ensure the caller may manage all groups of a key.
fn require_key(manage: &ManageAccess, key: &ApiKey) -> Result<(), Error> {
    if manage.is_global() {
        return Ok(());
    }

    let groups = key
        .groups
        .iter()
        .filter_map(|group| Uuid::parse_str(group).ok())
        .collect::<Vec<_>>();
    manage.require_groups(&groups)
}

/// Ensure a key exists, and the caller may manage all of its groups.
///
/// For delegated access, a key which isn't managed is reported as not found.
async fn require_existing_key(
    service: &ApiKeyService,
    manage: &ManageAccess,
    key: &ResourceKey,
    db: &impl ConnectionTrait,
) -> Result<(), Error> {
    match service.read(key, db).await? {
        Some(existing) if require_key(manage, &existing).is_ok() => Ok(()),
        _ => Err(Error::NotFound(format!("API key '{key}'"))),
    }
}
