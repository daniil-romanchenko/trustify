#[cfg(test)]
mod test;

use super::{
    model::*,
    service::{ListOptions, SbomGroupService},
};
use crate::Error;
use actix_web::{
    HttpRequest, HttpResponse, Responder, delete, get,
    http::header::{self, ETag, EntityTag, IfMatch},
    patch, post, put, web,
};
use sea_orm::TransactionTrait;
use serde::Serialize;
use serde_json::json;
use trustify_auth::{
    CreateSbomGroup, DeleteSbomGroup, Permission, ReadSbom, ReadSbomGroup, UpdateSbom,
    UpdateSbomGroup,
    authenticator::user::UserInformation,
    authorizer::{Authorizer, Require},
};
use trustify_common::{
    db::{self, pagination_cache::PaginationCache, query::Query},
    endpoints::extract_revision,
    model::{Paginated, Revisioned},
    resource_key::EXTERNAL_ID_PREFIX,
};
use utoipa::ToSchema;

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db_rw: db::ReadWrite,
    db_ro: db::ReadOnly,
    max_group_name_length: usize,
    cache: PaginationCache,
) {
    let service = SbomGroupService::new(max_group_name_length, cache);

    config
        .app_data(web::Data::new(db_rw))
        .app_data(web::Data::new(db_ro))
        .app_data(web::Data::new(service))
        .service(list)
        .service(create)
        .service(read)
        .service(update)
        .service(delete)
        .service(read_assignments)
        .service(update_assignments)
        .service(bulk_update_assignments)
        .service(patch_assignments);
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "listSbomGroups",
    params(
        ListOptions,
        Paginated,
        Query,
    ),
    responses(
        (
            status = 200, description = "Executed the SBOM group query",
            body = GroupListResult,
        ),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
   )
)]
#[get("/v3/group/sbom")]
/// List SBOM groups
async fn list(
    service: web::Data<SbomGroupService>,
    db: web::Data<db::ReadOnly>,
    web::Query(pagination): web::Query<Paginated>,
    web::Query(options): web::Query<ListOptions>,
    web::Query(query): web::Query<Query>,
    _: Require<ReadSbomGroup>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin().await?;
    let result = service.list(options, pagination, query, &tx).await?;

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Serialize, ToSchema)]
struct CreateResponse {
    /// The ID of the newly created group
    id: String,
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "createSbomGroup",
    request_body = GroupRequest,
    responses(
        (
            status = 201, description = "Created the requested group",
            body = CreateResponse,
            headers(
                ("location" = String, description = "The relative URL to the created resource")
            )
        ),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 409, description = "The name of the group is not unique within the parent"),
    )
)]
#[post("/v3/group/sbom")]
/// Create a new SBOM group
async fn create(
    req: HttpRequest,
    service: web::Data<SbomGroupService>,
    db: web::Data<db::ReadWrite>,
    web::Json(group): web::Json<GroupRequest>,
    _: Require<CreateSbomGroup>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let Revisioned {
        revision,
        value: id,
    } = service.create(group, &tx).await?;
    tx.commit().await?;

    Ok(HttpResponse::Created()
        .append_header((header::LOCATION, format!("{}/{}", req.path(), id)))
        .append_header((header::ETAG, ETag(EntityTag::new_strong(revision))))
        .json(json!({"id": id})))
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "deleteSbomGroup",
    request_body = GroupRequest,
    params(
        ("id", Path, description = "The ID of the group to delete, or `ext:<external id>`"),
        ("if-match" = Option<String>, Header, description = "The revision to delete"),
    ),
    responses(
        (status = 204, description = "The group was deleted or did not exist"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 409, description = "The group has child groups and cannot be deleted"),
        (status = 412, description = "The requested revision is not the current revision of the group"),
    )
)]
#[delete("/v3/group/sbom/{id}")]
/// Delete an SBOM group
async fn delete(
    service: web::Data<SbomGroupService>,
    db: web::Data<db::ReadWrite>,
    id: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    _: Require<DeleteSbomGroup>,
) -> Result<impl Responder, Error> {
    let revision = extract_revision(&if_match);

    let tx = db.begin().await?;
    // an unknown external ID is handled like any other unknown ID
    let id = service
        .resolve_key(&id, &tx)
        .await?
        .unwrap_or(id.into_inner());
    service.delete(&id, revision, &tx).await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "updateSbomGroup",
    request_body = GroupRequest,
    params(
        ("id", Path, description = "The ID of the group to update, or `ext:<external id>`"),
        ("if-match" = Option<String>, Header, description = "The revision to update"),
    ),
    responses(
        (status = 201, description = "The group was addressed by external ID and has been created", body = CreateResponse),
        (status = 204, description = "The group was updated"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The group was not found"),
        (status = 409, description = "The name of the group is not unique within the parent"),
        (status = 409, description = "Assigning the parent would create a cycle"),
        (status = 412, description = "The requested revision is not the current revision of the group"),
    )
)]
#[put("/v3/group/sbom/{id}")]
#[allow(clippy::too_many_arguments)]
/// Update an SBOM group
///
/// When the group is addressed by its external ID (`ext:<external id>`) and does not yet exist,
/// it will be created.
async fn update(
    req: HttpRequest,
    service: web::Data<SbomGroupService>,
    db: web::Data<db::ReadWrite>,
    id: web::Path<String>,
    web::Json(mut group): web::Json<GroupRequest>,
    web::Header(if_match): web::Header<IfMatch>,
    user: UserInformation,
    authorizer: web::Data<Authorizer>,
    _: Require<UpdateSbomGroup>,
) -> Result<impl Responder, Error> {
    let revision = extract_revision(&if_match);
    let id = id.into_inner();

    if let Some(external_id) = id.strip_prefix(EXTERNAL_ID_PREFIX) {
        // addressing by external ID implies the external ID of the group
        match &group.external_id {
            Some(requested) if requested != external_id => {
                return Err(Error::bad_request(
                    "External ID mismatch",
                    Some("The external ID of the request must match the one of the path"),
                ));
            }
            _ => group.external_id = Some(external_id.to_string()),
        }
    }

    let tx = db.begin().await?;

    let Some(resolved) = service.resolve_key(&id, &tx).await? else {
        // external ID, which doesn't exist yet: create it
        if revision.is_some() {
            return Err(Error::RevisionNotFound);
        }
        authorizer.require(&user, Permission::CreateSbomGroup)?;

        let Revisioned {
            revision,
            value: new_id,
        } = service.create(group, &tx).await?;
        tx.commit().await?;

        let location = req
            .path()
            .strip_suffix(&id)
            .map(|base| format!("{base}{new_id}"))
            .unwrap_or_else(|| req.path().to_string());

        return Ok(HttpResponse::Created()
            .append_header((header::LOCATION, location))
            .append_header((header::ETAG, ETag(EntityTag::new_strong(revision))))
            .json(json!({"id": new_id})));
    };

    service.update(&resolved, revision, group, &tx).await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "readSbomGroup",
    params(
        ("id", Path, description = "The ID of the group to read, or `ext:<external id>`"),
    ),
    responses(
        (
            status = 200, description = "The group was found and returned",
            body = Group,
            headers(
                ("etag" = String, description = "Revision ID")
            )
        ),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    )
)]
#[get("/v3/group/sbom/{id}")]
/// Read the SBOM group information
async fn read(
    service: web::Data<SbomGroupService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<String>,
    _: Require<ReadSbomGroup>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin().await?;
    let group = match service.resolve_key(&id, &tx).await? {
        Some(id) => service.read(&id, &tx).await?,
        None => None,
    };

    Ok(match group {
        Some(Revisioned { value, revision }) => HttpResponse::Ok()
            .append_header((header::ETAG, ETag(EntityTag::new_strong(revision))))
            .json(value),
        None => HttpResponse::NotFound().finish(),
    })
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "readSbomGroupAssignments",
    params(
        ("id", Path, description = "The ID of the SBOM"),
    ),
    responses(
        (status = 200, description = "The SBOM was found and assignments returned"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The SBOM was not found"),
    )
)]
#[get("/v3/group/sbom-assignment/{id}")]
/// Get SBOM group assignments
async fn read_assignments(
    service: web::Data<SbomGroupService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<String>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin().await?;
    let assignments = service.read_assignments(&id, &tx).await?;

    Ok(match assignments {
        Some(Revisioned { value, revision }) => HttpResponse::Ok()
            .append_header((header::ETAG, ETag(EntityTag::new_strong(revision))))
            .json(value),
        None => HttpResponse::NotFound().finish(),
    })
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "updateSbomGroupAssignments",
    request_body = Vec<String>,
    params(
        ("id", Path, description = "The ID of the SBOM to update"),
        ("if-match" = Option<String>, Header, description = "The revision of the SBOM assignments"),
    ),
    responses(
        (status = 204, description = "The SBOM assignments were updated"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 412, description = "The requested revision is not the current revision"),
    )
)]
#[put("/v3/group/sbom-assignment/{id}")]
/// Update SBOM group assignments
async fn update_assignments(
    service: web::Data<SbomGroupService>,
    db: web::Data<db::ReadWrite>,
    id: web::Path<String>,
    web::Json(group_ids): web::Json<Vec<String>>,
    web::Header(if_match): web::Header<IfMatch>,
    _: Require<UpdateSbom>,
) -> Result<impl Responder, Error> {
    let revision = extract_revision(&if_match);

    let tx = db.begin().await?;
    service
        .update_assignments(&id, revision, group_ids, &tx)
        .await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "bulkUpdateSbomGroupAssignments",
    request_body = BulkAssignmentRequest,
    responses(
        (status = 204, description = "The SBOM assignments were updated"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    )
)]
#[put("/v3/group/sbom-assignment")]
/// Bulk update SBOM group assignments
async fn bulk_update_assignments(
    service: web::Data<SbomGroupService>,
    db: web::Data<db::ReadWrite>,
    web::Json(request): web::Json<BulkAssignmentRequest>,
    _: Require<UpdateSbom>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    service
        .bulk_update_assignments(request.sbom_ids, request.group_ids, &tx)
        .await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "patchSbomGroupAssignments",
    request_body = PatchAssignmentRequest,
    responses(
        (status = 204, description = "The SBOM assignments were updated"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "One or more SBOMs were not found"),
    )
)]
#[patch("/v3/group/sbom-assignment")]
/// Partially update SBOM group assignments
async fn patch_assignments(
    service: web::Data<SbomGroupService>,
    db: web::Data<db::ReadWrite>,
    web::Json(request): web::Json<PatchAssignmentRequest>,
    _: Require<UpdateSbom>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    service
        .patch_assignments(request.sbom_ids, request.add, request.remove, &tx)
        .await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent().finish())
}
