#[cfg(test)]
mod test;

use super::{
    model::*,
    service::{ListOptions, SbomGroupService},
};
use crate::{
    Error,
    common::access::{require_group, require_sbom, require_unrestricted},
};
use actix_web::{
    HttpRequest, HttpResponse, Responder, delete, get,
    http::header::{self, ETag, EntityTag, IfMatch},
    patch, post, put, web,
};
use sea_orm::{ConnectionTrait, TransactionTrait};
use serde::Serialize;
use serde_json::json;
use trustify_auth::{
    CreateSbomGroup, DeleteSbomGroup, Permission, ReadSbom, ReadSbomGroup, UpdateSbom,
    UpdateSbomGroup,
    authenticator::user::UserInformation,
    authorizer::{AccessScope, Authorizer, Require},
};
use trustify_common::{
    db::{self, pagination_cache::PaginationCache, query::Query},
    endpoints::extract_revision,
    id::Id,
    model::{Paginated, Revisioned},
    resource_key::EXTERNAL_ID_PREFIX,
};
use utoipa::ToSchema;
use uuid::Uuid;

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
    scope: AccessScope,
    _: Require<ReadSbomGroup>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin().await?;
    let visible = scope.groups_with(Permission::ReadSbomGroup);
    let result = service
        .list(options, pagination, query, visible, &tx)
        .await?;

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
    scope: AccessScope,
    _: Require<CreateSbomGroup>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    require_parent(&scope, &service, group.parent.as_deref(), &tx).await?;
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
    scope: AccessScope,
    _: Require<DeleteSbomGroup>,
) -> Result<impl Responder, Error> {
    let revision = extract_revision(&if_match);

    let tx = db.begin().await?;
    // an unknown external ID is handled like any other unknown ID
    let id = service
        .resolve_key(&id, &tx)
        .await?
        .unwrap_or(id.into_inner());
    // an inaccessible group is handled like one which doesn't exist
    if require_group(&scope, Permission::DeleteSbomGroup, &id).is_err() {
        return Ok(HttpResponse::NoContent().finish());
    }
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
    scope: AccessScope,
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
        require_parent(&scope, &service, group.parent.as_deref(), &tx).await?;

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

    require_group(&scope, Permission::UpdateSbomGroup, &resolved)?;
    // moving a group requires the permission to create groups in the new parent
    if let Some(current) = service.read(&resolved, &tx).await?
        && current.value.parent != group.parent
    {
        require_parent(&scope, &service, group.parent.as_deref(), &tx).await?;
    }
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
    scope: AccessScope,
    _: Require<ReadSbomGroup>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin().await?;
    let group = match service.resolve_key(&id, &tx).await? {
        Some(id) if require_group(&scope, Permission::ReadSbomGroup, &id).is_ok() => {
            service.read(&id, &tx).await?
        }
        _ => None,
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
    scope: AccessScope,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin().await?;
    let Ok(sbom_id) = Uuid::parse_str(&id) else {
        return Ok(HttpResponse::NotFound().finish());
    };
    require_sbom(&scope, Permission::ReadSbom, &Id::Uuid(sbom_id), &tx).await?;
    let assignments = service
        .read_assignments(&id, scope.groups_with(Permission::ReadSbom), &tx)
        .await?;

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
    web::Json(mut group_ids): web::Json<Vec<String>>,
    web::Header(if_match): web::Header<IfMatch>,
    scope: AccessScope,
    _: Require<UpdateSbom>,
) -> Result<impl Responder, Error> {
    let revision = extract_revision(&if_match);

    let tx = db.begin().await?;
    if !scope.is_unrestricted() {
        let sbom_id = Uuid::parse_str(&id).map_err(|_| Error::NotFound(id.to_string()))?;
        require_sbom(&scope, Permission::UpdateSbom, &Id::Uuid(sbom_id), &tx).await?;
        require_groups(&scope, &group_ids)?;
        // keep assignments to groups outside the scope
        if let Some(Revisioned { value: current, .. }) =
            service.read_assignments(&id, None, &tx).await?
        {
            group_ids.extend(
                current
                    .into_iter()
                    .filter(|group| require_group(&scope, Permission::UpdateSbom, group).is_err()),
            );
        }
    }
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
    scope: AccessScope,
    _: Require<UpdateSbom>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    match scope.groups_with(Permission::UpdateSbom) {
        None => {
            service
                .bulk_update_assignments(request.sbom_ids, request.group_ids, &tx)
                .await?;
        }
        Some(editable) => {
            require_sboms(&scope, &request.sbom_ids, &tx).await?;
            require_groups(&scope, &request.group_ids)?;
            // replace only within the scope: remove all other editable groups
            let remove = editable
                .iter()
                .map(ToString::to_string)
                .filter(|group| !request.group_ids.contains(group))
                .collect();
            service
                .patch_assignments(request.sbom_ids, request.group_ids, remove, &tx)
                .await?;
        }
    }
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
    scope: AccessScope,
    _: Require<UpdateSbom>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    if !scope.is_unrestricted() {
        require_sboms(&scope, &request.sbom_ids, &tx).await?;
        require_groups(&scope, &request.add)?;
        require_groups(&scope, &request.remove)?;
    }
    service
        .patch_assignments(request.sbom_ids, request.add, request.remove, &tx)
        .await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent().finish())
}

/// Ensure a new parent group allows creating groups in it, or, for top-level groups, that access
/// is unrestricted.
async fn require_parent(
    scope: &AccessScope,
    service: &SbomGroupService,
    parent: Option<&str>,
    db: &impl ConnectionTrait,
) -> Result<(), Error> {
    let Some(parent) = parent else {
        return require_unrestricted(scope);
    };

    match service.resolve_key(parent, db).await? {
        Some(parent) => require_group(scope, Permission::CreateSbomGroup, &parent)
            .map_err(|_| Error::BadRequest("Parent group not found".into(), None)),
        // the service will reject the unknown parent
        None => Ok(()),
    }
}

/// Ensure all groups allow updating SBOM assignments.
fn require_groups(scope: &AccessScope, groups: &[String]) -> Result<(), Error> {
    for group in groups {
        require_group(scope, Permission::UpdateSbom, group)
            .map_err(|_| Error::BadRequest("Group not found".into(), Some(group.clone().into())))?;
    }
    Ok(())
}

/// Ensure all SBOMs, by ID, allow updating them.
async fn require_sboms(
    scope: &AccessScope,
    sbom_ids: &[String],
    db: &impl ConnectionTrait,
) -> Result<(), Error> {
    for sbom_id in sbom_ids {
        let id = Uuid::parse_str(sbom_id).map_err(|_| Error::NotFound(sbom_id.clone()))?;
        require_sbom(scope, Permission::UpdateSbom, &Id::Uuid(id), db).await?;
    }
    Ok(())
}
