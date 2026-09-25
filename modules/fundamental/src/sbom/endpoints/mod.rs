mod config;
mod label;
mod query;
#[cfg(test)]
mod test;

pub use query::*;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::{
    Error,
    common::{
        LicenseRefMapping,
        access::{can_access, require_group, require_sbom, visible_groups},
    },
    license::{
        get_sanitize_filename,
        service::{LicenseService, license_export::LicenseExporter},
    },
    sbom::{
        model::{
            SbomExternalPackageReference, SbomModel, SbomNodeReference, SbomPackage,
            SbomPackageRelation, SbomSummary, Which, details::SbomAdvisory,
        },
        service::{SbomService, sbom::FetchOptions},
    },
    sbom_group::service::SbomGroupService,
};
use actix_web::{HttpResponse, Responder, delete, get, http::header, post, web};
use config::Config;
use futures_util::TryStreamExt;
use sea_orm::TransactionTrait;
use serde_qs::actix::QsQuery;
use std::{collections::HashSet, str::FromStr};
use trustify_auth::{
    CreateSbom, DeleteSbom, Permission, ReadAdvisory, ReadSbom, all,
    authenticator::{
        error::AuthorizationError,
        user::{UserDetails, UserInformation},
    },
    authorizer::{AccessScope, Authorizer, Require},
};
use trustify_common::{
    db::{self, pagination_cache::PaginationCache, query::Query},
    decompress::decompress_async,
    id::Id,
    model::{BinaryData, Paginated, PaginatedResults},
};
use trustify_entity::{labels::Labels, relationship::Relationship};
use trustify_module_ingestor::{
    model::IngestResult,
    service::{Cache, Format, IngestorService},
};
use trustify_module_storage::service::{StorageBackend, StorageKey};

#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Deserialize, IntoParams)]
pub struct ModelGetParams {
    /// Include SBOM counts for each model
    #[serde(default)]
    pub counts: bool,
}

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db_rw: db::ReadWrite,
    db_ro: db::ReadOnly,
    upload_limit: usize,
    cache: PaginationCache,
) {
    let sbom_service = SbomService::new(cache);

    config
        .app_data(web::Data::new(db_rw))
        .app_data(web::Data::new(db_ro))
        .app_data(web::Data::new(sbom_service))
        .app_data(web::Data::new(Config { upload_limit }))
        .service(v2::all)
        .service(v3::all)
        .service(all_related)
        .service(count_related)
        .service(all_models)
        .service(get)
        .service(get_sbom_advisories)
        .service(delete)
        .service(delete_many)
        .service(packages)
        .service(models)
        .service(related)
        .service(upload)
        .service(download)
        .service(label::set)
        .service(label::update)
        .service(label::all)
        .service(get_unique_licenses)
        .service(get_license_export);
}

const CONTENT_TYPE_GZIP: &str = "application/gzip";

#[utoipa::path(
    tag = "sbom",
    operation_id = "listAllLicenseIds",
    params(
        ("id", Path, description = "ID of the SBOM to get the license IDs for"),
    ),
    responses(
        (status = 200, description = "fetch all unique license id and license info id", body = Vec<LicenseRefMapping>),
        (status = 404, description = "The SBOM could not be found"),
    ),
)]
#[get("/v3/sbom/{id}/all-license-ids")]
pub async fn get_unique_licenses(
    fetcher: web::Data<LicenseService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<String>,
    scope: AccessScope,
    _: Require<ReadSbom>,
) -> Result<impl Responder, Error> {
    let parsed_id = Id::from_str(&id).map_err(Error::IdKey)?;
    let tx = db.begin().await?;
    require_sbom(&scope, Permission::ReadSbom, &parsed_id, &tx).await?;
    let all_licenses_info = fetcher.get_all_license_info(parsed_id, &tx).await?;
    match all_licenses_info {
        Some(all_licenses) => Ok(HttpResponse::Ok().json(all_licenses)),
        None => Ok(HttpResponse::NotFound().into()),
    }
}

#[utoipa::path(
    tag = "sbom",
    operation_id = "getLicenseExport",
    params(
        ("id" = String, Path,),
    ),
    responses(
        (status = 200, description = "license gzip files", body = Vec<u8>, content_type = CONTENT_TYPE_GZIP),
        (status = 404, description = "The document could not be found"),
    ),
)]
#[get("/v3/sbom/{id}/license-export")]
pub async fn get_license_export(
    fetcher: web::Data<LicenseService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<String>,
    scope: AccessScope,
    _: Require<ReadSbom>,
) -> Result<impl Responder, Error> {
    let id = Id::from_str(&id).map_err(Error::IdKey)?;
    let tx = db.begin().await?;
    require_sbom(&scope, Permission::ReadSbom, &id, &tx).await?;

    let license_export_result = fetcher.license_export(id, &tx).await?;
    if let Some(name_group_version) = license_export_result.sbom_name_group_version.clone() {
        let exporter = LicenseExporter::new(
            name_group_version.sbom_id.clone(),
            name_group_version.sbom_name.clone(),
            license_export_result.sbom_package_license,
            license_export_result.extracted_licensing_infos,
        );
        let zip = exporter.generate()?;

        Ok(HttpResponse::Ok()
            .content_type(CONTENT_TYPE_GZIP)
            .append_header((
                "Content-Disposition",
                format!(
                    "attachment; filename=\"{}_licenses.tar.gz\"",
                    get_sanitize_filename(name_group_version.sbom_name)
                ),
            ))
            .body(zip))
    } else {
        Ok(HttpResponse::NotFound().into())
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct GroupFilterQuery {
    /// Filter by group IDs. Only SBOMs assigned to any of the provided groups will be returned.
    /// Can be specified multiple times. Malformed IDs are silently ignored.
    #[serde(default)]
    group: Vec<String>,
}

mod v2 {
    #![allow(deprecated)]
    use super::*;

    /// List SBOMs
    #[utoipa::path(
        tag = "sbom",
        operation_id = "v2/listSboms",
        params(
            Query,
            Paginated,
            GroupFilterQuery,
        ),
        responses(
            (status = 200, description = "Matching SBOMs", body = PaginatedResults<SbomSummary<SbomPackage>>),
        ),
    )]
    #[get("/v2/sbom")]
    #[allow(clippy::too_many_arguments)]
    #[deprecated = "Use the v3 version of this API"]
    pub async fn all(
        fetch: web::Data<SbomService>,
        db: web::Data<db::ReadOnly>,
        web::Query(search): web::Query<Query>,
        web::Query(paginated): web::Query<Paginated>,
        QsQuery(group_filter): QsQuery<GroupFilterQuery>,
        authorizer: web::Data<Authorizer>,
        user: UserInformation,
        scope: AccessScope,
    ) -> Result<impl Responder, Error> {
        authorizer.require(&user, Permission::ReadSbom)?;

        let tx = db.begin().await?;
        let mut options = FetchOptions::default().visible(visible_groups(&scope));
        if !group_filter.group.is_empty() {
            options = options.groups(group_filter.group);
        }

        let result = fetch
            .fetch_sboms::<_, SbomPackage>(search, paginated, options, &tx)
            .await?;

        Ok(HttpResponse::Ok().json(result))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Deserialize, IntoParams)]
pub struct SbomListParams {
    /// Include advisory severity summary per SBOM
    #[serde(default)]
    pub advisories: bool,
}

mod v3 {
    use super::*;
    use crate::sbom::model::SbomPackageSummary;

    /// List SBOMs
    #[utoipa::path(
        tag = "sbom",
        operation_id = "listSboms",
        params(
            Query,
            Paginated,
            GroupFilterQuery,
            SbomListParams,
        ),
        responses(
            (status = 200, description = "Matching SBOMs", body = PaginatedResults<SbomSummary<SbomPackageSummary>>),
        ),
    )]
    #[get("/v3/sbom")]
    #[allow(clippy::too_many_arguments)]
    pub async fn all(
        fetch: web::Data<SbomService>,
        db: web::Data<db::ReadOnly>,
        web::Query(search): web::Query<Query>,
        web::Query(paginated): web::Query<Paginated>,
        web::Query(params): web::Query<SbomListParams>,
        QsQuery(group_filter): QsQuery<GroupFilterQuery>,
        authorizer: web::Data<Authorizer>,
        user: UserInformation,
        scope: AccessScope,
    ) -> Result<impl Responder, Error> {
        authorizer.require(&user, Permission::ReadSbom)?;

        let tx = db.begin().await?;
        let mut options = FetchOptions::default()
            .advisories(params.advisories)
            .visible(visible_groups(&scope));
        if !group_filter.group.is_empty() {
            options = options.groups(group_filter.group);
        }

        let result = fetch
            .fetch_sboms::<_, SbomPackageSummary>(search, paginated, options, &tx)
            .await?;

        Ok(HttpResponse::Ok().json(result))
    }
}

/// Find all SBOMs containing the provided package.
///
/// The package can be provided either via a PURL or using the ID of a package as returned by
/// other APIs, but not both.
#[utoipa::path(
    tag = "sbom",
    operation_id = "listRelatedSboms",
    params(
        Query,
        Paginated,
        ExternalReferenceQuery,
    ),
    responses(
        (status = 200, description = "Matching SBOMs", body = PaginatedResults<SbomSummary>),
    ),
)]
#[get("/v3/sbom/by-package")]
#[allow(clippy::too_many_arguments)]
pub async fn all_related(
    sbom: web::Data<SbomService>,
    db: web::Data<db::ReadOnly>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(all_related): web::Query<ExternalReferenceQuery>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
    scope: AccessScope,
) -> Result<impl Responder, Error> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let id = (&all_related).try_into()?;
    let tx = db.begin().await?;

    let result = sbom
        .find_related_sboms(id, paginated, search, visible_groups(&scope), &tx)
        .await?;

    Ok(HttpResponse::Ok().json(result))
}

/// Count all SBOMs containing the provided packages.
///
/// The packages can be provided either via a PURL or using the ID of a package as returned by
/// other APIs, but not both.
#[utoipa::path(
    tag = "sbom",
    operation_id = "countRelatedSboms",
    params(
        ExternalReferenceQuery,
    ),
    responses(
        (status = 200, description = "Number of matching SBOMs per package", body = Vec<i64>),
    ),
)]
#[get("/v3/sbom/count-by-package")]
pub async fn count_related(
    sbom: web::Data<SbomService>,
    db: web::Data<db::ReadOnly>,
    web::Json(ids): web::Json<Vec<ExternalReferenceQuery>>,
    scope: AccessScope,
    _: Require<ReadSbom>,
) -> Result<impl Responder, Error> {
    let ids = ids
        .iter()
        .map(SbomExternalPackageReference::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    let tx = db.begin().await?;
    let result = sbom
        .count_related_sboms(ids, visible_groups(&scope), &tx)
        .await?;

    Ok(HttpResponse::Ok().json(result))
}

/// Get information about an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "getSbom",
    params(
        ("id" = Id, Path),
    ),
    responses(
        (status = 200, description = "Matching SBOM", body = SbomSummary),
        (status = 404, description = "The SBOM could not be found"),
    ),
)]
#[get("/v3/sbom/{id}")]
pub async fn get(
    fetcher: web::Data<SbomService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<String>,
    scope: AccessScope,
    _: Require<ReadSbom>,
) -> Result<impl Responder, Error> {
    let id = Id::from_str(&id).map_err(Error::IdKey)?;

    let tx = db.begin().await?;
    require_sbom(&scope, Permission::ReadSbom, &id, &tx).await?;

    match fetcher.fetch_sbom_summary(id, &tx).await? {
        Some(v) => Ok(HttpResponse::Ok().json(v)),
        None => Ok(HttpResponse::NotFound().finish()),
    }
}

/// Get advisories for an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "getSbomAdvisories",
    params(
        ("id" = Id, Path),
    ),
    responses(
        (status = 200, description = "Matching SBOM", body = Vec<SbomAdvisory>),
        (status = 404, description = "The SBOM could not be found"),
    ),
)]
#[get("/v3/sbom/{id}/advisory")]
pub async fn get_sbom_advisories(
    fetcher: web::Data<SbomService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<String>,
    scope: AccessScope,
    _: Require<GetSbomAdvisories>,
) -> Result<impl Responder, Error> {
    let id = Id::from_str(&id).map_err(Error::IdKey)?;
    let tx = db.begin().await?;
    require_sbom(&scope, Permission::ReadSbom, &id, &tx).await?;

    let statuses: Vec<String> = vec!["affected".to_string()];
    match fetcher.fetch_sbom_details(id, statuses, &tx).await? {
        Some(v) => Ok(HttpResponse::Ok().json(v.advisories)),
        None => Ok(HttpResponse::NotFound().finish()),
    }
}

all!(GetSbomAdvisories -> ReadSbom, ReadAdvisory);

async fn delete_blobs<T: StorageBackend>(digests: &[String], storage: &T) {
    if let Err(e) = storage
        .delete_many(
            &digests
                .iter()
                .map(|k| StorageKey::from_sha256(k))
                .collect::<Vec<_>>(),
        )
        .await
    {
        log::error!("Failed to remove SBOMs from the storage: {e:#?}");
    }
}

/// Delete an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "deleteSbom",
    params(
        ("id" = Id, Path),
    ),
    responses(
        (status = 204, description = "The SBOM was deleted or did not exist"),
    ),
)]
#[delete("/v3/sbom/{id}")]
pub async fn delete(
    i: web::Data<IngestorService>,
    service: web::Data<SbomService>,
    db: web::Data<db::ReadWrite>,
    id: web::Path<String>,
    scope: AccessScope,
    _: Require<DeleteSbom>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;

    let id = Id::from_str(&id)?;
    // an inaccessible SBOM is handled like one which doesn't exist
    if !can_access(&scope, Permission::DeleteSbom, &id, &tx).await? {
        return Ok(HttpResponse::NoContent().finish());
    }
    if let Some((v, _, _)) = service.fetch_sbom(id, &tx).await?
        && let digests = service.delete_sboms(vec![v.sbom_id], &tx).await?
        && !digests.is_empty()
    {
        tx.commit().await?;
        delete_blobs(&digests, i.storage()).await;
    }
    Ok(HttpResponse::NoContent().finish())
}

/// Delete multiple SBOMs
#[utoipa::path(
    tag = "sbom",
    operation_id = "deleteSboms",
    request_body(
        content = Vec<String>,
        description = "List of ids of SBOMs to be deleted",
        content_type = "application/json",
    ),
    responses(
        (status = 204, description = "Requested SBOMs were deleted or did not exist"),
    ),
)]
#[delete("/v3/sbom")]
pub async fn delete_many(
    i: web::Data<IngestorService>,
    service: web::Data<SbomService>,
    db: web::Data<db::ReadWrite>,
    web::Json(body): web::Json<Vec<String>>,
    scope: AccessScope,
    _: Require<DeleteSbom>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;

    let mut ids: Vec<Uuid> = Vec::new();
    for id in body.into_iter().filter_map(|x| Uuid::try_parse(&x).ok()) {
        // inaccessible SBOMs are handled like ones which don't exist
        if can_access(&scope, Permission::DeleteSbom, &Id::Uuid(id), &tx).await? {
            ids.push(id);
        }
    }

    let digests = service.delete_sboms(ids, &tx).await?;

    if !digests.is_empty() {
        tx.commit().await?;
        delete_blobs(&digests, i.storage()).await;
    }

    Ok(HttpResponse::NoContent().finish())
}

/// Search for packages of an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "listPackages",
    params(
        ("id" = Id, Path, description = "ID of the SBOM to get packages for"),
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Packages", body = PaginatedResults<SbomPackage>),
        (status = 404, description = "The SBOM could not be found"),
    ),
)]
#[get("/v3/sbom/{id}/packages")]
pub async fn packages(
    fetch: web::Data<SbomService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<String>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    scope: AccessScope,
    _: Require<ReadSbom>,
) -> Result<impl Responder, Error> {
    let id = Id::from_str(&id).map_err(Error::IdKey)?;
    let tx = db.begin().await?;
    require_sbom(&scope, Permission::ReadSbom, &id, &tx).await?;

    let Some((sbom, _, _)) = fetch.fetch_sbom(id, &tx).await? else {
        return Ok(HttpResponse::NotFound().finish());
    };

    let result = fetch
        .fetch_sbom_packages(sbom.sbom_id, search, paginated, &tx)
        .await?;

    Ok(HttpResponse::Ok().json(result))
}

/// Search for AI models associated with an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "listModels",
    params(
        ("id", Path, description = "ID of the SBOM to get models for"),
        Query,
        Paginated,
        ModelGetParams,
    ),
    responses(
        (status = 200, description = "AI Models", body = PaginatedResults<SbomModel>),
    ),
)]
#[get("/v3/sbom/{id}/models")]
#[allow(clippy::too_many_arguments)]
pub async fn models(
    fetch: web::Data<SbomService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<Uuid>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(ModelGetParams { counts }): web::Query<ModelGetParams>,
    scope: AccessScope,
    _: Require<ReadSbom>,
) -> Result<impl Responder, Error> {
    let id = id.into_inner();
    let tx = db.begin().await?;
    require_sbom(&scope, Permission::ReadSbom, &Id::Uuid(id), &tx).await?;
    let result = fetch
        .fetch_sbom_models(
            Some(id),
            search,
            paginated,
            counts,
            visible_groups(&scope),
            &tx,
        )
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// Search for all AI models
#[utoipa::path(
    tag = "sbom",
    operation_id = "listAllModels",
    params(
        Query,
        Paginated,
        ModelGetParams,
    ),
    responses(
        (status = 200, description = "AI Models", body = PaginatedResults<SbomModel>),
    ),
)]
#[get("/v3/sbom/models")]
pub async fn all_models(
    fetch: web::Data<SbomService>,
    db: web::Data<db::ReadOnly>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(ModelGetParams { counts }): web::Query<ModelGetParams>,
    scope: AccessScope,
    _: Require<ReadSbom>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let result = fetch
        .fetch_sbom_models(None, search, paginated, counts, visible_groups(&scope), &tx)
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

#[derive(Clone, Debug, serde::Deserialize, utoipa::IntoParams)]
struct RelatedQuery {
    /// The Package to use as reference
    pub reference: Option<String>,
    /// Which side the reference should be on
    #[serde(default)]
    #[param(inline)]
    pub which: Which,
    /// Optional relationship filter
    #[serde(default)]
    pub relationship: Option<Relationship>,
}

/// Search for related packages in an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "listRelatedPackages",
    params(
        ("id" = Id, Path, description = "ID of SBOM to search packages in"),
        RelatedQuery,
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Packages", body = PaginatedResults<SbomPackageRelation<SbomPackage>>),
        (status = 404, description = "The SBOM could not be found"),
    ),
)]
#[get("/v3/sbom/{id}/related")]
#[allow(clippy::too_many_arguments)]
pub async fn related(
    fetch: web::Data<SbomService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<String>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(related): web::Query<RelatedQuery>,
    scope: AccessScope,
    _: Require<ReadSbom>,
) -> Result<impl Responder, Error> {
    let id = Id::from_str(&id).map_err(Error::IdKey)?;
    let tx = db.begin().await?;
    require_sbom(&scope, Permission::ReadSbom, &id, &tx).await?;

    let Some((sbom, _, _)) = fetch.fetch_sbom(id, &tx).await? else {
        return Ok(HttpResponse::NotFound().finish());
    };

    let result: PaginatedResults<SbomPackageRelation<SbomPackage>> = fetch
        .fetch_related_packages(
            sbom.sbom_id,
            search,
            paginated,
            related.which,
            match &related.reference {
                None => SbomNodeReference::All,
                Some(id) => SbomNodeReference::Package(id),
            },
            related.relationship,
            &tx,
        )
        .await?;

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Clone, Debug, serde::Deserialize, utoipa::IntoParams)]
struct UploadQuery {
    /// Optional labels.
    ///
    /// Only use keys with a prefix of `labels.`
    #[serde(flatten, with = "trustify_entity::labels::prefixed")]
    labels: Labels,

    /// The format of the uploaded document.
    #[serde(default = "default_format")]
    #[param(inline)]
    format: Format,

    /// Await loading the document into the analysis graph cache
    #[serde(default)]
    #[param(inline)]
    cache: Cache,

    /// Optional group IDs to assign the SBOM to after ingestion.
    ///
    /// If one or more group IDs are invalid, the upload will fail with 400 Bad Request
    /// and the SBOM will not be ingested.
    #[serde(default)]
    group: Vec<String>,
}

const fn default_format() -> Format {
    Format::SBOM
}

/// Ensure uploads with a scoped access go into groups which allow it.
///
/// Uploads without a group would not be accessible, so at least one group is required.
fn require_upload_groups(scope: &AccessScope, groups: &[String]) -> Result<(), Error> {
    if scope.is_unrestricted() {
        return Ok(());
    }

    if groups.is_empty() {
        return Err(Error::bad_request(
            "Missing group",
            Some("At least one group is required for uploading an SBOM"),
        ));
    }

    for group in groups {
        require_group(scope, Permission::CreateSbom, group)
            .map_err(|_| Error::bad_request("Invalid group", Some(group.clone())))?;
    }

    Ok(())
}

/// Apply the scope of the API key, if the upload was authenticated using one.
///
/// Uploads without groups are assigned to the key's default group. Uploads into groups outside
/// the key's scope are rejected. The key's labels override labels of the request.
fn apply_api_key(
    user: &UserInformation,
    groups: &mut Vec<String>,
    labels: &mut Labels,
) -> Result<(), Error> {
    let UserInformation::Authenticated(UserDetails {
        api_key: Some(key), ..
    }) = user
    else {
        return Ok(());
    };

    if groups.is_empty() {
        groups.extend(key.default_group.clone());
    }

    let allowed: HashSet<Uuid> = key
        .groups
        .iter()
        .filter_map(|group| Uuid::parse_str(group).ok())
        .collect();

    let in_scope = !groups.is_empty()
        && groups
            .iter()
            .all(|group| Uuid::parse_str(group).is_ok_and(|group| allowed.contains(&group)));

    if !in_scope {
        log::info!(
            "API key '{}' is not allowed to upload into groups: {groups:?}",
            key.key_id
        );
        return Err(AuthorizationError::Failed.into());
    }

    labels.0.extend(key.labels.clone());

    Ok(())
}

#[utoipa::path(
    tag = "sbom",
    operation_id = "uploadSbom",
    request_body = Vec <u8>,
    params(
        UploadQuery,
    ),
    responses(
        (status = 201, description = "Upload an SBOM", body = IngestResult),
        (status = 400, description = "The file could not be parsed as an SBOM"),
        (status = 400, description = "One or more group IDs are invalid or do not exist"),
    )
)]
#[post("/v3/sbom")]
#[allow(clippy::too_many_arguments)]
/// Upload a new SBOM
pub async fn upload(
    ingestor: web::Data<IngestorService>,
    sbom_group: web::Data<SbomGroupService>,
    config: web::Data<Config>,
    db: web::Data<db::ReadWrite>,
    QsQuery(UploadQuery {
        mut labels,
        format,
        cache,
        mut group,
    }): QsQuery<UploadQuery>,
    content_type: Option<web::Header<header::ContentType>>,
    bytes: web::Bytes,
    user: UserInformation,
    scope: AccessScope,
    _: Require<CreateSbom>,
) -> Result<impl Responder, Error> {
    apply_api_key(&user, &mut group, &mut labels)?;
    require_upload_groups(&scope, &group)?;

    let format = format
        .ensure_allowed_for(default_format())
        .map_err(Error::Ingestor)?;
    let bytes = decompress_async(bytes, content_type.map(|ct| ct.0), config.upload_limit).await??;

    let tx = db.begin().await?;

    let mut result = ingestor
        .ingest(&bytes, format, labels, None, cache, &tx)
        .await
        .map_err(Error::Ingestor)?;

    if !group.is_empty() {
        sbom_group
            .update_assignments(&result.id, None, group, &tx)
            .await?;
    }

    // Rewrite ID to have the prefix: Although the field is "id" it always carried the ID,
    // but with the `urn:uuid:` prefix. Which was used for "key" fields. Which accepted
    // for than the actual ID. The whole naming is flawed and confusing. But in order to
    // keep the API stable, we need to return the ID with the prefix.
    result.id = format!("urn:uuid:{}", result.id);

    tx.commit().await?;

    log::info!("Uploaded SBOM: {}", result.id);
    Ok(HttpResponse::Created().json(result))
}

/// Download an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "downloadSbom",
    params(
        ("key" = Id, Path, description = "Identifier of the SBOM, either `urn:uuid:<uuid>` or a digest e.g. `sha256:<hex>`"),
    ),
    responses(
        (status = 200, description = "Download a an SBOM", body = inline(BinaryData)),
        (status = 404, description = "The document could not be found"),
    )
)]
#[get("/v3/sbom/{key}/download")]
pub async fn download(
    ingestor: web::Data<IngestorService>,
    db: web::Data<db::ReadOnly>,
    sbom: web::Data<SbomService>,
    key: web::Path<String>,
    scope: AccessScope,
    _: Require<ReadSbom>,
) -> Result<impl Responder, Error> {
    let id = Id::from_str(&key).map_err(Error::IdKey)?;
    let tx = db.begin().await?;
    require_sbom(&scope, Permission::ReadSbom, &id, &tx).await?;

    let Some(sbom) = sbom.fetch_sbom_summary(id, &tx).await? else {
        return Ok(HttpResponse::NotFound().finish());
    };

    let stream = ingestor
        .storage()
        .retrieve(sbom.source_document.try_into()?)
        .await
        .map_err(Error::Storage)?
        .map(|stream| stream.map_err(Error::Storage));

    Ok(match stream {
        Some(s) => HttpResponse::Ok().streaming(s),
        None => HttpResponse::NotFound().finish(),
    })
}
