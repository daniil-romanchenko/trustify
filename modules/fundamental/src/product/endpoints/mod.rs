#[cfg(test)]
mod test;

use crate::{
    Error,
    common::access::visible_sboms,
    product::{
        model::{details::ProductDetails, summary::ProductSummary},
        service::ProductService,
    },
};
use actix_web::{HttpResponse, Responder, delete, get, web};
use sea_orm::TransactionTrait;
use trustify_auth::{
    DeleteMetadata, ReadMetadata,
    authorizer::{AccessScope, Require},
};
use trustify_common::{
    db::{self, pagination_cache::PaginationCache, query::Query},
    model::{Paginated, PaginatedResults},
};
use uuid::Uuid;

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db_rw: db::ReadWrite,
    db_ro: db::ReadOnly,
    cache: PaginationCache,
) {
    let service = ProductService::new(cache);
    config
        .app_data(web::Data::new(db_rw))
        .app_data(web::Data::new(db_ro))
        .app_data(web::Data::new(service))
        .service(all)
        .service(delete)
        .service(get);
}

#[utoipa::path(
    tag = "product",
    operation_id = "listProducts",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching products", body = PaginatedResults<ProductSummary>),
    ),
)]
#[get("/v3/product")]
pub async fn all(
    state: web::Data<ProductService>,
    db: web::Data<db::ReadOnly>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    scope: AccessScope,
    _: Require<ReadMetadata>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let mut result = state.fetch_products(search, paginated, &tx).await?;

    // hide references to inaccessible SBOMs
    let candidates = result.items.iter().flat_map(|product| {
        product
            .versions
            .iter()
            .filter_map(|version| version.sbom_id)
    });
    if let Some(visible) = visible_sboms(&scope, candidates.collect::<Vec<_>>(), &tx).await? {
        for version in result.items.iter_mut().flat_map(|p| p.versions.iter_mut()) {
            if version.sbom_id.is_some_and(|id| !visible.contains(&id)) {
                version.sbom_id = None;
            }
        }
    }

    Ok(HttpResponse::Ok().json(result))
}

#[utoipa::path(
    tag = "product",
    operation_id = "getProduct",
    params(
        ("id", Path, description = "Opaque ID of the product")
    ),
    responses(
        (status = 200, description = "Matching product", body = ProductDetails),
        (status = 404, description = "The product could not be found"),
    ),
)]
#[get("/v3/product/{id}")]
pub async fn get(
    state: web::Data<ProductService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<Uuid>,
    scope: AccessScope,
    _: Require<ReadMetadata>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let fetched = state.fetch_product(*id, &tx).await?;
    if let Some(mut fetched) = fetched {
        // hide references to inaccessible SBOMs
        let candidates = fetched
            .versions
            .iter()
            .filter_map(|version| version.head.sbom_id);
        if let Some(visible) = visible_sboms(&scope, candidates.collect::<Vec<_>>(), &tx).await? {
            for version in &mut fetched.versions {
                if version
                    .head
                    .sbom_id
                    .is_some_and(|id| !visible.contains(&id))
                {
                    version.head.sbom_id = None;
                    version.sbom = None;
                }
            }
        }

        Ok(HttpResponse::Ok().json(fetched))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

#[utoipa::path(
    tag = "product",
    operation_id = "deleteProduct",
    params(
        ("id", Path, description = "Opaque ID of the product")
    ),
    responses(
        (status = 204, description = "The product was deleted or did not exist"),
    ),
)]
#[delete("/v3/product/{id}")]
pub async fn delete(
    state: web::Data<ProductService>,
    db: web::Data<db::ReadWrite>,
    id: web::Path<Uuid>,
    _: Require<DeleteMetadata>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    state.delete_product(*id, &tx).await?;
    tx.commit().await?;
    Ok(HttpResponse::NoContent().finish())
}
