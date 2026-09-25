//! Test helpers

use crate::endpoints::configure;
use sea_orm::{ActiveModelTrait, ConnectionTrait, DatabaseBackend, Set, Statement};
use trustify_common::db::{self, pagination_cache::PaginationCache};
use trustify_entity::{labels::Labels, sbom_group};
use trustify_test_context::{TrustifyContext, call::CallService};
use uuid::Uuid;

/// Create a test app, serving the tenancy endpoints.
pub async fn caller(ctx: &TrustifyContext) -> anyhow::Result<impl CallService + '_> {
    let db_rw = db::ReadWrite::new(ctx.db.clone());
    let db_ro = db::ReadOnly::new(ctx.db.clone());

    trustify_test_context::call::caller(|svc| {
        configure(svc, db_rw, db_ro, PaginationCache::for_test())
    })
    .await
}

/// Create an SBOM group, returning its ID.
pub async fn create_group(
    name: &str,
    parent: Option<Uuid>,
    external_id: Option<&str>,
    db: &impl ConnectionTrait,
) -> anyhow::Result<Uuid> {
    let id = Uuid::now_v7();
    sbom_group::ActiveModel {
        id: Set(id),
        parent: Set(parent),
        name: Set(name.into()),
        description: Set(None),
        revision: Set(Uuid::now_v7()),
        labels: Set(Labels::default()),
        kind: Set(None),
        external_id: Set(external_id.map(ToString::to_string)),
    }
    .insert(db)
    .await?;
    Ok(id)
}

/// Get the current authorization revision.
pub async fn authz_revision(db: &impl ConnectionTrait) -> anyhow::Result<i64> {
    let row = db
        .query_one(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT value FROM authz_revision",
        ))
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing authz_revision row"))?;
    Ok(row.try_get("", "value")?)
}
