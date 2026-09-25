//! Resolving SBOM groups.

use crate::Error;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, FromQueryResult, QueryFilter,
    Statement,
};
use trustify_common::resource_key::{ResourceKey, ResourceKeyError};
use trustify_entity::sbom_group;
use uuid::Uuid;

/// Resolve a group key (ID, or `ext:<external id>`) into the group's ID.
///
/// Returns `None` if the group doesn't exist.
pub async fn resolve_group(key: &str, db: &impl ConnectionTrait) -> Result<Option<Uuid>, Error> {
    let select = sbom_group::Entity::find();
    let select = match key.parse::<ResourceKey>() {
        Ok(ResourceKey::Id(id)) => select.filter(sbom_group::Column::Id.eq(id)),
        Ok(ResourceKey::External(id)) => select.filter(sbom_group::Column::ExternalId.eq(id)),
        // unknown IDs don't exist
        Err(ResourceKeyError::Invalid(_)) => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    Ok(select.one(db).await?.map(|group| group.id))
}

/// Expand groups into themselves, plus all of their descendants.
pub async fn expand_groups(groups: &[Uuid], db: &impl ConnectionTrait) -> Result<Vec<Uuid>, Error> {
    #[derive(FromQueryResult)]
    struct Row {
        id: Uuid,
    }

    if groups.is_empty() {
        return Ok(vec![]);
    }

    let rows = Row::find_by_statement(Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        r#"
            WITH RECURSIVE tree AS (
                SELECT id FROM sbom_group WHERE id = ANY($1)
                UNION
                SELECT g.id FROM sbom_group g JOIN tree t ON g.parent = t.id
            )
            SELECT id FROM tree
        "#,
        [groups.to_vec().into()],
    ))
    .all(db)
    .await?;

    Ok(rows.into_iter().map(|row| row.id).collect())
}
