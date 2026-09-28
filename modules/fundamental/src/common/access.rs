//! Enforcing the [`AccessScope`] on SBOMs.
//!
//! When access is scoped, only SBOMs assigned to one of the groups the permission is granted in
//! are accessible. Inaccessible SBOMs are handled as if they didn't exist.

use crate::Error;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter, QuerySelect,
    QueryTrait,
    sea_query::{Expr, IntoColumnRef, SelectStatement, SimpleExpr},
};
use std::collections::{BTreeMap, HashSet};
use trustify_auth::{Permission, authorizer::AccessScope};
use trustify_common::id::{Id, TrySelectForId};
use trustify_entity::{sbom, sbom_group_assignment};
use uuid::Uuid;

/// Query selecting the IDs of all SBOMs assigned to any of the groups.
pub fn sboms_in_groups(groups: Vec<Uuid>) -> SelectStatement {
    sbom_group_assignment::Entity::find()
        .select_only()
        .column(sbom_group_assignment::Column::SbomId)
        .filter(sbom_group_assignment::Column::GroupId.is_in(groups))
        .into_query()
}

/// The IDs of the groups in which SBOMs are visible, `None` if access is unrestricted.
pub fn visible_groups(scope: &AccessScope) -> Option<Vec<Uuid>> {
    scope.groups_with(Permission::ReadSbom)
}

/// Condition limiting a column holding SBOM IDs to accessible SBOMs.
///
/// Returns `None` if access is unrestricted.
pub fn sbom_filter(
    scope: &AccessScope,
    permission: Permission,
    column: impl IntoColumnRef,
) -> Option<SimpleExpr> {
    scope
        .groups_with(permission)
        .map(|groups| Expr::col(column).in_subquery(sboms_in_groups(groups)))
}

/// Check if an SBOM is accessible with the permission.
///
/// If the ID is a digest matching more than one SBOM, one of them being accessible is sufficient.
/// For an SBOM which doesn't exist, this returns `true` when access is unrestricted.
pub async fn can_access(
    scope: &AccessScope,
    permission: Permission,
    id: &Id,
    db: &impl ConnectionTrait,
) -> Result<bool, Error> {
    let Some(groups) = scope.groups_with(permission) else {
        return Ok(true);
    };

    let accessible = sbom::Entity::find()
        .try_filter(id.clone())?
        .filter(sbom::Column::SbomId.in_subquery(sboms_in_groups(groups)))
        .count(db)
        .await?;

    Ok(accessible > 0)
}

/// Ensure an SBOM is accessible with the permission.
///
/// Fails with "not found" otherwise, so that the existence of the SBOM isn't disclosed.
pub async fn require_sbom(
    scope: &AccessScope,
    permission: Permission,
    id: &Id,
    db: &impl ConnectionTrait,
) -> Result<(), Error> {
    if can_access(scope, permission, id, db).await? {
        Ok(())
    } else {
        Err(Error::NotFound(id.to_string()))
    }
}

/// Ensure a group, by ID, allows the permission.
///
/// Fails with "not found" otherwise, so that the existence of the group isn't disclosed.
pub fn require_group(scope: &AccessScope, permission: Permission, id: &str) -> Result<(), Error> {
    let allowed = match scope {
        AccessScope::Unrestricted => true,
        AccessScope::Scoped(_) => {
            Uuid::parse_str(id).is_ok_and(|group| scope.allows(group, permission))
        }
    };

    if allowed {
        Ok(())
    } else {
        Err(Error::NotFound(id.to_string()))
    }
}

/// Ensure new top-level groups may be created, which requires unrestricted access.
pub fn require_unrestricted(scope: &AccessScope) -> Result<(), Error> {
    if scope.is_unrestricted() {
        Ok(())
    } else {
        Err(Error::Authorization(
            trustify_auth::authenticator::error::AuthorizationError::Failed,
        ))
    }
}

/// Determine which of the SBOMs are visible.
///
/// Returns `None` if access is unrestricted. This is intended for filtering SBOMs referenced from
/// other entities, like vulnerabilities or products.
pub async fn visible_sboms(
    scope: &AccessScope,
    candidates: impl IntoIterator<Item = Uuid>,
    db: &impl ConnectionTrait,
) -> Result<Option<HashSet<Uuid>>, Error> {
    let Some(groups) = visible_groups(scope) else {
        return Ok(None);
    };

    let candidates: Vec<Uuid> = candidates.into_iter().collect();
    if candidates.is_empty() {
        return Ok(Some(HashSet::new()));
    }

    let visible = sbom_group_assignment::Entity::find()
        .select_only()
        .column(sbom_group_assignment::Column::SbomId)
        .filter(sbom_group_assignment::Column::GroupId.is_in(groups))
        .filter(sbom_group_assignment::Column::SbomId.is_in(candidates))
        .into_tuple::<Uuid>()
        .all(db)
        .await?;

    Ok(Some(visible.into_iter().collect()))
}

/// Determine the permissions which apply to each of the SBOMs.
///
/// A permission applies if it is among the `granted` global permissions and, when access is scoped,
/// is granted in any group the SBOM is assigned to. SBOMs which don't exist, or aren't visible,
/// are omitted.
pub async fn sbom_permissions(
    scope: &AccessScope,
    granted: &[Permission],
    ids: Vec<Uuid>,
    db: &impl ConnectionTrait,
) -> Result<BTreeMap<Uuid, Vec<Permission>>, Error> {
    if ids.is_empty() {
        return Ok(BTreeMap::new());
    }

    if scope.is_unrestricted() {
        let existing = sbom::Entity::find()
            .select_only()
            .column(sbom::Column::SbomId)
            .filter(sbom::Column::SbomId.is_in(ids))
            .into_tuple::<Uuid>()
            .all(db)
            .await?;
        return Ok(existing
            .into_iter()
            .map(|id| (id, granted.to_vec()))
            .collect());
    }

    let mut groups: BTreeMap<Uuid, Vec<Uuid>> = BTreeMap::new();
    for (sbom, group) in sbom_group_assignment::Entity::find()
        .select_only()
        .column(sbom_group_assignment::Column::SbomId)
        .column(sbom_group_assignment::Column::GroupId)
        .filter(sbom_group_assignment::Column::SbomId.is_in(ids))
        .into_tuple::<(Uuid, Uuid)>()
        .all(db)
        .await?
    {
        groups.entry(sbom).or_default().push(group);
    }

    Ok(groups
        .into_iter()
        .filter(|(_, groups)| scope.allows_any(groups, Permission::ReadSbom))
        .map(|(sbom, groups)| {
            let permissions = granted
                .iter()
                .copied()
                .filter(|permission| scope.allows_any(&groups, *permission))
                .collect();
            (sbom, permissions)
        })
        .collect())
}
