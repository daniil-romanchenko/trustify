//! Computing the [`AccessScope`] of a request.

use crate::{Error, binding::model::Role, group::expand_groups, user::service::access_of};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use std::collections::{HashMap, HashSet};
use trustify_auth::{Permission, authenticator::user::UserDetails, authorizer::AccessScope};
use uuid::Uuid;

/// How access to SBOMs is authorized.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum AuthzMode {
    /// Only the global permissions apply, role bindings are not enforced.
    #[default]
    Global,
    /// Access to SBOMs is limited to the groups a user holds a role on.
    Scoped,
}

/// The permissions a role grants, on a group and its descendants.
pub fn permissions(role: Role) -> &'static [Permission] {
    const VIEWER: &[Permission] = &[
        Permission::ReadSbom,
        Permission::ReadSbomGroup,
        Permission::ReadMetadata,
    ];
    const UPLOADER: &[Permission] = &[
        Permission::ReadSbom,
        Permission::ReadSbomGroup,
        Permission::ReadMetadata,
        Permission::CreateSbom,
    ];
    const EDITOR: &[Permission] = &[
        Permission::ReadSbom,
        Permission::ReadSbomGroup,
        Permission::ReadMetadata,
        Permission::CreateSbom,
        Permission::UpdateSbom,
        Permission::DeleteSbom,
    ];
    const ADMIN: &[Permission] = &[
        Permission::ReadSbom,
        Permission::ReadSbomGroup,
        Permission::ReadMetadata,
        Permission::CreateSbom,
        Permission::UpdateSbom,
        Permission::DeleteSbom,
        Permission::CreateSbomGroup,
        Permission::UpdateSbomGroup,
        Permission::DeleteSbomGroup,
        Permission::ManageTenancy,
    ];

    match role {
        Role::Viewer => VIEWER,
        Role::Uploader => UPLOADER,
        Role::Editor => EDITOR,
        Role::Admin => ADMIN,
    }
}

/// Check if a permission is limited by the access scope, as it is granted through roles.
pub fn is_scoped_permission(permission: Permission) -> bool {
    permissions(Role::Admin).contains(&permission)
}

/// Global permissions which grant access to all SBOMs.
const UNRESTRICTED: &[Permission] = &[Permission::ReadAllSboms, Permission::ManageTenancy];

/// Check if the global permissions of a user grant unrestricted access.
pub fn is_unrestricted(details: &UserDetails) -> bool {
    UNRESTRICTED.iter().any(|permission| {
        details
            .permissions
            .iter()
            .any(|granted| granted == permission.as_ref())
    })
}

/// The scope of a request made using an API key: uploading into its groups.
pub fn api_key_scope(groups: &[String]) -> AccessScope {
    AccessScope::scoped(
        groups
            .iter()
            .filter_map(|group| Uuid::parse_str(group).ok())
            .map(|group| (group, HashSet::from([Permission::CreateSbom])))
            .collect(),
    )
}

/// Compute the scope of a user, from its role bindings, directly or through teams.
pub async fn user_scope(user: Uuid, db: &impl ConnectionTrait) -> Result<AccessScope, Error> {
    // group the bound groups by role, so that we expand each set of groups only once
    let mut by_role: HashMap<Role, Vec<Uuid>> = HashMap::new();
    for access in access_of(user, db).await? {
        let group = Uuid::parse_str(&access.group)
            .map_err(|err| Error::Internal(format!("invalid group ID: {err}")))?;
        by_role.entry(access.role).or_default().push(group);
    }

    let mut groups: HashMap<Uuid, HashSet<Permission>> = HashMap::new();
    for (role, bound) in by_role {
        for group in expand_groups(&bound, db).await? {
            groups
                .entry(group)
                .or_default()
                .extend(permissions(role).iter().copied());
        }
    }

    Ok(AccessScope::scoped(groups))
}

/// Read the current authorization revision.
pub async fn current_revision(db: &impl ConnectionTrait) -> Result<i64, Error> {
    let row = db
        .query_one(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT value FROM authz_revision",
        ))
        .await?
        .ok_or_else(|| Error::Internal("missing authorization revision".into()))?;
    Ok(row.try_get("", "value")?)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn roles_are_cumulative() {
        let roles = [Role::Viewer, Role::Uploader, Role::Editor, Role::Admin];
        for pair in roles.windows(2) {
            let lower: HashSet<_> = permissions(pair[0]).iter().collect();
            let higher: HashSet<_> = permissions(pair[1]).iter().collect();
            assert!(lower.is_subset(&higher), "{:?} < {:?}", pair[0], pair[1]);
            assert!(lower.len() < higher.len());
        }
    }

    #[test]
    fn unrestricted_permissions() {
        let details = |permission: &str| UserDetails {
            permissions: vec![permission.into()],
            ..Default::default()
        };
        assert!(is_unrestricted(&details("read.allSboms")));
        assert!(is_unrestricted(&details("manage.tenancy")));
        assert!(!is_unrestricted(&details("read.sbom")));
    }
}
