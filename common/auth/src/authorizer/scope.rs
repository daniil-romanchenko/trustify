//! Restricting access to SBOMs, based on the SBOM groups they are assigned to.

use crate::Permission;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use uuid::Uuid;

/// The SBOM groups a request may access, and what it may do in each of them.
///
/// The scope is computed for each request (see the tenancy module). When no scope has been
/// computed, e.g. because scoped authorization is disabled, access is [`AccessScope::Unrestricted`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AccessScope {
    /// Access to all SBOMs, the global permissions still apply.
    #[default]
    Unrestricted,
    /// Access limited to SBOMs assigned to specific groups.
    Scoped(Arc<ScopedAccess>),
}

/// Permissions per SBOM group, already expanded to all descendants of a group.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopedAccess {
    groups: HashMap<Uuid, HashSet<Permission>>,
}

impl ScopedAccess {
    pub fn new(groups: HashMap<Uuid, HashSet<Permission>>) -> Self {
        Self { groups }
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}

impl AccessScope {
    /// A scope without access to any group.
    pub fn none() -> Self {
        Self::Scoped(Default::default())
    }

    pub fn scoped(groups: HashMap<Uuid, HashSet<Permission>>) -> Self {
        Self::Scoped(Arc::new(ScopedAccess::new(groups)))
    }

    pub fn is_unrestricted(&self) -> bool {
        matches!(self, Self::Unrestricted)
    }

    /// The groups in which the permission is granted.
    ///
    /// Returns `None` if access is unrestricted, meaning that no filtering must be applied.
    pub fn groups_with(&self, permission: Permission) -> Option<Vec<Uuid>> {
        match self {
            Self::Unrestricted => None,
            Self::Scoped(scoped) => {
                let mut groups: Vec<_> = scoped
                    .groups
                    .iter()
                    .filter(|(_, permissions)| permissions.contains(&permission))
                    .map(|(group, _)| *group)
                    .collect();
                groups.sort_unstable();
                Some(groups)
            }
        }
    }

    /// Check if the permission is granted in a group.
    pub fn allows(&self, group: Uuid, permission: Permission) -> bool {
        match self {
            Self::Unrestricted => true,
            Self::Scoped(scoped) => scoped
                .groups
                .get(&group)
                .is_some_and(|permissions| permissions.contains(&permission)),
        }
    }

    /// Check if the permission is granted in any of the groups.
    ///
    /// This is used for SBOMs, which may be assigned to more than one group.
    pub fn allows_any(&self, groups: &[Uuid], permission: Permission) -> bool {
        match self {
            Self::Unrestricted => true,
            Self::Scoped(_) => groups.iter().any(|group| self.allows(*group, permission)),
        }
    }
}

/// Extractor for the access scope, defaults to [`AccessScope::Unrestricted`] when absent.
#[cfg(feature = "actix")]
impl actix_web::FromRequest for AccessScope {
    type Error = actix_web::Error;
    type Future = core::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        use actix_web::HttpMessage;
        core::future::ready(Ok(req
            .extensions()
            .get::<AccessScope>()
            .cloned()
            .unwrap_or_default()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn scoped() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let scope = AccessScope::scoped(HashMap::from([
            (a, HashSet::from([Permission::ReadSbom])),
            (
                b,
                HashSet::from([Permission::ReadSbom, Permission::DeleteSbom]),
            ),
        ]));

        assert_eq!(scope.groups_with(Permission::ReadSbom), Some(vec![a, b]));
        assert_eq!(scope.groups_with(Permission::DeleteSbom), Some(vec![b]));
        assert_eq!(scope.groups_with(Permission::CreateSbom), Some(vec![]));
        assert!(scope.allows(b, Permission::DeleteSbom));
        assert!(!scope.allows(a, Permission::DeleteSbom));
        assert!(scope.allows_any(&[a, b], Permission::DeleteSbom));
        assert!(!scope.allows_any(&[], Permission::ReadSbom));

        assert_eq!(
            AccessScope::none().groups_with(Permission::ReadSbom),
            Some(vec![])
        );
    }

    #[test]
    fn unrestricted() {
        let scope = AccessScope::Unrestricted;
        assert_eq!(scope.groups_with(Permission::ReadSbom), None);
        assert!(scope.allows(Uuid::from_u128(1), Permission::DeleteSbom));
        assert!(scope.allows_any(&[], Permission::DeleteSbom));
    }
}
