//! Authorizing tenancy management, globally or delegated to group admins.

use crate::Error;
use trustify_auth::{
    Permission,
    authenticator::{error::AuthorizationError, user::UserInformation},
    authorizer::{AccessScope, Authorizer},
};
use uuid::Uuid;

/// Check if the caller may manage the tenancy configuration of all groups.
pub fn is_global_manager(authorizer: &Authorizer, user: &UserInformation) -> bool {
    authorizer.require(user, Permission::ManageTenancy).is_ok()
}

/// Ensure the caller may manage the tenancy configuration of all the groups.
///
/// This is either granted globally, through the `manage.tenancy` permission, or delegated
/// through the admin role on the groups. Delegation only applies with scoped authorization, when
/// the scope has actually been computed.
pub fn require_manage(
    authorizer: &Authorizer,
    user: &UserInformation,
    scope: &AccessScope,
    groups: &[Uuid],
) -> Result<(), Error> {
    if is_global_manager(authorizer, user) {
        return Ok(());
    }

    let delegated = matches!(scope, AccessScope::Scoped(_))
        && !groups.is_empty()
        && groups
            .iter()
            .all(|group| scope.allows(*group, Permission::ManageTenancy));

    if delegated {
        Ok(())
    } else {
        Err(AuthorizationError::Failed.into())
    }
}

/// The groups the caller may manage through delegation, `None` for all groups.
pub fn managed_groups(
    authorizer: &Authorizer,
    user: &UserInformation,
    scope: &AccessScope,
) -> Option<Vec<Uuid>> {
    if is_global_manager(authorizer, user) {
        return None;
    }

    match scope {
        AccessScope::Scoped(_) => scope.groups_with(Permission::ManageTenancy),
        // not computed, no delegation
        AccessScope::Unrestricted => Some(vec![]),
    }
}

/// Extractor for authorizing tenancy management, globally or delegated.
///
/// Unlike `Require<ManageTenancy>`, this doesn't fail right away, as delegated access depends on
/// the groups being managed.
pub struct ManageAccess {
    authorizer: Authorizer,
    user: UserInformation,
    scope: AccessScope,
}

impl ManageAccess {
    /// The user making the request.
    pub fn user(&self) -> &UserInformation {
        &self.user
    }

    /// Whether tenancy management is granted for all groups.
    pub fn is_global(&self) -> bool {
        is_global_manager(&self.authorizer, &self.user)
    }

    /// Ensure tenancy management is granted for all groups.
    pub fn require_global(&self) -> Result<(), Error> {
        if self.is_global() {
            Ok(())
        } else {
            Err(AuthorizationError::Failed.into())
        }
    }

    /// Ensure tenancy management is granted for all the groups.
    pub fn require_groups(&self, groups: &[Uuid]) -> Result<(), Error> {
        require_manage(&self.authorizer, &self.user, &self.scope, groups)
    }

    /// Ensure tenancy management is granted for a group, by key.
    ///
    /// For delegated access, an unknown or unmanaged group is reported as not found, so that
    /// the existence of groups isn't disclosed.
    pub async fn require_group(
        &self,
        key: &str,
        db: &impl sea_orm::ConnectionTrait,
    ) -> Result<(), Error> {
        if self.is_global() {
            return Ok(());
        }

        match crate::group::resolve_group(key, db).await? {
            Some(group) if self.require_groups(&[group]).is_ok() => Ok(()),
            _ => Err(Error::NotFound(format!("group '{key}'"))),
        }
    }

    /// The groups which may be managed, `None` for all groups.
    pub fn managed_groups(&self) -> Option<Vec<Uuid>> {
        managed_groups(&self.authorizer, &self.user, &self.scope)
    }
}

impl actix_web::FromRequest for ManageAccess {
    type Error = actix_web::Error;
    type Future = std::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        use actix_web::HttpMessage;

        let Some(authorizer) = req.app_data::<actix_web::web::Data<Authorizer>>() else {
            return std::future::ready(Err(actix_web::error::ErrorInternalServerError(
                "missing authorizer",
            )));
        };

        let extensions = req.extensions();
        std::future::ready(Ok(Self {
            authorizer: authorizer.get_ref().clone(),
            user: extensions
                .get::<UserInformation>()
                .cloned()
                .unwrap_or(UserInformation::Anonymous),
            scope: extensions.get::<AccessScope>().cloned().unwrap_or_default(),
        }))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use trustify_auth::{authenticator::user::UserDetails, authorizer::AuthorizerConfig};

    fn user(permissions: &[&str]) -> UserInformation {
        UserInformation::Authenticated(UserDetails {
            permissions: permissions.iter().map(ToString::to_string).collect(),
            ..Default::default()
        })
    }

    #[test]
    fn delegation() {
        let authorizer = Authorizer::new(Some(AuthorizerConfig {}));
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let admin_a = AccessScope::scoped(HashMap::from([(
            a,
            HashSet::from([Permission::ManageTenancy]),
        )]));

        // global permission
        assert!(require_manage(&authorizer, &user(&["manage.tenancy"]), &admin_a, &[b]).is_ok());

        // delegated
        assert!(require_manage(&authorizer, &user(&[]), &admin_a, &[a]).is_ok());
        assert!(require_manage(&authorizer, &user(&[]), &admin_a, &[a, b]).is_err());
        assert!(require_manage(&authorizer, &user(&[]), &admin_a, &[]).is_err());

        // an unrestricted scope (global mode) must not delegate anything
        assert!(require_manage(&authorizer, &user(&[]), &AccessScope::Unrestricted, &[a]).is_err());
        assert_eq!(
            managed_groups(&authorizer, &user(&[]), &AccessScope::Unrestricted),
            Some(vec![])
        );
        assert_eq!(
            managed_groups(&authorizer, &user(&["manage.tenancy"]), &admin_a),
            None
        );
    }
}
