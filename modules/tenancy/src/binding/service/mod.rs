use crate::{
    Error,
    audit::{self, Actor, Change},
    binding::model::{Binding, BindingRequest, PrincipalRef, Role},
    email::normalize_email,
    user::service::UserService,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set,
};
use sea_query::{Expr, OnConflict, SimpleExpr};
use serde_json::json;
use std::{
    collections::{BTreeMap, HashMap},
    slice,
};
use trustify_common::{
    model::Revisioned,
    resource_key::{ResourceKey, ResourceKeyError},
};
use trustify_entity::{principal_user, role_binding, sbom_group, team};
use uuid::Uuid;

/// Namespace for deriving the revision of a set of bindings.
const REVISION_NAMESPACE: Uuid = Uuid::from_u128(0x5b0f_3c2e_7a4d_4d8e_9f61_2c7e_8a1b_4d30);

/// A resolved principal.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Principal {
    User(Uuid),
    Team(Uuid),
}

impl Principal {
    fn of(binding: &role_binding::Model) -> Option<Self> {
        match (binding.user_id, binding.team_id) {
            (Some(user), None) => Some(Self::User(user)),
            (None, Some(team)) => Some(Self::Team(team)),
            _ => None,
        }
    }

    fn filter(&self) -> SimpleExpr {
        match self {
            Self::User(id) => role_binding::Column::UserId.eq(*id),
            Self::Team(id) => role_binding::Column::TeamId.eq(*id),
        }
    }

    fn columns(&self) -> (Option<Uuid>, Option<Uuid>) {
        match self {
            Self::User(id) => (Some(*id), None),
            Self::Team(id) => (None, Some(*id)),
        }
    }
}

#[derive(Default)]
pub struct BindingService;

impl BindingService {
    pub fn new() -> Self {
        Self
    }

    /// Resolve a group key into the group's ID.
    pub async fn resolve_group(
        &self,
        key: &str,
        db: &impl ConnectionTrait,
    ) -> Result<Option<Uuid>, Error> {
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

    async fn resolve_group_or_fail(
        &self,
        key: &str,
        db: &impl ConnectionTrait,
    ) -> Result<Uuid, Error> {
        self.resolve_group(key, db)
            .await?
            .ok_or_else(|| Error::NotFound(format!("group '{key}'")))
    }

    /// List the bindings directly on a group.
    pub async fn list(
        &self,
        group: &str,
        db: &impl ConnectionTrait,
    ) -> Result<Option<Revisioned<Vec<Binding>>>, Error> {
        let Some(group) = self.resolve_group(group, db).await? else {
            return Ok(None);
        };

        let bindings = self.load(group, db).await?;
        let revision = revision_of(&bindings);

        let users = principal_user::Entity::find()
            .filter(
                principal_user::Column::Id
                    .is_in(bindings.iter().filter_map(|binding| binding.user_id)),
            )
            .all(db)
            .await?
            .into_iter()
            .map(|user| (user.id, user.email))
            .collect::<HashMap<_, _>>();

        let value = bindings
            .into_iter()
            .filter_map(|binding| {
                let principal = match Principal::of(&binding)? {
                    Principal::User(id) => PrincipalRef::User(users.get(&id)?.clone()),
                    Principal::Team(id) => PrincipalRef::Team(id.to_string()),
                };
                Some(Binding {
                    principal,
                    role: binding.role,
                    created_at: binding.created_at,
                    created_by: binding.created_by,
                })
            })
            .collect();

        Ok(Some(Revisioned { value, revision }))
    }

    /// Replace all bindings directly on a group.
    pub async fn replace(
        &self,
        group: &str,
        requests: Vec<BindingRequest>,
        expected_revision: Option<&str>,
        users: &UserService,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<Revisioned<()>, Error> {
        let group = self.resolve_group_or_fail(group, db).await?;
        self.lock_group(group, db).await?;

        let existing = self.load(group, db).await?;
        if let Some(expected) = expected_revision
            && expected != revision_of(&existing)
        {
            return Err(Error::RevisionNotFound);
        }

        let mut desired = BTreeMap::new();
        for request in requests {
            let principal = self
                .resolve_principal(&request.principal, users, actor, db)
                .await?;
            if desired.insert(principal, request.role).is_some() {
                return Err(Error::bad_request(
                    "Duplicate principal",
                    Some(format!("{:?} is listed more than once", request.principal)),
                ));
            }
        }

        let existing = existing
            .into_iter()
            .filter_map(|binding| Principal::of(&binding).map(|p| (p, binding.role)))
            .collect::<BTreeMap<_, _>>();

        for principal in existing.keys().filter(|p| !desired.contains_key(p)) {
            role_binding::Entity::delete_many()
                .filter(role_binding::Column::GroupId.eq(group))
                .filter(principal.filter())
                .exec(db)
                .await?;
        }

        for (principal, role) in &desired {
            if existing.get(principal) != Some(role) {
                self.upsert(group, *principal, *role, actor, db).await?;
            }
        }

        audit::record(
            actor,
            Change {
                action: "replace-bindings",
                target_kind: "group",
                target_id: &group.to_string(),
                detail: json!({
                    "bindings": desired.iter().map(|(p, r)| json!({"principal": format!("{p:?}"), "role": r})).collect::<Vec<_>>()
                }),
            },
            db,
        )
        .await?;

        let revision = revision_of(&self.load(group, db).await?);
        Ok(Revisioned {
            value: (),
            revision,
        })
    }

    /// Grant a role to a principal on a group, replacing any role it had before.
    pub async fn set(
        &self,
        group: &str,
        principal: &PrincipalRef,
        role: Role,
        users: &UserService,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<(), Error> {
        let group = self.resolve_group_or_fail(group, db).await?;
        let resolved = self.resolve_principal(principal, users, actor, db).await?;

        self.upsert(group, resolved, role, actor, db).await?;

        audit::record(
            actor,
            Change {
                action: "set-binding",
                target_kind: "group",
                target_id: &group.to_string(),
                detail: json!({"principal": principal, "role": role}),
            },
            db,
        )
        .await?;

        Ok(())
    }

    /// Remove the role of a principal on a group.
    ///
    /// Returns `true` if a binding existed.
    pub async fn remove(
        &self,
        group: &str,
        principal: &PrincipalRef,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<bool, Error> {
        let Some(group) = self.resolve_group(group, db).await? else {
            return Ok(false);
        };

        // removing does not create users
        let resolved = match principal {
            PrincipalRef::User(email) => principal_user::Entity::find()
                .filter(principal_user::Column::Email.eq(normalize_email(email)?))
                .one(db)
                .await?
                .map(|user| Principal::User(user.id)),
            PrincipalRef::Team(key) => find_team(key, db).await?.map(Principal::Team),
        };

        let Some(resolved) = resolved else {
            return Ok(false);
        };

        let result = role_binding::Entity::delete_many()
            .filter(role_binding::Column::GroupId.eq(group))
            .filter(resolved.filter())
            .exec(db)
            .await?;

        if result.rows_affected > 0 {
            audit::record(
                actor,
                Change {
                    action: "remove-binding",
                    target_kind: "group",
                    target_id: &group.to_string(),
                    detail: json!({"principal": principal}),
                },
                db,
            )
            .await?;
        }

        Ok(result.rows_affected > 0)
    }

    async fn load(
        &self,
        group: Uuid,
        db: &impl ConnectionTrait,
    ) -> Result<Vec<role_binding::Model>, Error> {
        Ok(role_binding::Entity::find()
            .filter(role_binding::Column::GroupId.eq(group))
            .order_by_asc(role_binding::Column::UserId)
            .order_by_asc(role_binding::Column::TeamId)
            .all(db)
            .await?)
    }

    /// Serialize concurrent replacements of the bindings of a group.
    async fn lock_group(&self, group: Uuid, db: &impl ConnectionTrait) -> Result<(), Error> {
        sbom_group::Entity::find_by_id(group)
            .lock_exclusive()
            .one(db)
            .await?;
        Ok(())
    }

    async fn resolve_principal(
        &self,
        principal: &PrincipalRef,
        users: &UserService,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<Principal, Error> {
        Ok(match principal {
            PrincipalRef::User(email) => {
                let ids = users.ensure(slice::from_ref(email), actor, db).await?;
                let id = ids
                    .into_iter()
                    .next()
                    .ok_or_else(|| Error::NotFound(email.clone()))?;
                Principal::User(id)
            }
            PrincipalRef::Team(key) => Principal::Team(
                find_team(key, db)
                    .await?
                    .ok_or_else(|| Error::bad_request("Unknown team", Some(key.clone())))?,
            ),
        })
    }

    async fn upsert(
        &self,
        group: Uuid,
        principal: Principal,
        role: Role,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<(), Error> {
        let (user_id, team_id) = principal.columns();

        let (conflict_column, index_where) = match principal {
            Principal::User(_) => (role_binding::Column::UserId, role_binding::Column::UserId),
            Principal::Team(_) => (role_binding::Column::TeamId, role_binding::Column::TeamId),
        };

        role_binding::Entity::insert(role_binding::ActiveModel {
            id: Set(Uuid::now_v7()),
            group_id: Set(group),
            user_id: Set(user_id),
            team_id: Set(team_id),
            role: Set(role),
            created_at: Set(time::OffsetDateTime::now_utc()),
            created_by: Set(actor.id.clone()),
        })
        .on_conflict(
            OnConflict::columns([role_binding::Column::GroupId, conflict_column])
                .target_and_where(Expr::col(index_where).is_not_null())
                .update_columns([
                    role_binding::Column::Role,
                    role_binding::Column::CreatedAt,
                    role_binding::Column::CreatedBy,
                ])
                .to_owned(),
        )
        .exec_without_returning(db)
        .await?;

        Ok(())
    }
}

async fn find_team(key: &str, db: &impl ConnectionTrait) -> Result<Option<Uuid>, Error> {
    let select = team::Entity::find();
    let select = match key.parse::<ResourceKey>()? {
        ResourceKey::Id(id) => select.filter(team::Column::Id.eq(id)),
        ResourceKey::External(id) => select.filter(team::Column::ExternalId.eq(id)),
    };
    Ok(select.one(db).await?.map(|team| team.id))
}

/// Derive a stable revision from a set of bindings.
fn revision_of(bindings: &[role_binding::Model]) -> String {
    let mut entries = bindings
        .iter()
        .filter_map(|binding| {
            Principal::of(binding).map(|principal| format!("{principal:?}={}", binding.role))
        })
        .collect::<Vec<_>>();
    entries.sort_unstable();

    Uuid::new_v5(&REVISION_NAMESPACE, entries.join("\n").as_bytes()).to_string()
}
