#[cfg(test)]
mod test;

use crate::{
    Error,
    audit::{self, Actor, Change},
    email::normalize_email,
    user::model::{Access, User, UserRequest, UserState, Via},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, IntoActiveModel,
    QueryFilter, QueryOrder, QuerySelect, Set,
};
use sea_query::{Expr, OnConflict};
use serde_json::json;
use trustify_common::{
    db::{
        DatabaseErrors,
        limiter::LimiterTrait,
        pagination_cache::PaginationCache,
        query::{Filtering, Query},
    },
    model::{PaginatedResults, Pagination, Revisioned},
    resource_key::validate_external_id,
};
use trustify_entity::{principal_user, role_binding, team_member};
use uuid::Uuid;

pub struct UserService {
    cache: PaginationCache,
}

impl UserService {
    pub fn new(cache: PaginationCache) -> Self {
        Self { cache }
    }

    /// List users.
    pub async fn list(
        &self,
        query: Query,
        paginated: impl Pagination,
        db: &impl ConnectionTrait,
    ) -> Result<PaginatedResults<User>, Error> {
        let select = principal_user::Entity::find()
            .filtering(query)?
            .order_by_asc(principal_user::Column::Email);

        let limiter = select.limiting(db, paginated, &self.cache)?;
        let result = PaginatedResults::<principal_user::Model>::new(limiter, paginated).await?;

        Ok(PaginatedResults {
            items: result.items.into_iter().map(Into::into).collect(),
            total: result.total,
        })
    }

    /// Find a user by e-mail.
    pub async fn find(
        &self,
        email: &str,
        db: &impl ConnectionTrait,
    ) -> Result<Option<principal_user::Model>, Error> {
        let email = normalize_email(email)?;
        Ok(principal_user::Entity::find()
            .filter(principal_user::Column::Email.eq(email))
            .one(db)
            .await?)
    }

    /// Read a user by e-mail.
    pub async fn read(
        &self,
        email: &str,
        db: &impl ConnectionTrait,
    ) -> Result<Option<Revisioned<User>>, Error> {
        Ok(self.find(email, db).await?.map(|user| Revisioned {
            revision: user.revision.to_string(),
            value: user.into(),
        }))
    }

    /// Create or update a user.
    ///
    /// Returns the resulting user, and whether it was newly created.
    pub async fn upsert(
        &self,
        email: &str,
        request: UserRequest,
        expected_revision: Option<&str>,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<(Revisioned<User>, bool), Error> {
        let email = normalize_email(email)?;
        if let Some(external_id) = &request.external_id {
            validate_external_id(external_id)
                .map_err(|err| Error::bad_request("Invalid external ID", Some(err.to_string())))?;
        }

        let existing = principal_user::Entity::find()
            .filter(principal_user::Column::Email.eq(&email))
            .lock_exclusive()
            .one(db)
            .await?;

        let revision = Uuid::now_v7();

        let (model, created) = match existing {
            Some(existing) => {
                if let Some(expected) = expected_revision
                    && expected != existing.revision.to_string()
                {
                    return Err(Error::RevisionNotFound);
                }

                let state = match (request.disabled, existing.oidc_sub.is_some()) {
                    (true, _) => UserState::Disabled,
                    (false, true) => UserState::Active,
                    (false, false) => UserState::Invited,
                };

                let mut model = existing.into_active_model();
                model.display_name = Set(request.display_name.clone());
                model.external_id = Set(request.external_id.clone());
                model.state = Set(state);
                model.revision = Set(revision);

                (
                    model.update(db).await.map_err(conflict_on_duplicate)?,
                    false,
                )
            }
            None => {
                if expected_revision.is_some() {
                    return Err(Error::RevisionNotFound);
                }

                let model = principal_user::ActiveModel {
                    id: Set(Uuid::now_v7()),
                    email: Set(email.clone()),
                    oidc_issuer: Set(None),
                    oidc_sub: Set(None),
                    display_name: Set(request.display_name.clone()),
                    external_id: Set(request.external_id.clone()),
                    state: Set(if request.disabled {
                        UserState::Disabled
                    } else {
                        UserState::Invited
                    }),
                    created_at: Set(time::OffsetDateTime::now_utc()),
                    last_login: Set(None),
                    revision: Set(revision),
                };

                (model.insert(db).await.map_err(conflict_on_duplicate)?, true)
            }
        };

        audit::record(
            actor,
            Change {
                action: if created { "create" } else { "update" },
                target_kind: "user",
                target_id: &model.id.to_string(),
                detail: json!({
                    "email": model.email,
                    "externalId": model.external_id,
                    "state": model.state,
                }),
            },
            db,
        )
        .await?;

        Ok((
            Revisioned {
                revision: model.revision.to_string(),
                value: model.into(),
            },
            created,
        ))
    }

    /// Ensure users exist for all provided e-mail addresses.
    ///
    /// Missing users are created in state [`UserState::Invited`]. Returns the IDs of the users,
    /// in the order of the provided addresses.
    pub async fn ensure(
        &self,
        emails: &[String],
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<Vec<Uuid>, Error> {
        let emails = emails
            .iter()
            .map(|email| normalize_email(email))
            .collect::<Result<Vec<_>, _>>()?;

        if emails.is_empty() {
            return Ok(vec![]);
        }

        let now = time::OffsetDateTime::now_utc();
        let new = emails.iter().map(|email| principal_user::ActiveModel {
            id: Set(Uuid::now_v7()),
            email: Set(email.clone()),
            oidc_issuer: Set(None),
            oidc_sub: Set(None),
            display_name: Set(None),
            external_id: Set(None),
            state: Set(UserState::Invited),
            created_at: Set(now),
            last_login: Set(None),
            revision: Set(Uuid::now_v7()),
        });

        let inserted = principal_user::Entity::insert_many(new)
            .on_conflict(
                OnConflict::column(principal_user::Column::Email)
                    .do_nothing()
                    .to_owned(),
            )
            .exec_with_returning_many(db)
            .await?;

        for user in &inserted {
            audit::record(
                actor,
                Change {
                    action: "create",
                    target_kind: "user",
                    target_id: &user.id.to_string(),
                    detail: json!({"email": user.email, "state": user.state}),
                },
                db,
            )
            .await?;
        }

        let users = principal_user::Entity::find()
            .filter(principal_user::Column::Email.is_in(emails.clone()))
            .all(db)
            .await?;

        emails
            .iter()
            .map(|email| {
                users
                    .iter()
                    .find(|user| &user.email == email)
                    .map(|user| user.id)
                    .ok_or_else(|| Error::NotFound(email.clone()))
            })
            .collect()
    }

    /// Delete a user, including all of its team memberships and role bindings.
    ///
    /// Returns `true` if the user existed.
    pub async fn delete(
        &self,
        email: &str,
        expected_revision: Option<&str>,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<bool, Error> {
        let Some(user) = self.find(email, db).await? else {
            return Ok(false);
        };

        if let Some(expected) = expected_revision
            && expected != user.revision.to_string()
        {
            return Err(Error::RevisionNotFound);
        }

        let result = principal_user::Entity::delete_many()
            .filter(principal_user::Column::Id.eq(user.id))
            .filter(principal_user::Column::Revision.eq(user.revision))
            .exec(db)
            .await?;

        if result.rows_affected == 0 {
            // modified concurrently
            return Err(Error::RevisionNotFound);
        }

        audit::record(
            actor,
            Change {
                action: "delete",
                target_kind: "user",
                target_id: &user.id.to_string(),
                detail: json!({"email": user.email}),
            },
            db,
        )
        .await?;

        Ok(true)
    }

    /// Change the e-mail address of a user.
    pub async fn change_email(
        &self,
        email: &str,
        new_email: &str,
        expected_revision: Option<&str>,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<Revisioned<User>, Error> {
        let new_email = normalize_email(new_email)?;
        let Some(user) = self.find(email, db).await? else {
            return Err(Error::NotFound(email.to_string()));
        };

        if let Some(expected) = expected_revision
            && expected != user.revision.to_string()
        {
            return Err(Error::RevisionNotFound);
        }

        let old_email = user.email.clone();
        let mut model = user.into_active_model();
        model.email = Set(new_email.clone());
        model.revision = Set(Uuid::now_v7());
        let model = model.update(db).await.map_err(conflict_on_duplicate)?;

        audit::record(
            actor,
            Change {
                action: "change-email",
                target_kind: "user",
                target_id: &model.id.to_string(),
                detail: json!({"from": old_email, "to": new_email}),
            },
            db,
        )
        .await?;

        Ok(Revisioned {
            revision: model.revision.to_string(),
            value: model.into(),
        })
    }

    /// Get all role bindings which apply to a user, directly or through a team.
    ///
    /// This does not expand the bindings to the groups below the bound group.
    pub async fn access(
        &self,
        email: &str,
        db: &impl ConnectionTrait,
    ) -> Result<Option<Vec<Access>>, Error> {
        let Some(user) = self.find(email, db).await? else {
            return Ok(None);
        };

        let teams = team_member::Entity::find()
            .select_only()
            .column(team_member::Column::TeamId)
            .filter(team_member::Column::UserId.eq(user.id))
            .into_tuple::<Uuid>()
            .all(db)
            .await?;

        let bindings = role_binding::Entity::find()
            .filter(
                Expr::col(role_binding::Column::UserId)
                    .eq(user.id)
                    .or(Expr::col(role_binding::Column::TeamId).is_in(teams)),
            )
            .order_by_asc(role_binding::Column::GroupId)
            .all(db)
            .await?;

        Ok(Some(
            bindings
                .into_iter()
                .map(|binding| Access {
                    group: binding.group_id.to_string(),
                    role: binding.role,
                    via: match binding.team_id {
                        Some(team) => Via::Team {
                            id: team.to_string(),
                        },
                        None => Via::Direct,
                    },
                })
                .collect(),
        ))
    }
}

fn conflict_on_duplicate(err: DbErr) -> Error {
    if err.is_duplicate() {
        Error::Conflict("The e-mail address or external ID is already in use".into())
    } else {
        err.into()
    }
}
