use crate::{
    Error,
    audit::{self, Actor, Change},
    email::normalize_email,
    team::model::{Member, MembersPatch, Team, TeamRequest},
    user::service::UserService,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, IntoActiveModel,
    QueryFilter, QueryOrder, QuerySelect, RelationTrait, Set,
};
use sea_query::{JoinType, OnConflict};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use trustify_common::{
    db::{
        DatabaseErrors,
        limiter::LimiterTrait,
        pagination_cache::PaginationCache,
        query::{Filtering, Query},
    },
    model::{PaginatedResults, Pagination, Revisioned},
    resource_key::{ResourceKey, validate_external_id},
};
use trustify_entity::{principal_user, team, team_member};
use uuid::Uuid;

pub struct TeamService {
    cache: PaginationCache,
}

impl TeamService {
    pub fn new(cache: PaginationCache) -> Self {
        Self { cache }
    }

    /// List teams.
    pub async fn list(
        &self,
        query: Query,
        paginated: impl Pagination,
        db: &impl ConnectionTrait,
    ) -> Result<PaginatedResults<Team>, Error> {
        let select = team::Entity::find()
            .filtering(query)?
            .order_by_asc(team::Column::Name)
            .order_by_asc(team::Column::Id);

        let limiter = select.limiting(db, paginated, &self.cache)?;
        let result = PaginatedResults::<team::Model>::new(limiter, paginated).await?;

        Ok(PaginatedResults {
            items: result.items.into_iter().map(Into::into).collect(),
            total: result.total,
        })
    }

    /// Find a team by its key.
    pub async fn find(
        &self,
        key: &ResourceKey,
        db: &impl ConnectionTrait,
    ) -> Result<Option<team::Model>, Error> {
        let select = team::Entity::find();
        let select = match key {
            ResourceKey::Id(id) => select.filter(team::Column::Id.eq(*id)),
            ResourceKey::External(id) => select.filter(team::Column::ExternalId.eq(id)),
        };
        Ok(select.one(db).await?)
    }

    /// Find a team by its key, failing if it doesn't exist.
    async fn find_or_fail(
        &self,
        key: &ResourceKey,
        db: &impl ConnectionTrait,
    ) -> Result<team::Model, Error> {
        self.find(key, db)
            .await?
            .ok_or_else(|| Error::NotFound(format!("team '{key}'")))
    }

    /// Read a team by its key.
    pub async fn read(
        &self,
        key: &ResourceKey,
        db: &impl ConnectionTrait,
    ) -> Result<Option<Revisioned<Team>>, Error> {
        Ok(self.find(key, db).await?.map(|team| Revisioned {
            revision: team.revision.to_string(),
            value: team.into(),
        }))
    }

    /// Create a new team.
    pub async fn create(
        &self,
        request: TeamRequest,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<Revisioned<Team>, Error> {
        validate(&request)?;

        let model = team::ActiveModel {
            id: Set(Uuid::now_v7()),
            name: Set(request.name),
            description: Set(request.description),
            external_id: Set(request.external_id),
            revision: Set(Uuid::now_v7()),
        }
        .insert(db)
        .await
        .map_err(conflict_on_duplicate)?;

        record(actor, "create", &model, json!({}), db).await?;

        Ok(Revisioned {
            revision: model.revision.to_string(),
            value: model.into(),
        })
    }

    /// Update a team, or create it when it is addressed by an external ID which doesn't exist yet.
    ///
    /// Returns the resulting team, and whether it was newly created.
    pub async fn upsert(
        &self,
        key: &ResourceKey,
        mut request: TeamRequest,
        expected_revision: Option<&str>,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<(Revisioned<Team>, bool), Error> {
        if let ResourceKey::External(external_id) = key {
            match &request.external_id {
                Some(requested) if requested != external_id => {
                    return Err(Error::bad_request(
                        "External ID mismatch",
                        Some("The external ID of the request must match the one of the path"),
                    ));
                }
                _ => request.external_id = Some(external_id.clone()),
            }
        }

        validate(&request)?;

        let Some(existing) = self.find(key, db).await? else {
            return match key {
                ResourceKey::External(_) if expected_revision.is_none() => {
                    Ok((self.create(request, actor, db).await?, true))
                }
                ResourceKey::External(_) => Err(Error::RevisionNotFound),
                ResourceKey::Id(_) => Err(Error::NotFound(format!("team '{key}'"))),
            };
        };

        let (id, current) = (existing.id, existing.revision);
        let mut model = existing.into_active_model();
        model.name = Set(request.name);
        model.description = Set(request.description);
        model.external_id = Set(request.external_id);

        let model = update_revisioned(id, current, model, expected_revision, db).await?;

        record(actor, "update", &model, json!({}), db).await?;

        Ok((
            Revisioned {
                revision: model.revision.to_string(),
                value: model.into(),
            },
            false,
        ))
    }

    /// Delete a team, including all of its memberships and role bindings.
    ///
    /// Returns `true` if the team existed.
    pub async fn delete(
        &self,
        key: &ResourceKey,
        expected_revision: Option<&str>,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<bool, Error> {
        let Some(existing) = self.find(key, db).await? else {
            return Ok(false);
        };

        if let Some(expected) = expected_revision
            && expected != existing.revision.to_string()
        {
            return Err(Error::RevisionNotFound);
        }

        let result = team::Entity::delete_many()
            .filter(team::Column::Id.eq(existing.id))
            .filter(team::Column::Revision.eq(existing.revision))
            .exec(db)
            .await?;

        if result.rows_affected == 0 {
            return Err(Error::RevisionNotFound);
        }

        record(actor, "delete", &existing, json!({}), db).await?;

        Ok(true)
    }

    /// List the members of a team.
    pub async fn members(
        &self,
        key: &ResourceKey,
        paginated: impl Pagination,
        db: &impl ConnectionTrait,
    ) -> Result<Option<Revisioned<PaginatedResults<Member>>>, Error> {
        let Some(team) = self.find(key, db).await? else {
            return Ok(None);
        };

        let select = principal_user::Entity::find()
            .join(JoinType::InnerJoin, team_member::Relation::User.def().rev())
            .filter(team_member::Column::TeamId.eq(team.id))
            .order_by_asc(principal_user::Column::Email);

        let limiter = select.limiting(db, paginated, &self.cache)?;
        let result = PaginatedResults::<principal_user::Model>::new(limiter, paginated).await?;

        Ok(Some(Revisioned {
            revision: team.revision.to_string(),
            value: PaginatedResults {
                items: result.items.into_iter().map(Into::into).collect(),
                total: result.total,
            },
        }))
    }

    /// Replace all members of a team.
    pub async fn set_members(
        &self,
        key: &ResourceKey,
        emails: Vec<String>,
        expected_revision: Option<&str>,
        users: &UserService,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<Revisioned<()>, Error> {
        let team = self.find_or_fail(key, db).await?;
        if let Some(expected) = expected_revision
            && expected != team.revision.to_string()
        {
            return Err(Error::RevisionNotFound);
        }

        let emails = normalize_all(&emails)?;
        let user_ids = users.ensure(&emails, actor, db).await?;

        team_member::Entity::delete_many()
            .filter(team_member::Column::TeamId.eq(team.id))
            .filter(team_member::Column::UserId.is_not_in(user_ids.clone()))
            .exec(db)
            .await?;

        insert_members(team.id, &user_ids, db).await?;

        let revision = self
            .touch(
                team,
                expected_revision,
                actor,
                json!({"members": emails}),
                db,
            )
            .await?;

        Ok(Revisioned {
            value: (),
            revision,
        })
    }

    /// Add and remove members of a team.
    ///
    /// Removals are applied after additions.
    pub async fn patch_members(
        &self,
        key: &ResourceKey,
        patch: MembersPatch,
        expected_revision: Option<&str>,
        users: &UserService,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<Revisioned<()>, Error> {
        let team = self.find_or_fail(key, db).await?;
        if let Some(expected) = expected_revision
            && expected != team.revision.to_string()
        {
            return Err(Error::RevisionNotFound);
        }

        let add = normalize_all(&patch.add)?;
        let remove = normalize_all(&patch.remove)?;

        let user_ids = users.ensure(&add, actor, db).await?;
        insert_members(team.id, &user_ids, db).await?;

        if !remove.is_empty() {
            let remove_ids = principal_user::Entity::find()
                .select_only()
                .column(principal_user::Column::Id)
                .filter(principal_user::Column::Email.is_in(remove.clone()))
                .into_tuple::<Uuid>()
                .all(db)
                .await?;

            team_member::Entity::delete_many()
                .filter(team_member::Column::TeamId.eq(team.id))
                .filter(team_member::Column::UserId.is_in(remove_ids))
                .exec(db)
                .await?;
        }

        let revision = self
            .touch(
                team,
                expected_revision,
                actor,
                json!({"add": add, "remove": remove}),
                db,
            )
            .await?;

        Ok(Revisioned {
            value: (),
            revision,
        })
    }

    /// Bump the revision of a team after its members changed, and record the change.
    async fn touch(
        &self,
        team: team::Model,
        expected_revision: Option<&str>,
        actor: &Actor,
        detail: Value,
        db: &impl ConnectionTrait,
    ) -> Result<String, Error> {
        let (id, current) = (team.id, team.revision);
        let model =
            update_revisioned(id, current, team.into_active_model(), expected_revision, db).await?;

        record(actor, "update-members", &model, detail, db).await?;

        Ok(model.revision.to_string())
    }
}

/// Update a team, assigning a new revision, and checking the expected one.
///
/// The update only succeeds if the team still has the `current` revision.
async fn update_revisioned(
    id: Uuid,
    current: Uuid,
    mut model: team::ActiveModel,
    expected_revision: Option<&str>,
    db: &impl ConnectionTrait,
) -> Result<team::Model, Error> {
    if let Some(expected) = expected_revision
        && expected != current.to_string()
    {
        return Err(Error::RevisionNotFound);
    }

    model.revision = Set(Uuid::now_v7());

    let result = team::Entity::update_many()
        .set(model)
        .filter(team::Column::Id.eq(id))
        .filter(team::Column::Revision.eq(current))
        .exec_with_returning(db)
        .await
        .map_err(conflict_on_duplicate)?;

    result.into_iter().next().ok_or(Error::RevisionNotFound)
}

fn validate(request: &TeamRequest) -> Result<(), Error> {
    if request.name.trim().is_empty() {
        return Err(Error::bad_request(
            "Invalid team",
            Some("name must not be empty"),
        ));
    }
    if let Some(external_id) = &request.external_id {
        validate_external_id(external_id)
            .map_err(|err| Error::bad_request("Invalid external ID", Some(err.to_string())))?;
    }
    Ok(())
}

/// Normalize and de-duplicate e-mail addresses.
fn normalize_all(emails: &[String]) -> Result<Vec<String>, Error> {
    Ok(emails
        .iter()
        .map(|email| normalize_email(email))
        .collect::<Result<BTreeSet<_>, _>>()?
        .into_iter()
        .collect())
}

async fn insert_members(
    team_id: Uuid,
    user_ids: &[Uuid],
    db: &impl ConnectionTrait,
) -> Result<(), Error> {
    if user_ids.is_empty() {
        return Ok(());
    }

    team_member::Entity::insert_many(user_ids.iter().map(|user_id| team_member::ActiveModel {
        team_id: Set(team_id),
        user_id: Set(*user_id),
    }))
    .on_conflict(
        OnConflict::columns([team_member::Column::TeamId, team_member::Column::UserId])
            .do_nothing()
            .to_owned(),
    )
    .do_nothing()
    .exec(db)
    .await?;

    Ok(())
}

async fn record(
    actor: &Actor,
    action: &'static str,
    team: &team::Model,
    mut detail: Value,
    db: &impl ConnectionTrait,
) -> Result<(), Error> {
    if let Some(detail) = detail.as_object_mut() {
        detail.insert("name".into(), json!(team.name));
        detail.insert("externalId".into(), json!(team.external_id));
    }

    audit::record(
        actor,
        Change {
            action,
            target_kind: "team",
            target_id: &team.id.to_string(),
            detail,
        },
        db,
    )
    .await?;

    Ok(())
}

fn conflict_on_duplicate(err: DbErr) -> Error {
    if err.is_duplicate() {
        Error::Conflict("The external ID is already in use".into())
    } else {
        err.into()
    }
}
