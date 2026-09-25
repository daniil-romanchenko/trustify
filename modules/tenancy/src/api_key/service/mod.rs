#[cfg(test)]
mod test;

use crate::{
    Error,
    api_key::{
        config::TenancyConfig,
        model::{ApiKey, ApiKeyPatch, ApiKeyRequest, ApiKeyState, IssuedApiKey, RotateRequest},
        token::{Pepper, Token},
    },
    audit::{self, Actor, Change},
    group::{expand_groups, resolve_group},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, IntoActiveModel,
    QueryFilter, QueryOrder, QuerySelect, Set,
};
use sea_query::{Expr, OnConflict};
use serde_json::json;
use std::{collections::HashMap, time::Duration};
use time::OffsetDateTime;
use trustify_auth::{Permission, authenticator::token::ApiKeyInformation};
use trustify_common::{
    db::{DatabaseErrors, limiter::LimiterTrait, pagination_cache::PaginationCache},
    model::{PaginatedResults, Pagination},
    resource_key::{ResourceKey, validate_external_id},
};
use trustify_entity::{api_key, api_key_scope};
use uuid::Uuid;

/// The maximum number of groups an API key can be scoped to.
const MAX_GROUPS: usize = 50;
/// The maximum grace period, when rotating a key.
const MAX_GRACE_PERIOD: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Filter for listing API keys.
#[derive(Clone, Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct ListOptions {
    /// Only keys scoped to this group (ID, or `ext:<external id>`).
    #[serde(default)]
    pub group: Option<String>,
    /// Only keys in this state.
    #[serde(default)]
    #[param(inline)]
    pub state: Option<ApiKeyState>,
}

#[derive(Clone)]
pub struct ApiKeyService {
    pepper: Option<Pepper>,
    max_ttl: Duration,
    cache: PaginationCache,
}

impl ApiKeyService {
    pub fn new(config: &TenancyConfig, cache: PaginationCache) -> Self {
        let pepper = config
            .api_key_pepper
            .as_deref()
            .map(|pepper| Pepper::new(pepper.as_bytes()));
        if pepper.is_none() {
            log::info!("API keys are disabled, no pepper configured");
        }

        Self {
            pepper,
            max_ttl: config.api_key_max_ttl.into(),
            cache,
        }
    }

    /// Whether API keys are enabled.
    pub fn enabled(&self) -> bool {
        self.pepper.is_some()
    }

    fn pepper(&self) -> Result<&Pepper, Error> {
        self.pepper.as_ref().ok_or(Error::Disabled("API keys"))
    }

    /// Create a new API key.
    pub async fn create(
        &self,
        request: ApiKeyRequest,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<IssuedApiKey, Error> {
        let pepper = self.pepper()?;

        if request.name.trim().is_empty() {
            return Err(Error::bad_request(
                "Invalid API key",
                Some("name must not be empty"),
            ));
        }
        if let Some(external_id) = &request.external_id {
            validate_external_id(external_id)
                .map_err(|err| Error::bad_request("Invalid external ID", Some(err.to_string())))?;
        }
        let labels = request
            .labels
            .validate()
            .map_err(|err| Error::bad_request("Invalid labels", Some(err.to_string())))?;
        let permissions = validate_permissions(request.permissions)?;
        self.validate_expiration(request.expires_at)?;

        let groups = resolve_groups(&request.groups, db).await?;
        let default_group =
            resolve_default_group(request.default_group.as_deref(), &groups, db).await?;

        let token = Token::generate().map_err(|err| Error::Internal(err.to_string()))?;
        let model = api_key::ActiveModel {
            id: Set(Uuid::now_v7()),
            key_id: Set(token.key_id.clone()),
            secret_hmac: Set(pepper.sign(&token)),
            name: Set(request.name),
            permissions: Set(permissions),
            default_group: Set(Some(default_group)),
            labels: Set(labels),
            external_id: Set(request.external_id),
            state: Set(ApiKeyState::Active),
            expires_at: Set(request.expires_at),
            rotated_from: Set(None),
            created_at: Set(OffsetDateTime::now_utc()),
            created_by: Set(actor.id.clone()),
            last_used_at: Set(None),
        }
        .insert(db)
        .await
        .map_err(conflict_on_duplicate)?;

        insert_scopes(model.id, &groups, db).await?;
        record(actor, "create", &model, json!({"groups": groups}), db).await?;

        Ok(IssuedApiKey {
            key: ApiKey::new(model, to_strings(&groups)),
            token: token.expose(),
        })
    }

    /// List API keys.
    pub async fn list(
        &self,
        options: ListOptions,
        paginated: impl Pagination,
        db: &impl ConnectionTrait,
    ) -> Result<PaginatedResults<ApiKey>, Error> {
        let mut select = api_key::Entity::find()
            .order_by_desc(api_key::Column::CreatedAt)
            .order_by_asc(api_key::Column::Id);

        if let Some(group) = &options.group {
            let Some(group) = resolve_group(group, db).await? else {
                return Ok(PaginatedResults::default());
            };
            select = select.filter(
                api_key::Column::Id.in_subquery(
                    sea_query::Query::select()
                        .column(api_key_scope::Column::ApiKeyId)
                        .from(api_key_scope::Entity)
                        .and_where(Expr::col(api_key_scope::Column::GroupId).eq(group))
                        .to_owned(),
                ),
            );
        }
        if let Some(state) = options.state {
            select = select.filter(api_key::Column::State.eq(state));
        }

        let limiter = select.limiting(db, paginated, &self.cache)?;
        let result = PaginatedResults::<api_key::Model>::new(limiter, paginated).await?;

        let mut scopes = load_scopes(result.items.iter().map(|key| key.id).collect(), db).await?;

        Ok(PaginatedResults {
            items: result
                .items
                .into_iter()
                .map(|key| {
                    let groups = scopes.remove(&key.id).unwrap_or_default();
                    ApiKey::new(key, to_strings(&groups))
                })
                .collect(),
            total: result.total,
        })
    }

    /// Find an API key by its key.
    async fn find(
        &self,
        key: &ResourceKey,
        db: &impl ConnectionTrait,
    ) -> Result<Option<api_key::Model>, Error> {
        let select = api_key::Entity::find();
        let select = match key {
            ResourceKey::Id(id) => select.filter(api_key::Column::Id.eq(*id)),
            ResourceKey::External(id) => select.filter(api_key::Column::ExternalId.eq(id)),
        };
        Ok(select.one(db).await?)
    }

    async fn find_or_fail(
        &self,
        key: &ResourceKey,
        db: &impl ConnectionTrait,
    ) -> Result<api_key::Model, Error> {
        self.find(key, db)
            .await?
            .ok_or_else(|| Error::NotFound(format!("API key '{key}'")))
    }

    /// Read an API key.
    pub async fn read(
        &self,
        key: &ResourceKey,
        db: &impl ConnectionTrait,
    ) -> Result<Option<ApiKey>, Error> {
        let Some(model) = self.find(key, db).await? else {
            return Ok(None);
        };
        let groups = load_scopes(vec![model.id], db)
            .await?
            .remove(&model.id)
            .unwrap_or_default();
        Ok(Some(ApiKey::new(model, to_strings(&groups))))
    }

    /// Change the name or labels of an API key.
    pub async fn patch(
        &self,
        key: &ResourceKey,
        patch: ApiKeyPatch,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<ApiKey, Error> {
        let existing = self.find_or_fail(key, db).await?;

        let mut model = existing.into_active_model();
        if let Some(name) = patch.name {
            if name.trim().is_empty() {
                return Err(Error::bad_request(
                    "Invalid API key",
                    Some("name must not be empty"),
                ));
            }
            model.name = Set(name);
        }
        if let Some(labels) = patch.labels {
            let labels = labels
                .validate()
                .map_err(|err| Error::bad_request("Invalid labels", Some(err.to_string())))?;
            model.labels = Set(labels);
        }

        let model = model.update(db).await?;
        record(actor, "update", &model, json!({}), db).await?;

        let key = ResourceKey::Id(model.id);
        self.read(&key, db)
            .await?
            .ok_or_else(|| Error::NotFound(format!("API key '{key}'")))
    }

    /// Rotate an API key.
    ///
    /// This creates a new key, with the same scopes, and lets the old key expire after the grace
    /// period. An external ID moves to the new key.
    pub async fn rotate(
        &self,
        key: &ResourceKey,
        request: RotateRequest,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<IssuedApiKey, Error> {
        let pepper = self.pepper()?;

        let grace: Duration = request
            .grace_period
            .parse::<humantime::Duration>()
            .map_err(|err| Error::bad_request("Invalid grace period", Some(err.to_string())))?
            .into();
        if grace > MAX_GRACE_PERIOD {
            return Err(Error::bad_request(
                "Invalid grace period",
                Some("must not be longer than 7 days"),
            ));
        }
        self.validate_expiration(request.expires_at)?;

        let old = self.find_or_fail(key, db).await?;
        let now = OffsetDateTime::now_utc();
        if old.state != ApiKeyState::Active || old.expires_at <= now {
            return Err(Error::Conflict("Only active keys can be rotated".into()));
        }

        let groups = load_scopes(vec![old.id], db)
            .await?
            .remove(&old.id)
            .unwrap_or_default();

        // the old key expires after the grace period, and passes on its external ID

        let old_expires_at = old.expires_at.min(now + grace);
        let external_id = old.external_id.clone();
        let mut old_model = old.clone().into_active_model();
        old_model.expires_at = Set(old_expires_at);
        old_model.external_id = Set(None);
        let old = old_model.update(db).await?;

        let token = Token::generate().map_err(|err| Error::Internal(err.to_string()))?;
        let model = api_key::ActiveModel {
            id: Set(Uuid::now_v7()),
            key_id: Set(token.key_id.clone()),
            secret_hmac: Set(pepper.sign(&token)),
            name: Set(old.name.clone()),
            permissions: Set(old.permissions.clone()),
            default_group: Set(old.default_group),
            labels: Set(old.labels.clone()),
            external_id: Set(external_id),
            state: Set(ApiKeyState::Active),
            expires_at: Set(request.expires_at),
            rotated_from: Set(Some(old.id)),
            created_at: Set(now),
            created_by: Set(actor.id.clone()),
            last_used_at: Set(None),
        }
        .insert(db)
        .await
        .map_err(conflict_on_duplicate)?;

        insert_scopes(model.id, &groups, db).await?;
        record(
            actor,
            "rotate",
            &model,
            json!({"from": old.id, "oldExpiresAt": old_expires_at.to_string()}),
            db,
        )
        .await?;

        Ok(IssuedApiKey {
            key: ApiKey::new(model, to_strings(&groups)),
            token: token.expose(),
        })
    }

    /// Revoke an API key.
    ///
    /// Returns `true` if the key existed.
    pub async fn revoke(
        &self,
        key: &ResourceKey,
        actor: &Actor,
        db: &impl ConnectionTrait,
    ) -> Result<bool, Error> {
        let Some(existing) = self.find(key, db).await? else {
            return Ok(false);
        };

        if existing.state == ApiKeyState::Revoked {
            return Ok(true);
        }

        let mut model = existing.into_active_model();
        model.state = Set(ApiKeyState::Revoked);
        let model = model.update(db).await?;
        record(actor, "revoke", &model, json!({}), db).await?;

        Ok(true)
    }

    /// Load a usable (active, not expired) key by its public key ID.
    ///
    /// This does not verify the secret, use [`Self::verify`] for that.
    pub async fn load(
        &self,
        key_id: &str,
        db: &impl ConnectionTrait,
    ) -> Result<Option<(api_key::Model, ApiKeyInformation)>, Error> {
        let Some(model) = api_key::Entity::find()
            .filter(api_key::Column::KeyId.eq(key_id))
            .one(db)
            .await?
        else {
            return Ok(None);
        };

        if model.state != ApiKeyState::Active || model.expires_at <= OffsetDateTime::now_utc() {
            return Ok(None);
        }

        let groups = load_scopes(vec![model.id], db)
            .await?
            .remove(&model.id)
            .unwrap_or_default();
        let groups = expand_groups(&groups, db).await?;

        let info = ApiKeyInformation {
            id: model.id.to_string(),
            key_id: model.key_id.clone(),
            groups: to_strings(&groups),
            default_group: model.default_group.map(|id| id.to_string()),
            labels: model
                .labels
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };

        Ok(Some((model, info)))
    }

    /// Verify, in constant time, that a token matches a key.
    pub fn verify(&self, token: &Token, key: &api_key::Model) -> Result<bool, Error> {
        Ok(token.key_id == key.key_id && self.pepper()?.verify(token, &key.secret_hmac))
    }

    fn validate_expiration(&self, expires_at: OffsetDateTime) -> Result<(), Error> {
        let now = OffsetDateTime::now_utc();
        if expires_at <= now {
            return Err(Error::bad_request(
                "Invalid expiration",
                Some("must be in the future"),
            ));
        }
        if expires_at > now + self.max_ttl {
            return Err(Error::bad_request(
                "Invalid expiration",
                Some(format!(
                    "must not be later than {}",
                    humantime::format_duration(self.max_ttl)
                )),
            ));
        }
        Ok(())
    }
}

/// Record the use of a key, if it wasn't recorded recently.
pub async fn touch(
    key: &api_key::Model,
    interval: Duration,
    db: &impl ConnectionTrait,
) -> Result<(), DbErr> {
    let now = OffsetDateTime::now_utc();
    if key.last_used_at.is_some_and(|last| now - last < interval) {
        return Ok(());
    }

    api_key::Entity::update_many()
        .col_expr(api_key::Column::LastUsedAt, Expr::value(now))
        .filter(api_key::Column::Id.eq(key.id))
        .exec(db)
        .await?;

    Ok(())
}

fn validate_permissions(permissions: Option<Vec<String>>) -> Result<Vec<String>, Error> {
    let allowed = Permission::CreateSbom.to_string();
    let permissions = permissions.unwrap_or_else(|| vec![allowed.clone()]);

    if permissions.is_empty() || permissions.iter().any(|p| p != &allowed) {
        return Err(Error::bad_request(
            "Invalid permissions",
            Some(format!("only '{allowed}' is supported")),
        ));
    }

    Ok(vec![allowed])
}

async fn resolve_groups(keys: &[String], db: &impl ConnectionTrait) -> Result<Vec<Uuid>, Error> {
    if keys.is_empty() || keys.len() > MAX_GROUPS {
        return Err(Error::bad_request(
            "Invalid groups",
            Some(format!("between 1 and {MAX_GROUPS} groups are required")),
        ));
    }

    let mut result = Vec::with_capacity(keys.len());
    for key in keys {
        let group = resolve_group(key, db)
            .await?
            .ok_or_else(|| Error::bad_request("Unknown group", Some(key.clone())))?;
        if !result.contains(&group) {
            result.push(group);
        }
    }

    Ok(result)
}

async fn resolve_default_group(
    key: Option<&str>,
    groups: &[Uuid],
    db: &impl ConnectionTrait,
) -> Result<Uuid, Error> {
    let Some(key) = key else {
        return match groups {
            [single] => Ok(*single),
            _ => Err(Error::bad_request(
                "Missing default group",
                Some("a default group is required when using more than one group"),
            )),
        };
    };

    let group = resolve_group(key, db)
        .await?
        .ok_or_else(|| Error::bad_request("Unknown group", Some(key.to_string())))?;

    if !expand_groups(groups, db).await?.contains(&group) {
        return Err(Error::bad_request(
            "Invalid default group",
            Some("the default group must be one of the groups, or one of their descendants"),
        ));
    }

    Ok(group)
}

async fn insert_scopes(
    api_key_id: Uuid,
    groups: &[Uuid],
    db: &impl ConnectionTrait,
) -> Result<(), Error> {
    api_key_scope::Entity::insert_many(groups.iter().map(|group| api_key_scope::ActiveModel {
        api_key_id: Set(api_key_id),
        group_id: Set(*group),
    }))
    .on_conflict(
        OnConflict::columns([
            api_key_scope::Column::ApiKeyId,
            api_key_scope::Column::GroupId,
        ])
        .do_nothing()
        .to_owned(),
    )
    .do_nothing()
    .exec(db)
    .await?;

    Ok(())
}

async fn load_scopes(
    keys: Vec<Uuid>,
    db: &impl ConnectionTrait,
) -> Result<HashMap<Uuid, Vec<Uuid>>, Error> {
    if keys.is_empty() {
        return Ok(HashMap::new());
    }

    let rows = api_key_scope::Entity::find()
        .select_only()
        .column(api_key_scope::Column::ApiKeyId)
        .column(api_key_scope::Column::GroupId)
        .filter(api_key_scope::Column::ApiKeyId.is_in(keys))
        .order_by_asc(api_key_scope::Column::GroupId)
        .into_tuple::<(Uuid, Uuid)>()
        .all(db)
        .await?;

    let mut result: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for (key, group) in rows {
        result.entry(key).or_default().push(group);
    }
    Ok(result)
}

fn to_strings(ids: &[Uuid]) -> Vec<String> {
    ids.iter().map(ToString::to_string).collect()
}

async fn record(
    actor: &Actor,
    action: &'static str,
    key: &api_key::Model,
    mut detail: serde_json::Value,
    db: &impl ConnectionTrait,
) -> Result<(), Error> {
    if let Some(detail) = detail.as_object_mut() {
        detail.insert("keyId".into(), json!(key.key_id));
        detail.insert("name".into(), json!(key.name));
        detail.insert("externalId".into(), json!(key.external_id));
        detail.insert("expiresAt".into(), json!(key.expires_at.to_string()));
    }

    audit::record(
        actor,
        Change {
            action,
            target_kind: "api-key",
            target_id: &key.id.to_string(),
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
