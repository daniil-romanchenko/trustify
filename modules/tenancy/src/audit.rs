//! Recording changes to the tenancy configuration.

use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait, NotSet};
use serde_json::Value;
use trustify_auth::authenticator::user::UserInformation;
use trustify_entity::audit_event;

/// The principal performing an operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actor {
    pub kind: &'static str,
    pub id: String,
}

impl Actor {
    /// Used for internal operations, not triggered by a request.
    pub fn system() -> Self {
        Self {
            kind: "system",
            id: "system".into(),
        }
    }
}

impl From<&UserInformation> for Actor {
    fn from(value: &UserInformation) -> Self {
        match value {
            UserInformation::Authenticated(details) => Self {
                kind: "user",
                id: details.id.clone(),
            },
            UserInformation::Anonymous => Self {
                kind: "anonymous",
                id: "anonymous".into(),
            },
        }
    }
}

/// A change to be recorded.
pub struct Change<'a> {
    pub action: &'static str,
    pub target_kind: &'static str,
    pub target_id: &'a str,
    pub detail: Value,
}

/// Record a change to the tenancy configuration.
///
/// This writes an audit event, and bumps the authorization revision, which invalidates cached
/// authorization information. It must be called using the same transaction as the change itself.
pub async fn record(
    actor: &Actor,
    change: Change<'_>,
    db: &impl ConnectionTrait,
) -> Result<(), DbErr> {
    log::info!(
        target: "audit",
        "{} {}/{} by {}:{}: {}",
        change.action,
        change.target_kind,
        change.target_id,
        actor.kind,
        actor.id,
        change.detail
    );

    audit_event::Entity::insert(audit_event::ActiveModel {
        id: NotSet,
        at: NotSet,
        actor_kind: Set(actor.kind.to_string()),
        actor_id: Set(actor.id.clone()),
        action: Set(change.action.to_string()),
        target_kind: Set(change.target_kind.to_string()),
        target_id: Set(change.target_id.to_string()),
        detail: Set(change.detail),
    })
    .exec_without_returning(db)
    .await?;

    db.execute_unprepared("UPDATE authz_revision SET value = value + 1")
        .await?;

    Ok(())
}
