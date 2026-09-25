//! Reading the audit log.

#[cfg(test)]
mod test;

use crate::{Error, authz::ManageAccess};
use actix_web::{HttpResponse, Responder, get, web};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use trustify_common::{
    db::{self, limiter::LimiterTrait, pagination_cache::PaginationCache},
    model::{Paginated, PaginatedResults},
};
use trustify_entity::audit_event;
use utoipa::{IntoParams, ToSchema};

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig) {
    config.service(list);
}

/// A recorded change to the tenancy configuration.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: i64,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub at: OffsetDateTime,
    /// The kind of principal performing the change, e.g. `user` or `system`.
    pub actor_kind: String,
    pub actor_id: String,
    pub action: String,
    /// The kind of the changed resource, e.g. `user`, `team`, `group`, or `api-key`.
    pub target_kind: String,
    pub target_id: String,
    #[schema(value_type = Object)]
    pub detail: serde_json::Value,
}

impl From<audit_event::Model> for AuditEvent {
    fn from(value: audit_event::Model) -> Self {
        Self {
            id: value.id,
            at: value.at,
            actor_kind: value.actor_kind,
            actor_id: value.actor_id,
            action: value.action,
            target_kind: value.target_kind,
            target_id: value.target_id,
            detail: value.detail,
        }
    }
}

/// Filters for the audit log.
#[derive(Clone, Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct AuditQuery {
    /// Only events of this kind of target, e.g. `user`.
    #[serde(default)]
    pub target_kind: Option<String>,
    /// Only events of this target.
    #[serde(default)]
    pub target_id: Option<String>,
    /// Only events of this actor.
    #[serde(default)]
    pub actor_id: Option<String>,
    /// Only events of this action, e.g. `create`.
    #[serde(default)]
    pub action: Option<String>,
    /// Only events at, or after, this time (RFC 3339).
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(value_type = Option<String>, format = DateTime)]
    pub since: Option<OffsetDateTime>,
}

#[utoipa::path(
    tag = "tenancy",
    operation_id = "listAuditEvents",
    params(AuditQuery, Paginated),
    responses(
        (status = 200, description = "Matching audit events, newest first", body = PaginatedResults<AuditEvent>),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    )
)]
#[get("/v3/audit")]
/// List audit events
async fn list(
    db: web::Data<db::ReadOnly>,
    cache: web::Data<PaginationCache>,
    web::Query(query): web::Query<AuditQuery>,
    web::Query(paginated): web::Query<Paginated>,
    manage: ManageAccess,
) -> Result<impl Responder, Error> {
    manage.require_global()?;

    let mut select = audit_event::Entity::find().order_by_desc(audit_event::Column::Id);
    if let Some(value) = query.target_kind {
        select = select.filter(audit_event::Column::TargetKind.eq(value));
    }
    if let Some(value) = query.target_id {
        select = select.filter(audit_event::Column::TargetId.eq(value));
    }
    if let Some(value) = query.actor_id {
        select = select.filter(audit_event::Column::ActorId.eq(value));
    }
    if let Some(value) = query.action {
        select = select.filter(audit_event::Column::Action.eq(value));
    }
    if let Some(value) = query.since {
        select = select.filter(audit_event::Column::At.gte(value));
    }

    let tx = db.begin().await?;
    let limiter = select.limiting(&tx, paginated, &cache)?;
    let result = PaginatedResults::<audit_event::Model>::new(limiter, paginated).await?;

    Ok(HttpResponse::Ok().json(PaginatedResults {
        items: result
            .items
            .into_iter()
            .map(AuditEvent::from)
            .collect::<Vec<_>>(),
        total: result.total,
    }))
}
