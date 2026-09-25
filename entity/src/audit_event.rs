use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "audit_event")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,

    pub at: time::OffsetDateTime,

    pub actor_kind: String,
    pub actor_id: String,

    pub action: String,

    pub target_kind: String,
    pub target_id: String,

    pub detail: serde_json::Value,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
