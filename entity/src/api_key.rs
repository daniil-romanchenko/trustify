use crate::labels::Labels;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// An API key, allowing to upload SBOMs into SBOM groups.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "api_key")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,

    /// The public part of the key.
    pub key_id: String,
    /// HMAC of the secret part of the key.
    pub secret_hmac: Vec<u8>,

    pub name: String,
    pub permissions: Vec<String>,
    pub default_group: Option<Uuid>,
    pub labels: Labels,
    pub external_id: Option<String>,
    /// Network ranges (CIDR notation) the key may be used from, `None` for any.
    pub allowed_cidrs: Option<Vec<String>>,

    pub state: ApiKeyState,
    pub expires_at: time::OffsetDateTime,
    pub rotated_from: Option<Uuid>,

    pub created_at: time::OffsetDateTime,
    pub created_by: String,
    pub last_used_at: Option<time::OffsetDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl Related<super::sbom_group::Entity> for Entity {
    fn to() -> RelationDef {
        super::api_key_scope::Relation::Group.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::api_key_scope::Relation::ApiKey.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    EnumIter,
    DeriveActiveEnum,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[sea_orm(rs_type = "String", db_type = "Text")]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyState {
    #[sea_orm(string_value = "active")]
    Active,
    #[sea_orm(string_value = "revoked")]
    Revoked,
}
