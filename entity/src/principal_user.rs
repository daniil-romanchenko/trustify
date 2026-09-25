use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "principal_user")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,

    /// The e-mail address, always stored lower-cased.
    pub email: String,

    pub oidc_issuer: Option<String>,
    pub oidc_sub: Option<String>,

    pub display_name: Option<String>,
    pub external_id: Option<String>,

    pub state: UserState,

    pub created_at: time::OffsetDateTime,
    pub last_login: Option<time::OffsetDateTime>,

    pub revision: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl Related<super::team_member::Entity> for Entity {
    fn to() -> RelationDef {
        super::team_member::Relation::User.def().rev()
    }
}

impl Related<super::role_binding::Entity> for Entity {
    fn to() -> RelationDef {
        super::role_binding::Relation::User.def().rev()
    }
}

impl Related<super::team::Entity> for Entity {
    fn to() -> RelationDef {
        super::team_member::Relation::Team.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::team_member::Relation::User.def().rev())
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
pub enum UserState {
    /// Provisioned, but never signed in.
    #[sea_orm(string_value = "invited")]
    Invited,
    /// Signed in at least once, and linked to an OIDC subject.
    #[sea_orm(string_value = "active")]
    Active,
    /// Not allowed to sign in.
    #[sea_orm(string_value = "disabled")]
    Disabled,
}
