use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Grants a role, on an SBOM group and all its descendants, to either a user or a team.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "role_binding")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,

    pub group_id: Uuid,
    pub user_id: Option<Uuid>,
    pub team_id: Option<Uuid>,

    pub role: Role,

    pub created_at: time::OffsetDateTime,
    pub created_by: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::sbom_group::Entity",
        from = "Column::GroupId",
        to = "super::sbom_group::Column::Id"
    )]
    Group,
    #[sea_orm(
        belongs_to = "super::principal_user::Entity",
        from = "Column::UserId",
        to = "super::principal_user::Column::Id"
    )]
    User,
    #[sea_orm(
        belongs_to = "super::team::Entity",
        from = "Column::TeamId",
        to = "super::team::Column::Id"
    )]
    Team,
}

impl Related<super::sbom_group::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Group.def()
    }
}

impl Related<super::principal_user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl Related<super::team::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Team.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

/// A role on an SBOM group, each role includes all permissions of the ones before it.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    EnumIter,
    DeriveActiveEnum,
    Serialize,
    Deserialize,
    ToSchema,
    strum::Display,
    strum::EnumString,
)]
#[sea_orm(rs_type = "String", db_type = "Text")]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum Role {
    /// Read SBOMs and groups.
    #[sea_orm(string_value = "viewer")]
    Viewer,
    /// Viewer, plus uploading SBOMs.
    #[sea_orm(string_value = "uploader")]
    Uploader,
    /// Uploader, plus updating and deleting SBOMs and their group assignments.
    #[sea_orm(string_value = "editor")]
    Editor,
    /// Editor, plus managing child groups, role bindings, and API keys.
    #[sea_orm(string_value = "admin")]
    Admin,
}
