use sea_orm::entity::prelude::*;

/// An SBOM group an API key may upload into.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "api_key_scope")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub api_key_id: Uuid,
    #[sea_orm(primary_key)]
    pub group_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::api_key::Entity",
        from = "Column::ApiKeyId",
        to = "super::api_key::Column::Id"
    )]
    ApiKey,
    #[sea_orm(
        belongs_to = "super::sbom_group::Entity",
        from = "Column::GroupId",
        to = "super::sbom_group::Column::Id"
    )]
    Group,
}

impl ActiveModelBehavior for ActiveModel {}
