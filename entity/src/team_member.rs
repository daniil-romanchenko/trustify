use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "team_member")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub team_id: Uuid,
    #[sea_orm(primary_key)]
    pub user_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::team::Entity",
        from = "Column::TeamId",
        to = "super::team::Column::Id"
    )]
    Team,
    #[sea_orm(
        belongs_to = "super::principal_user::Entity",
        from = "Column::UserId",
        to = "super::principal_user::Column::Id"
    )]
    User,
}

impl ActiveModelBehavior for ActiveModel {}
