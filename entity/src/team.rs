use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "team")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,

    pub name: String,
    pub description: Option<String>,
    pub external_id: Option<String>,

    pub revision: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl Related<super::team_member::Entity> for Entity {
    fn to() -> RelationDef {
        super::team_member::Relation::Team.def().rev()
    }
}

impl Related<super::role_binding::Entity> for Entity {
    fn to() -> RelationDef {
        super::role_binding::Relation::Team.def().rev()
    }
}

impl Related<super::principal_user::Entity> for Entity {
    fn to() -> RelationDef {
        super::team_member::Relation::User.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::team_member::Relation::Team.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
