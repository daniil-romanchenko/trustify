use serde::{Deserialize, Serialize};
use trustify_entity::{principal_user, team};
use utoipa::ToSchema;

use crate::user::model::UserState;

/// A team, a set of users, which can be granted roles as a unit.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Team {
    /// The ID of the team, assigned by the system.
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// An optional ID, assigned by an external system.
    ///
    /// The team can also be addressed using the key `ext:<external_id>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

impl From<team::Model> for Team {
    fn from(value: team::Model) -> Self {
        Self {
            id: value.id.to_string(),
            name: value.name,
            description: value.description,
            external_id: value.external_id,
        }
    }
}

/// Mutable properties of a [`Team`].
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TeamRequest {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// An optional ID, assigned by an external system, unique across all teams.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

/// A member of a team.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub state: UserState,
}

impl From<principal_user::Model> for Member {
    fn from(value: principal_user::Model) -> Self {
        Self {
            email: value.email,
            display_name: value.display_name,
            state: value.state,
        }
    }
}

/// Replace all members of a team.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MembersRequest {
    /// The e-mail addresses of the members. Unknown users will be created as invited.
    pub emails: Vec<String>,
}

/// Add and remove members of a team.
#[derive(Serialize, Deserialize, Debug, Clone, Default, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MembersPatch {
    /// E-mail addresses of members to add. Unknown users will be created as invited.
    #[serde(default)]
    pub add: Vec<String>,
    /// E-mail addresses of members to remove.
    #[serde(default)]
    pub remove: Vec<String>,
}
