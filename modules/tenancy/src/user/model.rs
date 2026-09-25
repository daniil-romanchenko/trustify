use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
pub use trustify_entity::principal_user::UserState;
use trustify_entity::{principal_user, role_binding::Role};
use utoipa::ToSchema;

/// A user, identified by their e-mail address.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct User {
    /// The ID of the user, assigned by the system.
    pub id: String,
    /// The e-mail address, lower-cased.
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// An optional ID, assigned by an external system.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub state: UserState,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub last_login: Option<OffsetDateTime>,
}

impl From<principal_user::Model> for User {
    fn from(value: principal_user::Model) -> Self {
        Self {
            id: value.id.to_string(),
            email: value.email,
            display_name: value.display_name,
            external_id: value.external_id,
            state: value.state,
            created_at: value.created_at,
            last_login: value.last_login,
        }
    }
}

/// Mutable properties of a [`User`].
#[derive(Serialize, Deserialize, Debug, Clone, Default, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UserRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// An optional ID, assigned by an external system, unique across all users.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Prevent the user from signing in. Existing role bindings are kept.
    #[serde(default)]
    pub disabled: bool,
}

/// Request to change the e-mail address of a user.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChangeEmailRequest {
    pub new_email: String,
}

/// How access was granted to a user.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum Via {
    /// Directly bound to the user.
    Direct,
    /// Bound to a team the user is a member of.
    Team {
        /// The ID of the team
        id: String,
    },
}

/// A role a user holds on a group, and all groups below it.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Access {
    /// The ID of the group the role was granted on.
    pub group: String,
    pub role: Role,
    pub via: Via,
}
