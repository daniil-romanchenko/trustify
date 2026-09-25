use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
pub use trustify_entity::role_binding::Role;
use utoipa::ToSchema;

/// A reference to a principal: a user by e-mail, or a team by key.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum PrincipalRef {
    /// The e-mail address of a user.
    User(String),
    /// The ID of a team, or `ext:<external id>`.
    Team(String),
}

/// A role granted to a principal, on a group and all groups below it.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Binding {
    /// The principal holding the role. Teams are referenced by their ID.
    pub principal: PrincipalRef,
    pub role: Role,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    /// The ID of the principal who created the binding.
    pub created_by: String,
}

/// A role to grant to a principal.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BindingRequest {
    pub principal: PrincipalRef,
    pub role: Role,
}

/// A role to grant.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RoleRequest {
    pub role: Role,
}
