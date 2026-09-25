use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
pub use trustify_entity::api_key::ApiKeyState;
use trustify_entity::{api_key, labels::Labels};
use utoipa::ToSchema;

/// An API key, without its secret.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiKey {
    /// The ID of the key, assigned by the system.
    pub id: String,
    /// The public part of the token, e.g. for correlating with logs.
    pub key_id: String,
    pub name: String,
    /// The permissions granted by the key.
    pub permissions: Vec<String>,
    /// The IDs of the SBOM groups the key may upload into, including their descendants.
    pub groups: Vec<String>,
    /// The ID of the group uploads are assigned to, when they don't request any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_group: Option<String>,
    /// Labels applied to every uploaded document.
    #[serde(default, skip_serializing_if = "Labels::is_empty")]
    pub labels: Labels,
    /// An optional ID, assigned by an external system.
    ///
    /// The key can also be addressed using the key `ext:<external_id>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Network ranges (CIDR notation) the key may be used from, absent for any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_cidrs: Option<Vec<String>>,
    pub state: ApiKeyState,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
    /// The ID of the key this one replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_from: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    pub created_by: String,
    /// When the key was last used, with a granularity of a few minutes.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub last_used_at: Option<OffsetDateTime>,
}

impl ApiKey {
    pub fn new(model: api_key::Model, groups: Vec<String>) -> Self {
        Self {
            id: model.id.to_string(),
            key_id: model.key_id,
            name: model.name,
            permissions: model.permissions,
            groups,
            default_group: model.default_group.map(|id| id.to_string()),
            labels: model.labels,
            external_id: model.external_id,
            allowed_cidrs: model.allowed_cidrs,
            state: model.state,
            expires_at: model.expires_at,
            rotated_from: model.rotated_from.map(|id| id.to_string()),
            created_at: model.created_at,
            created_by: model.created_by,
            last_used_at: model.last_used_at,
        }
    }
}

/// A newly issued API key, including its token.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IssuedApiKey {
    #[serde(flatten)]
    pub key: ApiKey,
    /// The token to authenticate with. It is only returned once, and cannot be retrieved later.
    pub token: String,
}

/// Request to create a new API key.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyRequest {
    pub name: String,
    /// The SBOM groups the key may upload into, by ID or `ext:<external id>`.
    pub groups: Vec<String>,
    /// The group to assign uploads to, when they don't request any. Required when there is more
    /// than one group. Must be one of the groups, or one of their descendants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_group: Option<String>,
    /// The permissions of the key. Currently, only `create.sbom` is supported, which is the
    /// default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
    /// Labels applied to every uploaded document, overriding labels of the upload request.
    #[serde(default, skip_serializing_if = "Labels::is_empty")]
    pub labels: Labels,
    /// An optional ID, assigned by an external system, unique across all API keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Network ranges (CIDR notation, e.g. `10.0.0.0/8`) the key may be used from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_cidrs: Option<Vec<String>>,
}

/// Changes to an API key. Scopes and expiration can only be changed by rotating the key.
#[derive(Serialize, Deserialize, Debug, Clone, Default, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<Labels>,
    /// Replace the network ranges the key may be used from. An empty list allows any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_cidrs: Option<Vec<String>>,
}

/// Request to rotate an API key.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RotateRequest {
    /// How long the old key stays valid (humantime, e.g. "24h"), at most 7 days.
    #[serde(default = "default_grace_period")]
    pub grace_period: String,
    /// When the new key expires.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
}

fn default_grace_period() -> String {
    "24h".into()
}
