//! Validation of bearer tokens which are not OIDC access tokens, like API keys.

use crate::authenticator::{error::AuthenticationError, user::UserDetails};
use std::collections::BTreeMap;

/// Validates bearer tokens, other than OIDC access tokens.
#[async_trait::async_trait]
pub trait TokenValidator: Send + Sync {
    /// Validate a token.
    ///
    /// Returns `None` if the token is not handled by this validator, so that other validators
    /// can try. Once a validator handles a token, the outcome is final.
    async fn validate(&self, token: &str) -> Option<Result<UserDetails, AuthenticationError>>;
}

/// Information about the API key a request was authenticated with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApiKeyInformation {
    /// The ID of the API key.
    pub id: String,
    /// The public part of the key.
    pub key_id: String,
    /// The IDs of the SBOM groups the key may upload into, including their descendants.
    pub groups: Vec<String>,
    /// The group to use when an upload doesn't request any.
    pub default_group: Option<String>,
    /// Labels to apply to each uploaded document.
    pub labels: BTreeMap<String, String>,
}
