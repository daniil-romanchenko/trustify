//! Keys addressing resources by either their system-assigned ID or an external ID.
//!
//! External IDs are assigned by an external system (e.g. an orchestration platform), allowing it
//! to address resources without having to remember the IDs Trustify assigned.

use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};
use uuid::Uuid;

/// Prefix of a [`ResourceKey`] which references an external ID.
pub const EXTERNAL_ID_PREFIX: &str = "ext:";

/// Maximum length of an external ID.
pub const MAX_EXTERNAL_ID_LENGTH: usize = 255;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResourceKeyError {
    #[error(
        "invalid resource key '{0}': expected a UUID, 'urn:uuid:<uuid>', or 'ext:<external id>'"
    )]
    Invalid(String),
    #[error(transparent)]
    ExternalId(#[from] ExternalIdError),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExternalIdError {
    #[error("external ID must not be empty")]
    Empty,
    #[error("external ID must not be longer than {MAX_EXTERNAL_ID_LENGTH} characters")]
    TooLong,
    #[error(
        "external ID must only contain ASCII letters, digits, and the characters '.', '_', '-', ':', '/'"
    )]
    InvalidCharacter,
}

/// Ensure an external ID is valid.
pub fn validate_external_id(value: &str) -> Result<(), ExternalIdError> {
    if value.is_empty() {
        return Err(ExternalIdError::Empty);
    }
    if value.len() > MAX_EXTERNAL_ID_LENGTH {
        return Err(ExternalIdError::TooLong);
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/'))
    {
        return Err(ExternalIdError::InvalidCharacter);
    }
    Ok(())
}

/// A key referencing a resource, either by ID or by external ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceKey {
    Id(Uuid),
    External(String),
}

impl ResourceKey {
    /// Get the external ID, if this key is an external key.
    pub fn external_id(&self) -> Option<&str> {
        match self {
            Self::Id(_) => None,
            Self::External(id) => Some(id),
        }
    }
}

impl FromStr for ResourceKey {
    type Err = ResourceKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(external) = s.strip_prefix(EXTERNAL_ID_PREFIX) {
            validate_external_id(external)?;
            return Ok(Self::External(external.to_string()));
        }

        let id = s.strip_prefix("urn:uuid:").unwrap_or(s);
        Uuid::parse_str(id)
            .map(Self::Id)
            .map_err(|_| ResourceKeyError::Invalid(s.to_string()))
    }
}

impl Display for ResourceKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Id(id) => write!(f, "{id}"),
            Self::External(id) => write!(f, "{EXTERNAL_ID_PREFIX}{id}"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("ext:acme.payments", Ok(ResourceKey::External("acme.payments".into())))]
    #[case("ext:a/b:c-d_e", Ok(ResourceKey::External("a/b:c-d_e".into())))]
    #[case("ext:", Err(ResourceKeyError::ExternalId(ExternalIdError::Empty)))]
    #[case(
        "ext:a b",
        Err(ResourceKeyError::ExternalId(ExternalIdError::InvalidCharacter))
    )]
    #[case(
        "0199b9b4-6b6c-7000-8000-000000000001",
        Ok(ResourceKey::Id(Uuid::from_u128(0x0199b9b4_6b6c_7000_8000_000000000001)))
    )]
    #[case(
        "urn:uuid:0199b9b4-6b6c-7000-8000-000000000001",
        Ok(ResourceKey::Id(Uuid::from_u128(0x0199b9b4_6b6c_7000_8000_000000000001)))
    )]
    #[case("foo", Err(ResourceKeyError::Invalid("foo".into())))]
    fn parse(#[case] input: &str, #[case] expected: Result<ResourceKey, ResourceKeyError>) {
        assert_eq!(input.parse::<ResourceKey>(), expected);
    }

    #[test]
    fn too_long() {
        let value = "a".repeat(MAX_EXTERNAL_ID_LENGTH + 1);
        assert_eq!(validate_external_id(&value), Err(ExternalIdError::TooLong));
    }
}
