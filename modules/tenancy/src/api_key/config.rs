use crate::scope::AuthzMode;
use std::time::Duration;

/// Minimum length of the API key pepper.
pub const MIN_PEPPER_LENGTH: usize = 32;

#[derive(clap::Args, Debug, Clone)]
#[command(next_help_heading = "Tenancy")]
pub struct TenancyConfig {
    /// Server side secret, used to derive the stored hashes of API keys.
    ///
    /// Must be at least 32 characters. API keys are disabled when not set. Changing it
    /// invalidates all existing API keys.
    #[arg(
        long,
        env = "TRUSTD_API_KEY_PEPPER",
        hide_env_values = true,
        value_parser = parse_pepper
    )]
    pub api_key_pepper: Option<String>,

    /// The previous API key pepper, while rotating it.
    ///
    /// Keys created with the previous pepper keep working, and are migrated to the current pepper
    /// on their next use.
    #[arg(
        long,
        env = "TRUSTD_API_KEY_PEPPER_PREVIOUS",
        hide_env_values = true,
        value_parser = parse_pepper
    )]
    pub api_key_pepper_previous: Option<String>,

    /// Use the client address reported by a proxy (`Forwarded`, `X-Forwarded-For`) for API keys.
    ///
    /// Only enable this when running behind a proxy which sets these headers, as clients can forge
    /// them otherwise. The address is used for rate limiting failed attempts, and for the allowed
    /// network ranges of API keys.
    #[arg(
        long,
        env = "TRUSTD_API_KEY_TRUST_FORWARDED_FOR",
        default_value_t = false
    )]
    pub api_key_trust_forwarded_for: bool,

    /// The maximum lifetime of an API key (humantime, e.g. "90d")
    #[arg(long, env = "TRUSTD_API_KEY_MAX_TTL", default_value = "365d")]
    pub api_key_max_ttl: humantime::Duration,

    /// Don't create users on their first sign-in. Only users provisioned upfront get linked.
    #[arg(long, env = "TRUSTD_NO_JUST_IN_TIME_USERS", default_value_t = false)]
    pub no_just_in_time_users: bool,

    /// How access to SBOMs is authorized: only using global permissions, or scoped to the
    /// SBOM groups a user holds a role on.
    #[arg(long, env = "TRUSTD_AUTHZ_MODE", value_enum, default_value_t = AuthzMode::Global)]
    pub authz_mode: AuthzMode,

    /// How long audit events are kept (humantime, e.g. "400d")
    #[arg(long, env = "TRUSTD_AUDIT_RETENTION", default_value = "400d")]
    pub audit_retention: humantime::Duration,
}

impl Default for TenancyConfig {
    fn default() -> Self {
        Self {
            api_key_pepper: None,
            api_key_pepper_previous: None,
            api_key_trust_forwarded_for: false,
            api_key_max_ttl: Duration::from_secs(365 * 24 * 60 * 60).into(),
            no_just_in_time_users: false,
            authz_mode: AuthzMode::Global,
            audit_retention: Duration::from_secs(400 * 24 * 60 * 60).into(),
        }
    }
}

fn parse_pepper(value: &str) -> Result<String, String> {
    if value.len() < MIN_PEPPER_LENGTH {
        Err(format!(
            "the API key pepper must be at least {MIN_PEPPER_LENGTH} characters"
        ))
    } else {
        Ok(value.to_string())
    }
}
