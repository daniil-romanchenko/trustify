//! Authenticating requests using API keys.

use crate::api_key::{
    service::{ApiKeyService, touch},
    token::{PREFIX, Token},
};
use moka::future::Cache;
use std::time::Duration;
use time::OffsetDateTime;
use trustify_auth::authenticator::{
    error::AuthenticationError,
    token::{ApiKeyInformation, TokenValidator},
    user::UserDetails,
};
use trustify_common::db;
use trustify_entity::api_key;

/// Time a key is cached, before it is looked up again.
///
/// This is the maximum time it takes for a revocation to take effect on other instances.
const CACHE_TTL: Duration = Duration::from_secs(60);
const CACHE_CAPACITY: u64 = 10_000;
/// Minimum time between recording the use of a key.
const TOUCH_INTERVAL: Duration = Duration::from_secs(5 * 60);

type CachedKey = Option<(api_key::Model, ApiKeyInformation)>;

/// Validates API key tokens (`tfy_…`).
#[derive(Clone)]
pub struct ApiKeyValidator {
    service: ApiKeyService,
    db: db::ReadWrite,
    /// Usable keys, by key ID. The secret is still verified for every request.
    keys: Cache<String, CachedKey>,
    /// Keys which recently had their use recorded.
    touched: Cache<String, ()>,
}

impl ApiKeyValidator {
    pub fn new(service: ApiKeyService, db: db::ReadWrite) -> Self {
        Self {
            service,
            db,
            keys: Cache::builder()
                .max_capacity(CACHE_CAPACITY)
                .time_to_live(CACHE_TTL)
                .build(),
            touched: Cache::builder()
                .max_capacity(CACHE_CAPACITY)
                .time_to_live(TOUCH_INTERVAL)
                .build(),
        }
    }

    /// Drop all cached keys, e.g. after keys have been changed.
    pub fn invalidate(&self) {
        self.keys.invalidate_all();
    }

    async fn load(&self, key_id: &str) -> CachedKey {
        let result = self
            .keys
            .try_get_with(key_id.to_string(), self.service.load(key_id, &self.db))
            .await;

        match result {
            Ok(key) => key,
            Err(err) => {
                log::warn!("Failed to load API key '{key_id}': {err}");
                None
            }
        }
    }

    async fn touch(&self, key: &api_key::Model) {
        if self.touched.contains_key(&key.key_id) {
            return;
        }
        self.touched.insert(key.key_id.clone(), ()).await;

        if let Err(err) = touch(key, TOUCH_INTERVAL, &self.db).await {
            // e.g. in read-only mode
            log::debug!("Unable to record use of API key '{}': {err}", key.key_id);
        }
    }
}

#[async_trait::async_trait]
impl TokenValidator for ApiKeyValidator {
    async fn validate(&self, token: &str) -> Option<Result<UserDetails, AuthenticationError>> {
        if !token.starts_with(PREFIX) {
            return None;
        }

        let Ok(token) = Token::parse(token) else {
            return Some(Err(AuthenticationError::Failed));
        };

        let Some((model, info)) = self.load(&token.key_id).await else {
            log::info!("Rejected unknown or unusable API key '{}'", token.key_id);
            return Some(Err(AuthenticationError::Failed));
        };

        if !matches!(self.service.verify(&token, &model), Ok(true)) {
            log::warn!("Rejected API key '{}': invalid secret", token.key_id);
            return Some(Err(AuthenticationError::Failed));
        }

        // the cached key may have expired in the meantime
        if model.expires_at <= OffsetDateTime::now_utc() {
            self.keys.invalidate(&token.key_id).await;
            return Some(Err(AuthenticationError::Failed));
        }

        self.touch(&model).await;

        Some(Ok(UserDetails {
            id: format!("api-key:{}", model.key_id),
            permissions: model.permissions.clone(),
            issuer: None,
            email: None,
            api_key: Some(Box::new(info)),
        }))
    }
}
