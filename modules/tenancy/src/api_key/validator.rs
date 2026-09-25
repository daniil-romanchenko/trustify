//! Authenticating requests using API keys.

use crate::{
    api_key::{
        cidr::Cidr,
        service::{ApiKeyService, Verification, touch},
        token::{PREFIX, Token},
    },
    audit::{self, Actor, Change},
};
use moka::future::Cache;
use serde_json::json;
use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use time::OffsetDateTime;
use trustify_auth::authenticator::{
    error::AuthenticationError,
    token::{ApiKeyInformation, ClientAddress, TokenValidator},
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
/// Minimum time between audit events for the successful use of a key.
const AUDIT_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Failed attempts allowed per client address, within [`FAILURE_WINDOW`].
const MAX_FAILURES: u32 = 20;
const FAILURE_WINDOW: Duration = Duration::from_secs(60);

type CachedKey = Option<(api_key::Model, ApiKeyInformation)>;

/// Why a token was rejected.
#[derive(Copy, Clone, Debug, PartialEq, Eq, strum::IntoStaticStr)]
#[strum(serialize_all = "kebab-case")]
enum Rejection {
    Malformed,
    Unknown,
    InvalidSecret,
    Expired,
    NetworkNotAllowed,
}

/// Validates API key tokens (`tfy_…`).
#[derive(Clone)]
pub struct ApiKeyValidator {
    service: ApiKeyService,
    db: db::ReadWrite,
    trust_forwarded: bool,
    /// Usable keys, by key ID. The secret is still verified for every request.
    keys: Cache<String, CachedKey>,
    /// Keys which recently had their use recorded.
    touched: Cache<String, ()>,
    /// Keys which recently had their use audited.
    audited: Cache<String, ()>,
    /// Failed attempts, by client address.
    failures: Cache<IpAddr, Arc<AtomicU32>>,
}

impl ApiKeyValidator {
    pub fn new(service: ApiKeyService, db: db::ReadWrite, trust_forwarded: bool) -> Self {
        Self {
            service,
            db,
            trust_forwarded,
            keys: Cache::builder()
                .max_capacity(CACHE_CAPACITY)
                .time_to_live(CACHE_TTL)
                .build(),
            touched: Cache::builder()
                .max_capacity(CACHE_CAPACITY)
                .time_to_live(TOUCH_INTERVAL)
                .build(),
            audited: Cache::builder()
                .max_capacity(CACHE_CAPACITY)
                .time_to_live(AUDIT_INTERVAL)
                .build(),
            failures: Cache::builder()
                .max_capacity(CACHE_CAPACITY)
                .time_to_live(FAILURE_WINDOW)
                .build(),
        }
    }

    /// Drop all cached keys, e.g. after keys have been changed.
    pub fn invalidate(&self) {
        self.keys.invalidate_all();
    }

    fn client(&self, client: ClientAddress) -> Option<IpAddr> {
        if self.trust_forwarded {
            client.forwarded.or(client.peer)
        } else {
            client.peer
        }
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

    async fn audit(&self, key_id: &str, action: &'static str, detail: serde_json::Value) {
        let actor = Actor {
            kind: "api-key",
            id: key_id.to_string(),
        };
        let change = Change {
            action,
            target_kind: "api-key",
            target_id: key_id,
            detail,
        };
        if let Err(err) = audit::record(&actor, change, &self.db).await {
            log::debug!("Unable to audit use of API key '{key_id}': {err}");
        }
    }

    async fn is_blocked(&self, client: Option<IpAddr>) -> bool {
        let Some(client) = client else {
            return false;
        };
        self.failures
            .get(&client)
            .await
            .is_some_and(|count| count.load(Ordering::Relaxed) >= MAX_FAILURES)
    }

    /// Record a rejected attempt.
    async fn reject(
        &self,
        client: Option<IpAddr>,
        key_id: Option<&str>,
        rejection: Rejection,
    ) -> Option<Result<UserDetails, AuthenticationError>> {
        let reason: &'static str = rejection.into();
        log::info!(
            "Rejected API key '{}' from {client:?}: {reason}",
            key_id.unwrap_or("<malformed>")
        );

        if let Some(client) = client {
            self.failures
                .get_with(client, async { Arc::new(AtomicU32::new(0)) })
                .await
                .fetch_add(1, Ordering::Relaxed);
        }

        // only audit attempts for existing keys, to not flood the audit log with guesses
        if let (Some(key_id), true) = (key_id, rejection != Rejection::Unknown) {
            self.audit(
                key_id,
                "reject",
                json!({"reason": reason, "client": client.map(|c| c.to_string())}),
            )
            .await;
        }

        Some(Err(AuthenticationError::Failed))
    }
}

#[async_trait::async_trait]
impl TokenValidator for ApiKeyValidator {
    async fn validate(
        &self,
        token: &str,
        client: ClientAddress,
    ) -> Option<Result<UserDetails, AuthenticationError>> {
        if !token.starts_with(PREFIX) {
            return None;
        }

        let client = self.client(client);
        if self.is_blocked(client).await {
            return Some(Err(AuthenticationError::TooManyRequests));
        }

        let Ok(token) = Token::parse(token) else {
            return self.reject(client, None, Rejection::Malformed).await;
        };

        let Some((model, info)) = self.load(&token.key_id).await else {
            return self
                .reject(client, Some(&token.key_id), Rejection::Unknown)
                .await;
        };

        let verification = self
            .service
            .verify(&token, &model)
            .unwrap_or(Verification::Mismatch);
        if !verification.is_valid() {
            return self
                .reject(client, Some(&token.key_id), Rejection::InvalidSecret)
                .await;
        }

        // the cached key may have expired in the meantime
        if model.expires_at <= OffsetDateTime::now_utc() {
            self.keys.invalidate(&token.key_id).await;
            return self
                .reject(client, Some(&token.key_id), Rejection::Expired)
                .await;
        }

        if let Some(allowed) = &model.allowed_cidrs {
            let allowed = client.is_some_and(|client| {
                allowed
                    .iter()
                    .filter_map(|cidr| cidr.parse::<Cidr>().ok())
                    .any(|cidr| cidr.contains(client))
            });
            if !allowed {
                return self
                    .reject(client, Some(&token.key_id), Rejection::NetworkNotAllowed)
                    .await;
            }
        }

        if verification == Verification::Previous {
            match self.service.rehash(&token, &model, &self.db).await {
                Ok(()) => {
                    log::info!("Migrated API key '{}' to the current pepper", model.key_id);
                    self.keys.invalidate(&token.key_id).await;
                }
                Err(err) => log::debug!("Unable to migrate API key '{}': {err}", model.key_id),
            }
        }

        self.touch(&model).await;
        if !self.audited.contains_key(&model.key_id) {
            self.audited.insert(model.key_id.clone(), ()).await;
            self.audit(
                &model.key_id,
                "use",
                json!({"client": client.map(|c| c.to_string())}),
            )
            .await;
        }

        Some(Ok(UserDetails {
            id: format!("api-key:{}", model.key_id),
            permissions: model.permissions.clone(),
            issuer: None,
            email: None,
            api_key: Some(Box::new(info)),
        }))
    }
}
