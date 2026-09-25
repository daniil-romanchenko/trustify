use super::*;
use crate::{
    api_key::{config::TenancyConfig, validator::ApiKeyValidator},
    test::{TEST_PEPPER, create_group},
};
use sea_orm::EntityTrait;
use test_context::test_context;
use test_log::test;
use time::Duration as TimeDuration;
use trustify_auth::authenticator::token::{ClientAddress, TokenValidator};
use trustify_common::db;
use trustify_entity::{labels::Labels, sbom_group};
use trustify_test_context::TrustifyContext;

fn service() -> ApiKeyService {
    ApiKeyService::new(
        &TenancyConfig {
            api_key_pepper: Some(TEST_PEPPER.into()),
            ..Default::default()
        },
        PaginationCache::for_test(),
    )
}

fn client() -> ClientAddress {
    ClientAddress {
        peer: Some("192.0.2.1".parse().expect("valid address")),
        forwarded: None,
    }
}

fn actor() -> Actor {
    Actor {
        kind: "user",
        id: "orchestrator".into(),
    }
}

fn request(groups: &[&str]) -> ApiKeyRequest {
    ApiKeyRequest {
        name: "ci".into(),
        groups: groups.iter().map(ToString::to_string).collect(),
        default_group: None,
        permissions: None,
        expires_at: OffsetDateTime::now_utc() + TimeDuration::days(30),
        labels: Labels::new().add("pipeline", "gitlab"),
        external_id: Some("checkout.ci".into()),
        allowed_cidrs: None,
    }
}

async fn assert_bad_request(
    service: &ApiKeyService,
    request: ApiKeyRequest,
    db: &impl ConnectionTrait,
) {
    let result = service.create(request.clone(), &actor(), db).await;
    assert!(
        matches!(result, Err(Error::BadRequest(..))),
        "{request:?}: {result:?}"
    );
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn create_validation(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let service = service();
    let acme = create_group("acme", None, Some("acme"), &ctx.db).await?;
    create_group("payments", Some(acme), Some("acme.payments"), &ctx.db).await?;
    create_group("other", None, Some("other"), &ctx.db).await?;

    // no groups, unknown group
    assert_bad_request(&service, request(&[]), &ctx.db).await;
    assert_bad_request(&service, request(&["ext:unknown"]), &ctx.db).await;

    // more than one group requires a default
    assert_bad_request(&service, request(&["ext:acme", "ext:other"]), &ctx.db).await;

    // default outside the scope
    let mut req = request(&["ext:acme.payments"]);
    req.default_group = Some("ext:acme".into());
    assert_bad_request(&service, req, &ctx.db).await;

    // unsupported permissions
    let mut req = request(&["ext:acme"]);
    req.permissions = Some(vec!["read.sbom".into()]);
    assert_bad_request(&service, req, &ctx.db).await;

    // expiration in the past, or too far in the future
    let mut req = request(&["ext:acme"]);
    req.expires_at = OffsetDateTime::now_utc() - TimeDuration::minutes(1);
    assert_bad_request(&service, req, &ctx.db).await;
    let mut req = request(&["ext:acme"]);
    req.expires_at = OffsetDateTime::now_utc() + TimeDuration::days(366);
    assert_bad_request(&service, req, &ctx.db).await;

    // disabled without a pepper
    let disabled = ApiKeyService::new(&TenancyConfig::default(), PaginationCache::for_test());
    let result = disabled
        .create(request(&["ext:acme"]), &actor(), &ctx.db)
        .await;
    assert!(matches!(result, Err(Error::Disabled(_))), "{result:?}");

    // a default within a scope's descendants is fine
    let mut req = request(&["ext:acme", "ext:other"]);
    req.default_group = Some("ext:acme.payments".into());
    let issued = service.create(req, &actor(), &ctx.db).await?;
    assert_eq!(issued.key.groups.len(), 2);
    assert_eq!(issued.key.permissions, vec!["create.sbom"]);

    // external IDs are unique
    let result = service
        .create(request(&["ext:acme"]), &actor(), &ctx.db)
        .await;
    assert!(matches!(result, Err(Error::Conflict(_))), "{result:?}");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn lifecycle(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let service = service();
    let acme = create_group("acme", None, Some("acme"), &ctx.db).await?;
    let payments = create_group("payments", Some(acme), None, &ctx.db).await?;

    let issued = service
        .create(request(&["ext:acme"]), &actor(), &ctx.db)
        .await?;
    assert_eq!(issued.key.default_group, Some(acme.to_string()));
    let token = Token::parse(&issued.token)?;

    // the token authenticates, its scope includes descendants

    let (model, info) = service
        .load(&token.key_id, &ctx.db)
        .await?
        .ok_or_else(|| anyhow::anyhow!("key must be usable"))?;
    assert!(service.verify(&token, &model)?.is_valid());
    assert!(info.groups.contains(&acme.to_string()));
    assert!(info.groups.contains(&payments.to_string()));
    assert_eq!(
        info.labels.get("pipeline").map(String::as_str),
        Some("gitlab")
    );

    // a wrong secret doesn't

    let mut wrong = Token::generate()?;
    wrong.key_id = token.key_id.clone();
    assert!(!service.verify(&wrong, &model)?.is_valid());

    // patch

    let patched = service
        .patch(
            &ResourceKey::External("checkout.ci".into()),
            ApiKeyPatch {
                name: Some("renamed".into()),
                labels: None,
                allowed_cidrs: None,
            },
            &actor(),
            &ctx.db,
        )
        .await?;
    assert_eq!(patched.name, "renamed");
    assert_eq!(patched.labels, Labels::new().add("pipeline", "gitlab"));

    // rotate, the external ID moves, the old key expires after the grace period

    let rotated = service
        .rotate(
            &ResourceKey::External("checkout.ci".into()),
            RotateRequest {
                grace_period: "1h".into(),
                expires_at: OffsetDateTime::now_utc() + TimeDuration::days(60),
            },
            &actor(),
            &ctx.db,
        )
        .await?;
    assert_ne!(rotated.key.id, issued.key.id);
    assert_eq!(rotated.key.rotated_from, Some(issued.key.id.clone()));
    assert_eq!(rotated.key.external_id.as_deref(), Some("checkout.ci"));
    assert_eq!(rotated.key.groups, vec![acme.to_string()]);
    assert_eq!(rotated.key.name, "renamed");

    let old = service
        .read(&ResourceKey::Id(Uuid::parse_str(&issued.key.id)?), &ctx.db)
        .await?
        .ok_or_else(|| anyhow::anyhow!("old key must exist"))?;
    assert_eq!(old.external_id, None);
    assert!(old.expires_at <= OffsetDateTime::now_utc() + TimeDuration::hours(1));
    // still usable during the grace period
    assert!(service.load(&token.key_id, &ctx.db).await?.is_some());

    // a grace period that is too long

    let result = service
        .rotate(
            &ResourceKey::External("checkout.ci".into()),
            RotateRequest {
                grace_period: "8d".into(),
                expires_at: OffsetDateTime::now_utc() + TimeDuration::days(60),
            },
            &actor(),
            &ctx.db,
        )
        .await;
    assert!(matches!(result, Err(Error::BadRequest(..))), "{result:?}");

    // revoke, twice

    for _ in 0..2 {
        assert!(
            service
                .revoke(
                    &ResourceKey::External("checkout.ci".into()),
                    &actor(),
                    &ctx.db
                )
                .await?
        );
    }
    let new_token = Token::parse(&rotated.token)?;
    assert!(service.load(&new_token.key_id, &ctx.db).await?.is_none());

    // rotating a revoked key fails

    let result = service
        .rotate(
            &ResourceKey::External("checkout.ci".into()),
            RotateRequest {
                grace_period: "1h".into(),
                expires_at: OffsetDateTime::now_utc() + TimeDuration::days(60),
            },
            &actor(),
            &ctx.db,
        )
        .await;
    assert!(matches!(result, Err(Error::Conflict(_))), "{result:?}");

    // listing, by group and state

    let active = service
        .list(
            ListOptions {
                group: Some("ext:acme".into()),
                state: Some(ApiKeyState::Active),
            },
            trustify_common::model::Paginated::default(),
            &ctx.db,
        )
        .await?;
    assert_eq!(
        active.items.iter().map(|k| &k.id).collect::<Vec<_>>(),
        vec![&issued.key.id]
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn validator(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let service = service();
    let group = create_group("acme", None, None, &ctx.db).await?;
    let validator =
        ApiKeyValidator::new(service.clone(), db::ReadWrite::new(ctx.db.clone()), false);

    let issued = service
        .create(request(&[&group.to_string()]), &actor(), &ctx.db)
        .await?;

    // not an API key, left to other validators

    assert!(validator.validate("eyJhbGciOi", client()).await.is_none());

    // valid, twice, the second one from the cache

    for _ in 0..2 {
        let details = validator
            .validate(&issued.token, client())
            .await
            .ok_or_else(|| anyhow::anyhow!("must be handled"))??;
        assert_eq!(details.permissions, vec!["create.sbom"]);
        let key = details
            .api_key
            .ok_or_else(|| anyhow::anyhow!("must carry the API key"))?;
        assert_eq!(key.groups, vec![group.to_string()]);
        assert_eq!(key.default_group, Some(group.to_string()));
    }

    // a wrong secret, for a cached key ID, is still rejected

    let mut wrong = Token::generate()?;
    wrong.key_id = Token::parse(&issued.token)?.key_id;
    assert!(matches!(
        validator.validate(&wrong.expose(), client()).await,
        Some(Err(_))
    ));
    // and doesn't lock out the real one
    assert!(matches!(
        validator.validate(&issued.token, client()).await,
        Some(Ok(_))
    ));

    // malformed

    assert!(matches!(
        validator.validate("tfy_nope", client()).await,
        Some(Err(_))
    ));

    // use is recorded

    let key = trustify_entity::api_key::Entity::find()
        .one(&ctx.db)
        .await?
        .ok_or_else(|| anyhow::anyhow!("key must exist"))?;
    assert!(key.last_used_at.is_some());

    // deleting the only group revokes the key

    sbom_group::Entity::delete_by_id(group)
        .exec(&ctx.db)
        .await?;
    validator.invalidate();
    assert!(matches!(
        validator.validate(&issued.token, client()).await,
        Some(Err(_))
    ));

    Ok(())
}

fn from(address: &str) -> ClientAddress {
    ClientAddress {
        peer: Some(address.parse().expect("valid address")),
        forwarded: None,
    }
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn hardening(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use trustify_auth::authenticator::error::AuthenticationError;
    use trustify_entity::audit_event;

    let group = create_group("acme", None, None, &ctx.db).await?;
    let old_pepper = "old pepper, old pepper, old pepper";
    let new_pepper = "new pepper, new pepper, new pepper";

    // a key created with the old pepper, only usable from 10.0.0.0/8

    let old = ApiKeyService::new(
        &TenancyConfig {
            api_key_pepper: Some(old_pepper.into()),
            ..Default::default()
        },
        PaginationCache::for_test(),
    );
    let mut req = request(&[&group.to_string()]);
    req.allowed_cidrs = Some(vec!["10.0.0.0/8".into()]);
    let issued = old.create(req, &actor(), &ctx.db).await?;
    assert_eq!(issued.key.allowed_cidrs, Some(vec!["10.0.0.0/8".into()]));

    // invalid ranges are rejected

    let mut req = request(&[&group.to_string()]);
    req.external_id = None;
    req.allowed_cidrs = Some(vec!["10.0.0.0/33".into()]);
    assert!(matches!(
        old.create(req, &actor(), &ctx.db).await,
        Err(Error::BadRequest(..))
    ));

    // rotate the pepper

    let new = ApiKeyService::new(
        &TenancyConfig {
            api_key_pepper: Some(new_pepper.into()),
            api_key_pepper_previous: Some(old_pepper.into()),
            ..Default::default()
        },
        PaginationCache::for_test(),
    );
    let validator = ApiKeyValidator::new(new, db::ReadWrite::new(ctx.db.clone()), false);

    // wrong network
    assert!(matches!(
        validator.validate(&issued.token, from("192.0.2.1")).await,
        Some(Err(AuthenticationError::Failed))
    ));
    // allowed network, verified with the previous pepper, and migrated
    assert!(matches!(
        validator.validate(&issued.token, from("10.1.2.3")).await,
        Some(Ok(_))
    ));

    let only_new = ApiKeyService::new(
        &TenancyConfig {
            api_key_pepper: Some(new_pepper.into()),
            ..Default::default()
        },
        PaginationCache::for_test(),
    );
    let validator_new = ApiKeyValidator::new(only_new, db::ReadWrite::new(ctx.db.clone()), false);
    assert!(matches!(
        validator_new
            .validate(&issued.token, from("10.1.2.3"))
            .await,
        Some(Ok(_))
    ));

    // use and rejections are audited

    let actions: Vec<String> = audit_event::Entity::find()
        .all(&ctx.db)
        .await?
        .into_iter()
        .filter(|event| event.actor_kind == "api-key")
        .map(|event| event.action)
        .collect();
    assert!(actions.contains(&"use".to_string()), "{actions:?}");
    assert!(actions.contains(&"reject".to_string()), "{actions:?}");

    // too many failures from one address are throttled, others are not affected

    for _ in 0..20 {
        let _ = validator.validate("tfy_guess", from("198.51.100.7")).await;
    }
    assert!(matches!(
        validator
            .validate(&issued.token, from("198.51.100.7"))
            .await,
        Some(Err(AuthenticationError::TooManyRequests))
    ));
    assert!(matches!(
        validator.validate(&issued.token, from("10.1.2.3")).await,
        Some(Ok(_))
    ));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn trust_forwarded(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let group = create_group("acme", None, None, &ctx.db).await?;
    let mut req = request(&[&group.to_string()]);
    req.allowed_cidrs = Some(vec!["10.0.0.0/8".into()]);
    let issued = service().create(req, &actor(), &ctx.db).await?;

    // behind a proxy: the peer is the proxy, the client is forwarded
    let behind_proxy = ClientAddress {
        peer: Some("192.0.2.1".parse()?),
        forwarded: Some("10.0.0.5".parse()?),
    };

    let untrusting = ApiKeyValidator::new(service(), db::ReadWrite::new(ctx.db.clone()), false);
    assert!(matches!(
        untrusting.validate(&issued.token, behind_proxy).await,
        Some(Err(_))
    ));

    let trusting = ApiKeyValidator::new(service(), db::ReadWrite::new(ctx.db.clone()), true);
    assert!(matches!(
        trusting.validate(&issued.token, behind_proxy).await,
        Some(Ok(_))
    ));

    Ok(())
}
