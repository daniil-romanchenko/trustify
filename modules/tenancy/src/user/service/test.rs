use super::*;
use crate::test::authz_revision;
use sea_orm::{EntityTrait, PaginatorTrait};
use test_context::test_context;
use test_log::test;
use trustify_common::model::Paginated;
use trustify_entity::audit_event;
use trustify_test_context::TrustifyContext;

fn actor() -> Actor {
    Actor {
        kind: "user",
        id: "orchestrator".into(),
    }
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn upsert_lifecycle(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let service = UserService::new(PaginationCache::for_test());
    let before = authz_revision(&ctx.db).await?;

    // create, using a non-normalized address

    let (user, created) = service
        .upsert(
            " Alice@ACME.com",
            UserRequest {
                display_name: Some("Alice".into()),
                ..Default::default()
            },
            None,
            &actor(),
            &ctx.db,
        )
        .await?;
    assert!(created);
    assert_eq!(user.value.email, "alice@acme.com");
    assert_eq!(user.value.state, UserState::Invited);

    // update with the wrong revision must fail

    let result = service
        .upsert(
            "alice@acme.com",
            UserRequest::default(),
            Some("wrong"),
            &actor(),
            &ctx.db,
        )
        .await;
    assert!(matches!(result, Err(Error::RevisionNotFound)));

    // disable, with the correct revision

    let (disabled, created) = service
        .upsert(
            "ALICE@acme.com",
            UserRequest {
                disabled: true,
                ..Default::default()
            },
            Some(&user.revision),
            &actor(),
            &ctx.db,
        )
        .await?;
    assert!(!created);
    assert_eq!(disabled.value.id, user.value.id);
    assert_eq!(disabled.value.state, UserState::Disabled);
    assert_eq!(disabled.value.display_name, None);
    assert_ne!(disabled.revision, user.revision);

    // every change must be audited, and bump the authorization revision

    assert_eq!(audit_event::Entity::find().count(&ctx.db).await?, 2);
    assert_eq!(authz_revision(&ctx.db).await?, before + 2);

    // delete twice, the second time it's gone

    assert!(
        service
            .delete("alice@acme.com", None, &actor(), &ctx.db)
            .await?
    );
    assert!(
        !service
            .delete("alice@acme.com", None, &actor(), &ctx.db)
            .await?
    );
    assert!(service.read("alice@acme.com", &ctx.db).await?.is_none());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn ensure_is_idempotent(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let service = UserService::new(PaginationCache::for_test());

    let (existing, _) = service
        .upsert(
            "bob@acme.com",
            UserRequest::default(),
            None,
            &actor(),
            &ctx.db,
        )
        .await?;

    let ids = service
        .ensure(
            &[
                "carol@acme.com".into(),
                "BOB@acme.com".into(),
                "carol@acme.com".into(),
            ],
            &actor(),
            &ctx.db,
        )
        .await?;

    assert_eq!(ids.len(), 3);
    assert_eq!(ids[1].to_string(), existing.value.id);
    assert_eq!(ids[0], ids[2]);

    // running it again doesn't create anything new

    let again = service
        .ensure(&["carol@acme.com".into()], &actor(), &ctx.db)
        .await?;
    assert_eq!(again, vec![ids[0]]);

    let all = service
        .list(Default::default(), Paginated::default(), &ctx.db)
        .await?;
    assert_eq!(
        all.items
            .iter()
            .map(|u| u.email.as_str())
            .collect::<Vec<_>>(),
        vec!["bob@acme.com", "carol@acme.com"]
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn change_email(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let service = UserService::new(PaginationCache::for_test());

    service
        .ensure(
            &["a@acme.com".into(), "b@acme.com".into()],
            &actor(),
            &ctx.db,
        )
        .await?;

    // conflicts with an existing user

    let result = service
        .change_email("a@acme.com", "B@acme.com", None, &actor(), &ctx.db)
        .await;
    assert!(matches!(result, Err(Error::Conflict(_))), "{result:?}");

    // unknown user

    let result = service
        .change_email("x@acme.com", "y@acme.com", None, &actor(), &ctx.db)
        .await;
    assert!(matches!(result, Err(Error::NotFound(_))), "{result:?}");

    // works

    let user = service
        .change_email("a@acme.com", "C@acme.com", None, &actor(), &ctx.db)
        .await?;
    assert_eq!(user.value.email, "c@acme.com");
    assert!(service.read("a@acme.com", &ctx.db).await?.is_none());

    Ok(())
}
