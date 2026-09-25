use super::*;
use crate::{
    audit::Actor,
    user::{model::UserRequest, service::UserService},
};
use test_context::test_context;
use test_log::test;
use trustify_common::db::pagination_cache::PaginationCache;
use trustify_test_context::TrustifyContext;

fn identity(subject: &str, email: &str) -> Identity {
    Identity {
        issuer: "https://sso.example.com/realms/acme".into(),
        subject: subject.into(),
        email: email.into(),
    }
}

fn user(result: SignIn) -> trustify_entity::principal_user::Model {
    match result {
        SignIn::User(user) => user,
        other => panic!("expected a user, got: {other:?}"),
    }
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn just_in_time(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // without just-in-time creation, unknown users stay unknown

    let result = sign_in(&identity("sub-1", "a@acme.com"), false, &ctx.db).await?;
    assert_eq!(result, SignIn::Unknown);

    // with, they get created, active, and linked

    let created = user(sign_in(&identity("sub-1", "A@acme.com"), true, &ctx.db).await?);
    assert_eq!(created.email, "a@acme.com");
    assert_eq!(created.state, UserState::Active);
    assert_eq!(created.oidc_sub.as_deref(), Some("sub-1"));
    assert!(created.last_login.is_some());

    // signing in again finds the same user

    let again = user(sign_in(&identity("sub-1", "a@acme.com"), true, &ctx.db).await?);
    assert_eq!(again.id, created.id);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn link_provisioned(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let users = UserService::new(PaginationCache::for_test());
    let (invited, _) = users
        .upsert(
            "invited@acme.com",
            UserRequest::default(),
            None,
            &Actor::system(),
            &ctx.db,
        )
        .await?;
    let (disabled, _) = users
        .upsert(
            "disabled@acme.com",
            UserRequest {
                disabled: true,
                ..Default::default()
            },
            None,
            &Actor::system(),
            &ctx.db,
        )
        .await?;

    // read-only lookup finds provisioned users, but doesn't link them

    let found = user(find_linked(&identity("sub-1", "invited@acme.com"), &ctx.db).await?);
    assert_eq!(found.id.to_string(), invited.value.id);
    assert_eq!(found.oidc_sub, None);

    // an invited user becomes active

    let linked = user(sign_in(&identity("sub-1", "invited@acme.com"), false, &ctx.db).await?);
    assert_eq!(linked.id.to_string(), invited.value.id);
    assert_eq!(linked.state, UserState::Active);
    assert_eq!(linked.oidc_sub.as_deref(), Some("sub-1"));

    // a disabled user stays disabled

    let linked = user(sign_in(&identity("sub-2", "disabled@acme.com"), false, &ctx.db).await?);
    assert_eq!(linked.id.to_string(), disabled.value.id);
    assert_eq!(linked.state, UserState::Disabled);

    // a different identity, using the same address, is a conflict

    let result = sign_in(&identity("sub-3", "invited@acme.com"), true, &ctx.db).await?;
    assert_eq!(result, SignIn::Conflict);
    let result = find_linked(&identity("sub-3", "invited@acme.com"), &ctx.db).await?;
    assert_eq!(result, SignIn::Conflict);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn follow_email_change(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let a = user(sign_in(&identity("sub-a", "a@acme.com"), true, &ctx.db).await?);
    user(sign_in(&identity("sub-b", "b@acme.com"), true, &ctx.db).await?);

    // the identity provider changed the address

    let changed = user(sign_in(&identity("sub-a", "a2@acme.com"), true, &ctx.db).await?);
    assert_eq!(changed.id, a.id);
    assert_eq!(changed.email, "a2@acme.com");

    // but must not take over another user's address

    let unchanged = user(sign_in(&identity("sub-a", "b@acme.com"), true, &ctx.db).await?);
    assert_eq!(unchanged.id, a.id);
    assert_eq!(unchanged.email, "a2@acme.com");

    Ok(())
}
