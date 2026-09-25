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

mod scope {
    use super::*;
    use crate::{
        binding::model::PrincipalRef,
        binding::{model::Role, service::BindingService},
        scope::AuthzMode,
        test::create_group,
    };
    use std::time::Duration;
    use trustify_auth::{
        Permission,
        authenticator::{token::ApiKeyInformation, user::UserDetails},
        authorizer::AccessScope,
    };

    fn user(permissions: &[&str]) -> UserInformation {
        UserInformation::Authenticated(UserDetails {
            id: "sub".into(),
            permissions: permissions.iter().map(ToString::to_string).collect(),
            ..Default::default()
        })
    }

    #[test_context(TrustifyContext)]
    #[test_log::test(tokio::test)]
    async fn compute(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let acme = create_group("acme", None, Some("acme"), &ctx.db).await?;
        let payments = create_group("payments", Some(acme), None, &ctx.db).await?;
        let other = create_group("other", None, None, &ctx.db).await?;

        let users = UserService::new(PaginationCache::for_test());
        let teams = crate::team::service::TeamService::new(PaginationCache::for_test());
        let bindings = BindingService::new();
        let actor = Actor::system();

        let alice = users
            .ensure(&["alice@acme.com".into()], &actor, &ctx.db)
            .await?[0];
        teams
            .create(
                crate::team::model::TeamRequest {
                    name: "devs".into(),
                    description: None,
                    external_id: Some("devs".into()),
                },
                &actor,
                &ctx.db,
            )
            .await?;
        teams
            .set_members(
                &"ext:devs".parse()?,
                vec!["alice@acme.com".into()],
                None,
                &users,
                &actor,
                &ctx.db,
            )
            .await?;
        bindings
            .set(
                "ext:acme",
                &PrincipalRef::Team("ext:devs".into()),
                Role::Viewer,
                &users,
                &actor,
                &ctx.db,
            )
            .await?;
        bindings
            .set(
                &payments.to_string(),
                &PrincipalRef::User("alice@acme.com".into()),
                Role::Editor,
                &users,
                &actor,
                &ctx.db,
            )
            .await?;

        let resolver = PrincipalResolver::new(
            trustify_common::db::ReadWrite::new(ctx.db.clone()),
            true,
            AuthzMode::Scoped,
        );
        let principal = Principal {
            id: alice,
            email: "alice@acme.com".into(),
        };

        let scope = resolver
            .access_scope(Some(&user(&["read.sbom"])), Some(&principal))
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?
            .ok_or_else(|| anyhow::anyhow!("must be scoped"))?;

        // inherited viewer role on the child, plus the direct editor role
        assert!(scope.allows(acme, Permission::ReadSbom));
        assert!(!scope.allows(acme, Permission::DeleteSbom));
        assert!(scope.allows(payments, Permission::ReadSbom));
        assert!(scope.allows(payments, Permission::DeleteSbom));
        assert!(!scope.allows(other, Permission::ReadSbom));

        // a new binding takes effect once the revision cache expired

        bindings
            .set(
                &other.to_string(),
                &PrincipalRef::User("alice@acme.com".into()),
                Role::Viewer,
                &users,
                &actor,
                &ctx.db,
            )
            .await?;
        tokio::time::sleep(Duration::from_millis(1100)).await;

        let scope = resolver
            .access_scope(Some(&user(&["read.sbom"])), Some(&principal))
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?
            .ok_or_else(|| anyhow::anyhow!("must be scoped"))?;
        assert!(scope.allows(other, Permission::ReadSbom));

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test_log::test(tokio::test)]
    async fn special_cases(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let db = trustify_common::db::ReadWrite::new(ctx.db.clone());
        let scoped = PrincipalResolver::new(db.clone(), true, AuthzMode::Scoped);
        let global = PrincipalResolver::new(db, true, AuthzMode::Global);
        let access = |resolver: &PrincipalResolver, user: Option<UserInformation>| {
            let resolver = resolver.clone();
            async move {
                resolver
                    .access_scope(user.as_ref(), None)
                    .await
                    .map_err(|err| anyhow::anyhow!("{err}"))
            }
        };

        // global mode doesn't compute a scope
        assert_eq!(access(&global, Some(user(&[]))).await?, None);

        // authentication disabled
        assert_eq!(
            access(&scoped, None).await?,
            Some(AccessScope::Unrestricted)
        );
        assert_eq!(
            access(&scoped, Some(UserInformation::Anonymous)).await?,
            Some(AccessScope::Unrestricted)
        );

        // unrestricted by global permission
        for permission in ["read.allSboms", "manage.tenancy"] {
            assert_eq!(
                access(&scoped, Some(user(&[permission]))).await?,
                Some(AccessScope::Unrestricted)
            );
        }

        // no linked user, no access
        assert_eq!(
            access(&scoped, Some(user(&["read.sbom"]))).await?,
            Some(AccessScope::none())
        );

        // API keys can only upload into their groups
        let group = Uuid::now_v7();
        let key = UserInformation::Authenticated(UserDetails {
            api_key: Some(Box::new(ApiKeyInformation {
                groups: vec![group.to_string()],
                ..Default::default()
            })),
            ..Default::default()
        });
        let scope = access(&scoped, Some(key))
            .await?
            .ok_or_else(|| anyhow::anyhow!("must be scoped"))?;
        assert!(scope.allows(group, Permission::CreateSbom));
        assert!(!scope.allows(group, Permission::ReadSbom));
        assert_eq!(
            scope.groups_with(Permission::ReadSbom),
            Some(Vec::<Uuid>::new())
        );

        Ok(())
    }
}
