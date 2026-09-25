use crate::test::{caller, create_group};
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_auth::authenticator::user::UserDetails;
use trustify_test_context::{TrustifyContext, auth::TestAuthentication, call::CallService};

fn details(subject: &str, email: Option<&str>) -> UserDetails {
    UserDetails {
        id: subject.into(),
        permissions: vec!["read.sbom".into()],
        issuer: Some("https://sso.example.com/realms/acme".into()),
        email: email.map(ToString::to_string),
        api_key: None,
    }
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn anonymous_and_without_email(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let me: Value = app
        .call_and_read_body_json(TestRequest::get().uri("/api/v3/me").to_request())
        .await;
    assert_eq!(
        me,
        json!({"permissions": [], "access": [], "scoped": false})
    );

    let me: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/me")
                .to_request()
                .test_auth_details(details("sub-1", None)),
        )
        .await;
    assert_eq!(
        me,
        json!({
            "subject": "sub-1",
            "permissions": ["read.sbom"],
            "effectivePermissions": ["read.sbom"],
            "access": [],
            "scoped": false,
        })
    );

    // no user was created

    let users: Value = app
        .call_and_read_body_json(TestRequest::get().uri("/api/v3/user").to_request())
        .await;
    assert_eq!(users["items"], json!([]));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn provisioned_user(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;
    let group = create_group("payments", None, Some("payments"), &ctx.db).await?;

    // provision a team with a role, before the user ever signed in

    for request in [
        TestRequest::put()
            .uri("/api/v3/team/ext:devs")
            .set_json(json!({"name": "Devs"})),
        TestRequest::put().uri("/api/v3/team/ext:devs/member/alice@acme.com"),
        TestRequest::put()
            .uri("/api/v3/group/sbom/ext:payments/binding/team/ext:devs")
            .set_json(json!({"role": "viewer"})),
    ] {
        let response = app.call_service(request.to_request()).await;
        assert!(response.status().is_success(), "{}", response.status());
    }

    // sign in, the address from the token differs in case

    let me: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/me")
                .to_request()
                .test_auth_details(details("sub-alice", Some("Alice@acme.com"))),
        )
        .await;
    assert_eq!(me["subject"], "sub-alice");
    assert_eq!(me["user"]["email"], "alice@acme.com");
    assert_eq!(me["user"]["state"], "active");
    assert_eq!(me["access"].as_array().map(Vec::len), Some(1));
    assert_eq!(me["access"][0]["group"], group.to_string());
    assert_eq!(me["access"][0]["role"], "viewer");

    // disable the user, the next request must be rejected

    let response = app
        .call_service(
            TestRequest::put()
                .uri("/api/v3/user/alice@acme.com")
                .set_json(json!({"disabled": true}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .call_service(
            TestRequest::get()
                .uri("/api/v3/me")
                .to_request()
                .test_auth_details(details("sub-alice", Some("alice@acme.com"))),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // and enabled again

    let response = app
        .call_service(
            TestRequest::put()
                .uri("/api/v3/user/alice@acme.com")
                .set_json(json!({"disabled": false}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let me: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/me")
                .to_request()
                .test_auth_details(details("sub-alice", Some("alice@acme.com"))),
        )
        .await;
    assert_eq!(me["user"]["state"], "active");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn scoped(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use actix_http::HttpMessage;
    use std::collections::{HashMap, HashSet};
    use trustify_auth::{Permission, authorizer::AccessScope};
    use uuid::Uuid;

    let app = caller(ctx).await?;
    let group = Uuid::now_v7();
    let scope = AccessScope::scoped(HashMap::from([(
        group,
        HashSet::from([Permission::ReadSbom, Permission::CreateSbom]),
    )]));

    let mut user = details("sub-1", None);
    user.permissions = vec![
        "read.sbom".into(),
        "create.sbom".into(),
        "delete.sbom".into(),
        "read.advisory".into(),
    ];
    let request = TestRequest::get()
        .uri("/api/v3/me")
        .to_request()
        .test_auth_details(user);
    request.extensions_mut().insert(scope);

    let me: Value = app.call_and_read_body_json(request).await;
    assert_eq!(me["scoped"], true);
    // delete.sbom is granted globally, but not by any role, read.advisory isn't scoped at all
    assert_eq!(
        me["effectivePermissions"],
        json!(["read.sbom", "create.sbom", "read.advisory"])
    );
    assert_eq!(
        me["groups"],
        json!([{"id": group.to_string(), "permissions": ["create.sbom", "read.sbom"]}])
    );

    Ok(())
}
