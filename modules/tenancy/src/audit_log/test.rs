use crate::test::{caller, caller_authorized};
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_auth::authenticator::user::UserDetails;
use trustify_test_context::{TrustifyContext, auth::TestAuthentication, call::CallService};

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_and_filter(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    for email in ["a@acme.com", "b@acme.com"] {
        let response = app
            .call_service(
                TestRequest::put()
                    .uri(&format!("/api/v3/user/{email}"))
                    .set_json(json!({}))
                    .to_request(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }
    let response = app
        .call_service(
            TestRequest::delete()
                .uri("/api/v3/user/a@acme.com")
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let all: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/audit?total=true")
                .to_request(),
        )
        .await;
    assert_eq!(all["total"], 3);
    // newest first
    assert_eq!(all["items"][0]["action"], "delete");
    assert_eq!(all["items"][0]["targetKind"], "user");
    assert_eq!(all["items"][0]["detail"]["email"], "a@acme.com");

    let creates: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/audit?action=create&targetKind=user")
                .to_request(),
        )
        .await;
    assert_eq!(creates["items"].as_array().map(Vec::len), Some(2));

    let future: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/audit?since=2999-01-01T00:00:00Z")
                .to_request(),
        )
        .await;
    assert_eq!(future["items"], json!([]));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn requires_global_manager(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller_authorized(ctx).await?;

    let response = app
        .call_service(
            TestRequest::get()
                .uri("/api/v3/audit")
                .to_request()
                .test_auth_details(UserDetails {
                    permissions: vec!["read.sbom".into()],
                    ..Default::default()
                }),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn prune(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use crate::audit::{self, Actor, Change};
    use sea_orm::{EntityTrait, PaginatorTrait};
    use std::time::Duration;
    use trustify_entity::audit_event;

    audit::record(
        &Actor::system(),
        Change {
            action: "test",
            target_kind: "test",
            target_id: "1",
            detail: json!({}),
        },
        &ctx.db,
    )
    .await?;

    // nothing is old enough
    assert_eq!(audit::prune(Duration::from_secs(3600), &ctx.db).await?, 0);
    // everything is older than "now"
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(audit::prune(Duration::ZERO, &ctx.db).await?, 1);
    assert_eq!(audit_event::Entity::find().count(&ctx.db).await?, 0);

    Ok(())
}
