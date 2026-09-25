use crate::test::{caller, caller_with, create_group};
use actix_http::StatusCode;
use actix_web::{http::header, test::TestRequest};
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use trustify_auth::authenticator::user::UserDetails;
use trustify_test_context::{TrustifyContext, auth::TestAuthentication, call::CallService};

fn in_days(days: i64) -> anyhow::Result<String> {
    Ok((OffsetDateTime::now_utc() + Duration::days(days)).format(&Rfc3339)?)
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn lifecycle(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;
    create_group("checkout", None, Some("checkout"), &ctx.db).await?;

    // create

    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v3/api-key")
                .set_json(json!({
                    "name": "checkout CI",
                    "groups": ["ext:checkout"],
                    "expiresAt": in_days(90)?,
                    "externalId": "checkout.ci",
                    "labels": {"pipeline": "gitlab"},
                }))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let issued: Value = actix_web::test::read_body_json(response).await;
    let token = issued["token"].as_str().unwrap_or_default().to_string();
    assert!(token.starts_with("tfy_"), "{issued}");

    // reading never exposes the token

    let key: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/api-key/ext:checkout.ci")
                .to_request(),
        )
        .await;
    assert_eq!(key["id"], issued["id"]);
    assert_eq!(key["state"], "active");
    assert!(key.get("token").is_none());
    assert!(!key.to_string().contains(&token[20..]));

    let keys: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/api-key?group=ext:checkout&state=active")
                .to_request(),
        )
        .await;
    assert_eq!(keys["items"].as_array().map(Vec::len), Some(1));

    // patch

    let patched: Value = app
        .call_and_read_body_json(
            TestRequest::patch()
                .uri("/api/v3/api-key/ext:checkout.ci")
                .set_json(json!({"name": "renamed"}))
                .to_request(),
        )
        .await;
    assert_eq!(patched["name"], "renamed");

    // rotate

    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v3/api-key/ext:checkout.ci/rotate")
                .set_json(json!({"gracePeriod": "2h", "expiresAt": in_days(90)?}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    let rotated: Value = actix_web::test::read_body_json(response).await;
    assert_ne!(rotated["token"], issued["token"]);
    assert_eq!(rotated["rotatedFrom"], issued["id"]);
    assert_eq!(
        location,
        rotated["id"]
            .as_str()
            .map(|id| format!("/api/v3/api-key/{id}"))
    );

    // revoke, twice

    for _ in 0..2 {
        let response = app
            .call_service(
                TestRequest::delete()
                    .uri("/api/v3/api-key/ext:checkout.ci")
                    .to_request(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    let key: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri(&format!(
                    "/api/v3/api-key/{}",
                    rotated["id"].as_str().unwrap_or_default()
                ))
                .to_request(),
        )
        .await;
    assert_eq!(key["state"], "revoked");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn disabled_without_pepper(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let tenancy = crate::endpoints::Tenancy::new(
        &Default::default(),
        trustify_common::db::ReadWrite::new(ctx.db.clone()),
        trustify_common::db::pagination_cache::PaginationCache::for_test(),
    );
    assert!(tenancy.token_validators().is_empty());

    let app = caller_with(ctx, tenancy).await?;
    create_group("checkout", None, Some("checkout"), &ctx.db).await?;

    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v3/api-key")
                .set_json(json!({
                    "name": "ci",
                    "groups": ["ext:checkout"],
                    "expiresAt": in_days(1)?,
                }))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    Ok(())
}

/// Requests made with an API key must only be able to upload SBOMs.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn api_key_principal_is_restricted(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let details = UserDetails {
        id: "api-key:abc".into(),
        permissions: vec!["create.sbom".into()],
        api_key: Some(Box::default()),
        ..Default::default()
    };

    for request in [
        TestRequest::get().uri("/api/v3/me"),
        TestRequest::get().uri("/api/v3/user"),
        TestRequest::post()
            .uri("/api/v3/api-key")
            .set_json(json!({})),
        TestRequest::get().uri("/api/v3/sbom"),
    ] {
        let response = app
            .call_service(request.to_request().test_auth_details(details.clone()))
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // the upload endpoint passes the middleware (it's not mounted here, so it's not found)

    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v3/sbom")
                .to_request()
                .test_auth_details(details),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}
