use crate::test::caller;
use actix_web::{http::StatusCode, test::TestRequest};
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyContext, call::CallService};

/// Groups can be created, updated, read, and deleted by their external ID.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upsert_by_external_id(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // create root and child, the child references its parent by external ID

    for (uri, body) in [
        (
            "/api/v3/group/sbom/ext:acme",
            json!({"name": "ACME", "kind": "organization"}),
        ),
        (
            "/api/v3/group/sbom/ext:acme.payments",
            json!({"name": "payments", "kind": "team", "parent": "ext:acme"}),
        ),
    ] {
        let response = app
            .call_service(TestRequest::put().uri(uri).set_json(body).to_request())
            .await;
        assert_eq!(response.status(), StatusCode::CREATED, "{uri}");
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        let id = actix_web::test::read_body_json::<Value, _>(response).await["id"].clone();
        assert_eq!(
            location,
            id.as_str().map(|id| format!("/api/v3/group/sbom/{id}"))
        );
    }

    let acme: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/group/sbom/ext:acme")
                .to_request(),
        )
        .await;
    assert_eq!(acme["external_id"], "acme");
    assert_eq!(acme["kind"], "organization");

    let payments: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/group/sbom/ext:acme.payments")
                .to_request(),
        )
        .await;
    assert_eq!(payments["parent"], acme["id"]);

    // second PUT updates, and keeps the external ID

    let response = app
        .call_service(
            TestRequest::put()
                .uri("/api/v3/group/sbom/ext:acme.payments")
                .set_json(json!({"name": "Payments", "parent": "ext:acme"}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let updated: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/group/sbom/ext:acme.payments")
                .to_request(),
        )
        .await;
    assert_eq!(updated["id"], payments["id"]);
    assert_eq!(updated["name"], "Payments");
    assert_eq!(updated["external_id"], "acme.payments");
    assert!(updated.get("kind").is_none());

    // mismatching external IDs, unknown parent, invalid external ID

    for (uri, body) in [
        (
            "/api/v3/group/sbom/ext:acme",
            json!({"name": "ACME", "external_id": "other"}),
        ),
        (
            "/api/v3/group/sbom/ext:new",
            json!({"name": "new", "parent": "ext:unknown"}),
        ),
        ("/api/v3/group/sbom/ext:in%20valid", json!({"name": "new"})),
    ] {
        let response = app
            .call_service(TestRequest::put().uri(uri).set_json(body).to_request())
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
    }

    // external IDs are unique

    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v3/group/sbom")
                .set_json(json!({"name": "other", "external_id": "acme"}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // delete by external ID, twice

    for _ in 0..2 {
        let response = app
            .call_service(
                TestRequest::delete()
                    .uri("/api/v3/group/sbom/ext:acme.payments")
                    .to_request(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    let response = app
        .call_service(
            TestRequest::get()
                .uri("/api/v3/group/sbom/ext:acme.payments")
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}
