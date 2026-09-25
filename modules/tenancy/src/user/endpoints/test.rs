use crate::test::caller;
use actix_http::StatusCode;
use actix_web::{http::header, test::TestRequest};
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyContext, call::CallService};

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn put_get_delete(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // create

    let response = app
        .call_service(
            TestRequest::put()
                .uri("/api/v3/user/Alice%40ACME.com")
                .set_json(json!({"displayName": "Alice", "externalId": "u-1"}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let etag = response
        .headers()
        .get(header::ETAG)
        .expect("must have an etag")
        .to_str()?
        .to_string();

    // update, using a stale revision

    let response = app
        .call_service(
            TestRequest::put()
                .uri("/api/v3/user/alice@acme.com")
                .insert_header((header::IF_MATCH, "\"stale\""))
                .set_json(json!({"displayName": "Alice A."}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);

    // update, using the correct revision

    let response = app
        .call_service(
            TestRequest::put()
                .uri("/api/v3/user/alice@acme.com")
                .insert_header((header::IF_MATCH, etag))
                .set_json(json!({"displayName": "Alice A.", "externalId": "u-1"}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    // read, case-insensitive

    let user: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/user/ALICE@acme.com")
                .to_request(),
        )
        .await;
    assert_eq!(user["email"], "alice@acme.com");
    assert_eq!(user["displayName"], "Alice A.");
    assert_eq!(user["externalId"], "u-1");
    assert_eq!(user["state"], "invited");

    // list

    let users: Value = app
        .call_and_read_body_json(TestRequest::get().uri("/api/v3/user").to_request())
        .await;
    assert_eq!(users["items"].as_array().map(Vec::len), Some(1));

    // delete, twice, both succeed

    for _ in 0..2 {
        let response = app
            .call_service(
                TestRequest::delete()
                    .uri("/api/v3/user/alice@acme.com")
                    .to_request(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    let response = app
        .call_service(
            TestRequest::get()
                .uri("/api/v3/user/alice@acme.com")
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn invalid_input(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    for (uri, body) in [
        ("/api/v3/user/not-an-email", json!({})),
        (
            "/api/v3/user/a@acme.com",
            json!({"externalId": "has space"}),
        ),
    ] {
        let response = app
            .call_service(TestRequest::put().uri(uri).set_json(body).to_request())
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
    }

    // external IDs must be unique

    for (email, expected) in [
        ("a@acme.com", StatusCode::CREATED),
        ("b@acme.com", StatusCode::CONFLICT),
    ] {
        let response = app
            .call_service(
                TestRequest::put()
                    .uri(&format!("/api/v3/user/{email}"))
                    .set_json(json!({"externalId": "same"}))
                    .to_request(),
            )
            .await;
        assert_eq!(response.status(), expected, "{email}");
    }

    Ok(())
}
