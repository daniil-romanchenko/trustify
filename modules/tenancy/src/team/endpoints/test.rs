use crate::test::caller;
use actix_http::StatusCode;
use actix_web::{http::header, test::TestRequest};
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyContext, call::CallService};

async fn members(app: &impl CallService, key: &str) -> Vec<String> {
    let result: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri(&format!("/api/v3/team/{key}/member"))
                .to_request(),
        )
        .await;

    result["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|member| member["email"].as_str().map(ToString::to_string))
        .collect()
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upsert_by_external_id(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // first call creates, second one updates

    for (name, expected) in [
        ("Devs", StatusCode::CREATED),
        ("Developers", StatusCode::OK),
    ] {
        let response = app
            .call_service(
                TestRequest::put()
                    .uri("/api/v3/team/ext:acme.devs")
                    .set_json(json!({"name": name}))
                    .to_request(),
            )
            .await;
        assert_eq!(response.status(), expected);
    }

    let team: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/team/ext:acme.devs")
                .to_request(),
        )
        .await;
    assert_eq!(team["name"], "Developers");
    assert_eq!(team["externalId"], "acme.devs");

    // can also be read by ID

    let id = team["id"].as_str().expect("must have an ID");
    let response = app
        .call_service(
            TestRequest::get()
                .uri(&format!("/api/v3/team/{id}"))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    // external ID of body and path must match

    let response = app
        .call_service(
            TestRequest::put()
                .uri("/api/v3/team/ext:acme.devs")
                .set_json(json!({"name": "Devs", "externalId": "other"}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // an unknown ID is not created

    let response = app
        .call_service(
            TestRequest::put()
                .uri("/api/v3/team/0199b9b4-6b6c-7000-8000-000000000001")
                .set_json(json!({"name": "Devs"}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // delete is idempotent

    for _ in 0..2 {
        let response = app
            .call_service(
                TestRequest::delete()
                    .uri("/api/v3/team/ext:acme.devs")
                    .to_request(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn manage_members(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v3/team")
                .set_json(json!({"name": "Devs", "externalId": "devs"}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // replace, creating users on the fly

    let response = app
        .call_service(
            TestRequest::put()
                .uri("/api/v3/team/ext:devs/member")
                .set_json(json!({"emails": ["Bob@acme.com", "alice@acme.com", "bob@acme.com"]}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let etag = response
        .headers()
        .get(header::ETAG)
        .expect("must have an etag")
        .to_str()?
        .to_string();

    assert_eq!(
        members(&app, "ext:devs").await,
        vec!["alice@acme.com", "bob@acme.com"]
    );

    let user: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/user/bob@acme.com")
                .to_request(),
        )
        .await;
    assert_eq!(user["state"], "invited");

    // patch, with a stale revision

    let response = app
        .call_service(
            TestRequest::patch()
                .uri("/api/v3/team/ext:devs/member")
                .insert_header((header::IF_MATCH, "\"stale\""))
                .set_json(json!({"add": ["carol@acme.com"]}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);

    // patch, with the correct revision

    let response = app
        .call_service(
            TestRequest::patch()
                .uri("/api/v3/team/ext:devs/member")
                .insert_header((header::IF_MATCH, etag))
                .set_json(json!({"add": ["carol@acme.com"], "remove": ["alice@acme.com"]}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    assert_eq!(
        members(&app, "ext:devs").await,
        vec!["bob@acme.com", "carol@acme.com"]
    );

    // single member operations, both idempotent

    for _ in 0..2 {
        let response = app
            .call_service(
                TestRequest::put()
                    .uri("/api/v3/team/ext:devs/member/dave@acme.com")
                    .to_request(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = app
            .call_service(
                TestRequest::delete()
                    .uri("/api/v3/team/ext:devs/member/bob@acme.com")
                    .to_request(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    assert_eq!(
        members(&app, "ext:devs").await,
        vec!["carol@acme.com", "dave@acme.com"]
    );

    // deleting a user removes the membership

    let response = app
        .call_service(
            TestRequest::delete()
                .uri("/api/v3/user/carol@acme.com")
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    assert_eq!(members(&app, "ext:devs").await, vec!["dave@acme.com"]);

    // unknown team

    let response = app
        .call_service(
            TestRequest::get()
                .uri("/api/v3/team/ext:unknown/member")
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}
