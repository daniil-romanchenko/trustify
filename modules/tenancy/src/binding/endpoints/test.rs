use crate::test::{caller, create_group};
use actix_http::StatusCode;
use actix_web::{http::header, test::TestRequest};
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyContext, call::CallService};

async fn bindings(app: &impl CallService, group: &str) -> Value {
    app.call_and_read_body_json(
        TestRequest::get()
            .uri(&format!("/api/v3/group/sbom/{group}/binding"))
            .to_request(),
    )
    .await
}

/// Reduce bindings to `(principal, role)` pairs, for comparing.
fn principals(bindings: &Value) -> Vec<(Value, String)> {
    let mut result: Vec<_> = bindings
        .as_array()
        .into_iter()
        .flatten()
        .map(|b| {
            (
                b["principal"].clone(),
                b["role"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    result.sort_by_key(|(p, _)| p.to_string());
    result
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn replace_bindings(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;
    let acme = create_group("acme", None, Some("acme"), &ctx.db).await?;
    create_group("payments", Some(acme), Some("acme.payments"), &ctx.db).await?;

    let response = app
        .call_service(
            TestRequest::put()
                .uri("/api/v3/team/ext:acme.devs")
                .set_json(json!({"name": "Devs"}))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let team: Value = actix_web::test::read_body_json(response).await;
    let team_id = team["id"].as_str().expect("must have an ID").to_string();

    // replace, by external ID of group and team

    let response = app
        .call_service(
            TestRequest::put()
                .uri("/api/v3/group/sbom/ext:acme.payments/binding")
                .set_json(json!([
                    {"principal": {"team": "ext:acme.devs"}, "role": "viewer"},
                    {"principal": {"user": "Lead@acme.com"}, "role": "admin"},
                ]))
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

    let result = bindings(&app, "ext:acme.payments").await;
    assert_eq!(
        principals(&result),
        vec![
            (json!({"team": team_id}), "viewer".to_string()),
            (json!({"user": "lead@acme.com"}), "admin".to_string()),
        ]
    );

    // replacing with the same content is a no-op, and keeps the revision

    let response = app
        .call_service(
            TestRequest::put()
                .uri("/api/v3/group/sbom/ext:acme.payments/binding")
                .insert_header((header::IF_MATCH, etag.clone()))
                .set_json(json!([
                    {"principal": {"user": "lead@acme.com"}, "role": "admin"},
                    {"principal": {"team": team_id}, "role": "viewer"},
                ]))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok()),
        Some(etag.as_str())
    );

    // change a role, and drop the team

    let response = app
        .call_service(
            TestRequest::put()
                .uri("/api/v3/group/sbom/ext:acme.payments/binding")
                .insert_header((header::IF_MATCH, etag.clone()))
                .set_json(json!([
                    {"principal": {"user": "lead@acme.com"}, "role": "editor"},
                ]))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let result = bindings(&app, "ext:acme.payments").await;
    assert_eq!(
        principals(&result),
        vec![(json!({"user": "lead@acme.com"}), "editor".to_string())]
    );

    // the old revision is now stale

    let response = app
        .call_service(
            TestRequest::put()
                .uri("/api/v3/group/sbom/ext:acme.payments/binding")
                .insert_header((header::IF_MATCH, etag))
                .set_json(json!([]))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn invalid_bindings(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;
    let group = create_group("acme", None, None, &ctx.db).await?;

    for body in [
        // unknown team
        json!([{"principal": {"team": "ext:unknown"}, "role": "viewer"}]),
        // duplicate principal
        json!([
            {"principal": {"user": "a@acme.com"}, "role": "viewer"},
            {"principal": {"user": "A@acme.com"}, "role": "admin"},
        ]),
        // unknown role
        json!([{"principal": {"user": "a@acme.com"}, "role": "owner"}]),
        // invalid e-mail
        json!([{"principal": {"user": "a"}, "role": "viewer"}]),
    ] {
        let response = app
            .call_service(
                TestRequest::put()
                    .uri(&format!("/api/v3/group/sbom/{group}/binding"))
                    .set_json(&body)
                    .to_request(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
    }

    // nothing was applied

    assert_eq!(bindings(&app, &group.to_string()).await, json!([]));

    // unknown group

    for request in [
        TestRequest::get().uri("/api/v3/group/sbom/ext:unknown/binding"),
        TestRequest::put()
            .uri("/api/v3/group/sbom/ext:unknown/binding")
            .set_json(json!([])),
        TestRequest::put()
            .uri("/api/v3/group/sbom/ext:unknown/binding/user/a@acme.com")
            .set_json(json!({"role": "viewer"})),
    ] {
        let response = app.call_service(request.to_request()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn single_bindings_and_access(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;
    let acme = create_group("acme", None, Some("acme"), &ctx.db).await?;
    let payments = create_group("payments", Some(acme), None, &ctx.db).await?;

    for request in [
        TestRequest::put()
            .uri("/api/v3/team/ext:devs")
            .set_json(json!({"name": "Devs"})),
        TestRequest::put().uri("/api/v3/team/ext:devs/member/alice@acme.com"),
        TestRequest::put()
            .uri("/api/v3/group/sbom/ext:acme/binding/team/ext:devs")
            .set_json(json!({"role": "viewer"})),
        TestRequest::put()
            .uri(&format!(
                "/api/v3/group/sbom/{payments}/binding/user/alice@acme.com"
            ))
            .set_json(json!({"role": "uploader"})),
        // setting it again, with a different role, replaces it
        TestRequest::put()
            .uri(&format!(
                "/api/v3/group/sbom/{payments}/binding/user/alice@acme.com"
            ))
            .set_json(json!({"role": "editor"})),
    ] {
        let response = app.call_service(request.to_request()).await;
        assert!(response.status().is_success(), "{}", response.status());
    }

    let access: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/user/alice@acme.com/access")
                .to_request(),
        )
        .await;
    let access = access.as_array().cloned().unwrap_or_default();
    assert_eq!(access.len(), 2, "{access:?}");
    assert!(access.contains(&json!({
        "group": payments.to_string(),
        "role": "editor",
        "via": {"kind": "direct"},
    })));
    assert!(
        access
            .iter()
            .any(|a| a["group"] == acme.to_string() && a["via"]["kind"] == "team"),
        "{access:?}"
    );

    // removing is idempotent, also for unknown principals

    for uri in [
        format!("/api/v3/group/sbom/{payments}/binding/user/alice@acme.com"),
        format!("/api/v3/group/sbom/{payments}/binding/user/alice@acme.com"),
        format!("/api/v3/group/sbom/{payments}/binding/user/nobody@acme.com"),
        "/api/v3/group/sbom/ext:acme/binding/team/ext:nobody".to_string(),
    ] {
        let response = app
            .call_service(TestRequest::delete().uri(&uri).to_request())
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT, "{uri}");
    }

    // deleting the team removes its bindings

    let response = app
        .call_service(
            TestRequest::delete()
                .uri("/api/v3/team/ext:devs")
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    assert_eq!(bindings(&app, "ext:acme").await, json!([]));

    Ok(())
}
