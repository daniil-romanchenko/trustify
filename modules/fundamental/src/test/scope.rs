//! Ensure the access scope is enforced, and doesn't leak SBOMs of other groups.

use crate::test::caller;
use actix_http::{HttpMessage, Request, StatusCode};
use actix_web::test::TestRequest;
use sea_orm::{ActiveModelTrait, Set};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use test_context::test_context;
use test_log::test;
use trustify_auth::{Permission, authorizer::AccessScope};
use trustify_entity::{labels::Labels, sbom_group, sbom_group_assignment};
use trustify_test_context::{TrustifyContext, call::CallService, document_bytes};
use uuid::Uuid;

/// Two groups, each holding one SBOM.
struct Tenants {
    a: Uuid,
    b: Uuid,
    sbom_a: String,
    sbom_b: String,
}

impl Tenants {
    async fn new(ctx: &TrustifyContext) -> anyhow::Result<Self> {
        let a = group("a", ctx).await?;
        let b = group("b", ctx).await?;

        let sbom_a = sbom("cyclonedx/application.cdx.json", a, ctx).await?;
        let sbom_b = sbom("spdx/OCP-TOOLS-4.11-RHEL-8.json", b, ctx).await?;

        Ok(Self {
            a,
            b,
            sbom_a,
            sbom_b,
        })
    }
}

async fn group(name: &str, ctx: &TrustifyContext) -> anyhow::Result<Uuid> {
    let id = Uuid::now_v7();
    sbom_group::ActiveModel {
        id: Set(id),
        parent: Set(None),
        name: Set(name.into()),
        description: Set(None),
        revision: Set(Uuid::now_v7()),
        labels: Set(Labels::default()),
        kind: Set(None),
        external_id: Set(None),
    }
    .insert(&ctx.db)
    .await?;
    Ok(id)
}

async fn sbom(path: &str, group: Uuid, ctx: &TrustifyContext) -> anyhow::Result<String> {
    let result = ctx.ingest_document(path).await?;
    let id = result.id.to_string();
    let id = id.strip_prefix("urn:uuid:").unwrap_or(&id).to_string();

    sbom_group_assignment::ActiveModel {
        sbom_id: Set(Uuid::parse_str(&id)?),
        group_id: Set(group),
    }
    .insert(&ctx.db)
    .await?;

    Ok(id)
}

fn scope(group: Uuid, permissions: &[Permission]) -> AccessScope {
    AccessScope::scoped(HashMap::from([(
        group,
        permissions.iter().copied().collect::<HashSet<_>>(),
    )]))
}

fn viewer(group: Uuid) -> AccessScope {
    scope(
        group,
        &[
            Permission::ReadSbom,
            Permission::ReadSbomGroup,
            Permission::ReadMetadata,
        ],
    )
}

fn editor(group: Uuid) -> AccessScope {
    scope(
        group,
        &[
            Permission::ReadSbom,
            Permission::ReadSbomGroup,
            Permission::CreateSbom,
            Permission::UpdateSbom,
            Permission::DeleteSbom,
        ],
    )
}

fn scoped(request: TestRequest, scope: &AccessScope) -> Request {
    let request = request.to_request();
    request.extensions_mut().insert(scope.clone());
    request
}

async fn ids(app: &impl CallService, uri: &str, scope: &AccessScope) -> Vec<String> {
    let result: Value = app
        .call_and_read_body_json(scoped(TestRequest::get().uri(uri), scope))
        .await;
    result["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item["id"].as_str())
        .map(|id| id.strip_prefix("urn:uuid:").unwrap_or(id).to_string())
        .collect()
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn read_sboms(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;
    let t = Tenants::new(ctx).await?;
    let scope_a = viewer(t.a);

    // listing only shows SBOMs of the scope

    assert_eq!(
        ids(&app, "/api/v3/sbom", &scope_a).await,
        vec![t.sbom_a.clone()]
    );
    assert_eq!(
        ids(&app, "/api/v2/sbom", &scope_a).await,
        vec![t.sbom_a.clone()]
    );
    assert!(
        ids(&app, "/api/v3/sbom", &AccessScope::none())
            .await
            .is_empty()
    );
    assert_eq!(
        ids(&app, "/api/v3/sbom", &AccessScope::Unrestricted)
            .await
            .len(),
        2
    );

    // filtering by a group outside the scope yields nothing

    assert!(
        ids(&app, &format!("/api/v3/sbom?group={}", t.b), &scope_a)
            .await
            .is_empty()
    );

    // reading an SBOM of the scope works, one of another group is not found

    for suffix in [
        "",
        "/packages",
        "/related",
        "/advisory",
        "/all-license-ids",
        "/download",
        "/license-export",
    ] {
        let ok = app
            .call_service(scoped(
                TestRequest::get().uri(&format!("/api/v3/sbom/urn:uuid:{}{suffix}", t.sbom_a)),
                &scope_a,
            ))
            .await;
        assert_eq!(ok.status(), StatusCode::OK, "own SBOM: {suffix}");

        let hidden = app
            .call_service(scoped(
                TestRequest::get().uri(&format!("/api/v3/sbom/urn:uuid:{}{suffix}", t.sbom_b)),
                &scope_a,
            ))
            .await;
        assert_eq!(
            hidden.status(),
            StatusCode::NOT_FOUND,
            "other SBOM: {suffix}"
        );
    }

    // assignments only show groups of the scope

    let assignments: Value = app
        .call_and_read_body_json(scoped(
            TestRequest::get().uri(&format!("/api/v3/group/sbom-assignment/{}", t.sbom_a)),
            &scope_a,
        ))
        .await;
    assert_eq!(assignments, json!([t.a.to_string()]));

    let response = app
        .call_service(scoped(
            TestRequest::get().uri(&format!("/api/v3/group/sbom-assignment/{}", t.sbom_b)),
            &scope_a,
        ))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn by_package(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;
    let t = Tenants::new(ctx).await?;

    // take a package of SBOM A

    let packages: Value = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri(&format!("/api/v3/sbom/urn:uuid:{}/packages", t.sbom_a))
                .to_request(),
        )
        .await;
    let purl = packages["items"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|p| p["purl"].as_array().cloned().unwrap_or_default())
        .find_map(|p| p["purl"].as_str().map(ToString::to_string))
        .ok_or_else(|| anyhow::anyhow!("SBOM A must have a package with a PURL"))?;
    let uri = format!(
        "/api/v3/sbom/by-package?purl={}",
        urlencoding::encode(&purl)
    );

    assert_eq!(ids(&app, &uri, &viewer(t.a)).await, vec![t.sbom_a.clone()]);
    assert!(ids(&app, &uri, &viewer(t.b)).await.is_empty());

    let counts: Value = app
        .call_and_read_body_json(scoped(
            TestRequest::get()
                .uri("/api/v3/sbom/count-by-package")
                .set_json(json!([{"purl": purl}])),
            &viewer(t.b),
        ))
        .await;
    assert_eq!(counts, json!([0]));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn modify_sboms(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;
    let t = Tenants::new(ctx).await?;
    let scope_a = editor(t.a);

    // labels of another group's SBOM can't be changed

    let response = app
        .call_service(scoped(
            TestRequest::put()
                .uri(&format!("/api/v3/sbom/urn:uuid:{}/label", t.sbom_b))
                .set_json(json!({"foo": "bar"})),
            &scope_a,
        ))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // assigning an SBOM into another group is rejected

    let response = app
        .call_service(scoped(
            TestRequest::put()
                .uri(&format!("/api/v3/group/sbom-assignment/{}", t.sbom_a))
                .set_json(json!([t.b.to_string()])),
            &scope_a,
        ))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // replacing assignments keeps those outside the scope

    sbom_group_assignment::ActiveModel {
        sbom_id: Set(Uuid::parse_str(&t.sbom_a)?),
        group_id: Set(t.b),
    }
    .insert(&ctx.db)
    .await?;

    let a2 = group("a2", ctx).await?;
    let scope_a_a2 = AccessScope::scoped(HashMap::from([
        (
            t.a,
            HashSet::from([Permission::ReadSbom, Permission::UpdateSbom]),
        ),
        (
            a2,
            HashSet::from([Permission::ReadSbom, Permission::UpdateSbom]),
        ),
    ]));
    let response = app
        .call_service(scoped(
            TestRequest::put()
                .uri(&format!("/api/v3/group/sbom-assignment/{}", t.sbom_a))
                .set_json(json!([a2.to_string()])),
            &scope_a_a2,
        ))
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let mut assignments: Vec<String> = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri(&format!("/api/v3/group/sbom-assignment/{}", t.sbom_a))
                .to_request(),
        )
        .await;
    assignments.sort();
    let mut expected = vec![a2.to_string(), t.b.to_string()];
    expected.sort();
    assert_eq!(assignments, expected);

    // deleting another group's SBOM is a no-op

    let response = app
        .call_service(scoped(
            TestRequest::delete().uri(&format!("/api/v3/sbom/urn:uuid:{}", t.sbom_b)),
            &scope_a,
        ))
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        ids(&app, "/api/v3/sbom", &AccessScope::Unrestricted)
            .await
            .len(),
        2
    );

    // uploads need a group of the scope

    let payload = document_bytes("quarkus-bom-2.13.8.Final-redhat-00004.json").await?;
    for (uri, expected) in [
        ("/api/v3/sbom".to_string(), StatusCode::BAD_REQUEST),
        (
            format!("/api/v3/sbom?group={}", t.b),
            StatusCode::BAD_REQUEST,
        ),
        (format!("/api/v3/sbom?group={}", t.a), StatusCode::CREATED),
    ] {
        let response = app
            .call_service(scoped(
                TestRequest::post().uri(&uri).set_payload(payload.clone()),
                &scope_a,
            ))
            .await;
        assert_eq!(response.status(), expected, "{uri}");
    }

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn groups(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;
    let t = Tenants::new(ctx).await?;
    let scope_a = viewer(t.a);

    let listed = ids(&app, "/api/v3/group/sbom", &scope_a).await;
    assert_eq!(listed, vec![t.a.to_string()]);

    let response = app
        .call_service(scoped(
            TestRequest::get().uri(&format!("/api/v3/group/sbom/{}", t.b)),
            &scope_a,
        ))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // top-level groups can only be created with unrestricted access

    let admin_a = scope(
        t.a,
        &[
            Permission::ReadSbomGroup,
            Permission::CreateSbomGroup,
            Permission::UpdateSbomGroup,
            Permission::DeleteSbomGroup,
        ],
    );
    for (body, expected) in [
        (json!({"name": "top"}), StatusCode::FORBIDDEN),
        (
            json!({"name": "child", "parent": t.b.to_string()}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"name": "child", "parent": t.a.to_string()}),
            StatusCode::CREATED,
        ),
    ] {
        let response = app
            .call_service(scoped(
                TestRequest::post()
                    .uri("/api/v3/group/sbom")
                    .set_json(&body),
                &admin_a,
            ))
            .await;
        assert_eq!(response.status(), expected, "{body}");
    }

    // another group can't be deleted, the call is a no-op

    let response = app
        .call_service(scoped(
            TestRequest::delete().uri(&format!("/api/v3/group/sbom/{}", t.b)),
            &admin_a,
        ))
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = app
        .call_service(
            TestRequest::get()
                .uri(&format!("/api/v3/group/sbom/{}", t.b))
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;
    let t = Tenants::new(ctx).await?;

    let report: Value = app
        .call_and_read_body_json(scoped(
            TestRequest::post()
                .uri("/api/v3/purl/recommend/report")
                .set_json(json!({"sbom_ids": [t.sbom_a, t.sbom_b]})),
            &viewer(t.a),
        ))
        .await;

    // SBOM B is not part of the report, as if it didn't exist
    let text = report.to_string();
    assert!(!text.contains(&t.sbom_b), "{report:#}");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn sbom_permissions(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;
    let t = Tenants::new(ctx).await?;

    let permissions = |scope: Option<AccessScope>| {
        let body = json!([t.sbom_a, t.sbom_b, "not-an-id", Uuid::now_v7()]);
        let app = &app;
        async move {
            let request = TestRequest::post()
                .uri("/api/v3/sbom-permissions")
                .set_json(body);
            let request = match &scope {
                Some(scope) => scoped(request, scope),
                None => request.to_request(),
            };
            app.call_and_read_body_json::<Value>(request).await
        }
    };

    // unrestricted: all SBOMs which exist, with all permissions
    assert_eq!(
        permissions(None).await,
        json!({
            &t.sbom_a: ["read.sbom", "update.sbom", "delete.sbom"],
            &t.sbom_b: ["read.sbom", "update.sbom", "delete.sbom"],
        })
    );

    // scoped: permissions of the groups, SBOMs of other groups are omitted
    assert_eq!(
        permissions(Some(editor(t.a))).await,
        json!({ &t.sbom_a: ["read.sbom", "update.sbom", "delete.sbom"] })
    );

    let mut groups = HashMap::new();
    groups.insert(
        t.a,
        HashSet::from([Permission::ReadSbom, Permission::UpdateSbom]),
    );
    groups.insert(t.b, HashSet::from([Permission::ReadSbom]));
    assert_eq!(
        permissions(Some(AccessScope::scoped(groups))).await,
        json!({
            &t.sbom_a: ["read.sbom", "update.sbom"],
            &t.sbom_b: ["read.sbom"],
        })
    );

    // IDs in the `urn:uuid:` form, as returned by the SBOM endpoints, are kept as requested
    let request = TestRequest::post()
        .uri("/api/v3/sbom-permissions")
        .set_json(json!([format!("urn:uuid:{}", t.sbom_a), t.sbom_b]));
    assert_eq!(
        app.call_and_read_body_json::<Value>(scoped(request, &viewer(t.a)))
            .await,
        json!({ format!("urn:uuid:{}", t.sbom_a): ["read.sbom"] })
    );

    // the number of SBOMs is limited
    let request = TestRequest::post()
        .uri("/api/v3/sbom-permissions")
        .set_json(vec![Uuid::now_v7().to_string(); 1001])
        .to_request();
    assert_eq!(
        app.call_service(request).await.status(),
        StatusCode::BAD_REQUEST
    );

    Ok(())
}
