//! Graph queries must not reveal SBOMs outside the visible groups.

use crate::{
    config::AnalysisConfig,
    model::Node,
    service::{AnalysisService, ComponentReference, QueryOptions},
};
use sea_orm::{ActiveModelTrait, Set};
use std::collections::HashSet;
use test_context::test_context;
use trustify_common::{db::ReadOnly, model::Paginated};
use trustify_entity::{labels::Labels, sbom_group, sbom_group_assignment};
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

async fn group_with(sbom: &str, ctx: &TrustifyContext) -> anyhow::Result<Uuid> {
    let id = Uuid::now_v7();
    sbom_group::ActiveModel {
        id: Set(id),
        parent: Set(None),
        name: Set(id.to_string()),
        description: Set(None),
        revision: Set(Uuid::now_v7()),
        labels: Set(Labels::default()),
        kind: Set(None),
        external_id: Set(None),
    }
    .insert(&ctx.db)
    .await?;

    sbom_group_assignment::ActiveModel {
        sbom_id: Set(Uuid::parse_str(
            sbom.strip_prefix("urn:uuid:").unwrap_or(sbom),
        )?),
        group_id: Set(id),
    }
    .insert(&ctx.db)
    .await?;

    Ok(id)
}

fn sbom_ids(nodes: &[Node], ids: &mut HashSet<String>) {
    for node in nodes {
        ids.insert(node.base.sbom_id.clone());
        sbom_ids(node.descendants.as_deref().unwrap_or_default(), ids);
        sbom_ids(node.ancestors.as_deref().unwrap_or_default(), ids);
    }
}

#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn prune_at_sbom_boundary(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let results = ctx
        .ingest_documents(["spdx/simple-ext-a.json", "spdx/simple-ext-b.json"])
        .await?;
    let sbom_a = results[0].id.to_string();
    let sbom_b = results[1].id.to_string();
    let group_a = group_with(&sbom_a, ctx).await?;
    let group_b = group_with(&sbom_b, ctx).await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));
    let query = |groups: Option<Vec<Uuid>>| {
        let service = service.clone();
        async move {
            let result = service
                .retrieve_scoped(
                    ComponentReference::Name("A"),
                    QueryOptions {
                        descendants: 10,
                        ..Default::default()
                    },
                    Paginated::default(),
                    groups,
                    &ctx.db,
                )
                .await?;
            let mut ids = HashSet::new();
            sbom_ids(&result.items, &mut ids);
            Ok::<_, anyhow::Error>((result.items.len(), ids))
        }
    };

    // unrestricted, the walk crosses into SBOM B

    let (count, ids) = query(None).await?;
    assert!(count > 0);
    assert_eq!(ids.len(), 2, "{ids:?}");

    // only group A: the walk stops at the boundary

    let (count, ids) = query(Some(vec![group_a])).await?;
    assert!(count > 0);
    let strip = |id: &str| id.strip_prefix("urn:uuid:").unwrap_or(id).to_string();
    assert_eq!(
        ids.iter().map(|id| strip(id)).collect::<HashSet<_>>(),
        HashSet::from([strip(&sbom_a)])
    );

    // only group B: component A of SBOM A is not found at all

    let (_, ids) = query(Some(vec![group_b])).await?;
    assert!(!ids.iter().any(|id| strip(id) == strip(&sbom_a)), "{ids:?}");

    // no groups at all

    let (count, _) = query(Some(vec![])).await?;
    assert_eq!(count, 0);

    Ok(())
}
