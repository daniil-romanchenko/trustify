//! Limiting graph queries to SBOMs visible to the caller.

use crate::{
    Error,
    model::{Node, PackageGraph},
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect};
use std::{collections::HashSet, sync::Arc};
use trustify_entity::sbom_group_assignment;
use uuid::Uuid;

/// Determine which of the SBOMs are assigned to any of the visible groups.
///
/// Returns `None` if there is no restriction.
pub(crate) async fn visible_sboms(
    visible_groups: Option<&[Uuid]>,
    candidates: impl IntoIterator<Item = Uuid>,
    connection: &impl ConnectionTrait,
) -> Result<Option<HashSet<Uuid>>, Error> {
    let Some(groups) = visible_groups else {
        return Ok(None);
    };

    let candidates: HashSet<Uuid> = candidates.into_iter().collect();
    if candidates.is_empty() || groups.is_empty() {
        return Ok(Some(HashSet::new()));
    }

    let visible = sbom_group_assignment::Entity::find()
        .select_only()
        .column(sbom_group_assignment::Column::SbomId)
        .filter(sbom_group_assignment::Column::GroupId.is_in(groups.to_vec()))
        .filter(sbom_group_assignment::Column::SbomId.is_in(candidates))
        .into_tuple::<Uuid>()
        .all(connection)
        .await?;

    Ok(Some(visible.into_iter().collect()))
}

/// Only keep the graphs of visible SBOMs.
pub(crate) async fn restrict_graphs(
    graphs: Vec<(Uuid, Arc<PackageGraph>)>,
    visible_groups: Option<&[Uuid]>,
    connection: &impl ConnectionTrait,
) -> Result<Vec<(Uuid, Arc<PackageGraph>)>, Error> {
    let Some(visible) =
        visible_sboms(visible_groups, graphs.iter().map(|(id, _)| *id), connection).await?
    else {
        return Ok(graphs);
    };

    Ok(graphs
        .into_iter()
        .filter(|(id, _)| visible.contains(id))
        .collect())
}

/// Remove nodes of invisible SBOMs, including everything reached through them.
///
/// Ancestors and descendants may cross SBOM boundaries through external references. The walk is
/// cut at the first node of an SBOM which isn't visible.
pub(crate) async fn prune_nodes(
    nodes: Vec<Node>,
    visible_groups: Option<&[Uuid]>,
    connection: &impl ConnectionTrait,
) -> Result<Vec<Node>, Error> {
    if visible_groups.is_none() {
        return Ok(nodes);
    }

    let mut candidates = HashSet::new();
    for node in &nodes {
        collect_sbom_ids(node, &mut candidates);
    }

    let visible = visible_sboms(visible_groups, candidates, connection)
        .await?
        .unwrap_or_default();

    Ok(nodes
        .into_iter()
        .filter_map(|node| prune(node, &visible))
        .collect())
}

fn is_visible(node: &Node, visible: &HashSet<Uuid>) -> bool {
    Uuid::parse_str(&node.base.sbom_id).is_ok_and(|id| visible.contains(&id))
}

fn collect_sbom_ids(node: &Node, ids: &mut HashSet<Uuid>) {
    if let Ok(id) = Uuid::parse_str(&node.base.sbom_id) {
        ids.insert(id);
    }
    for child in node
        .ancestors
        .iter()
        .flatten()
        .chain(node.descendants.iter().flatten())
    {
        collect_sbom_ids(child, ids);
    }
}

fn prune(mut node: Node, visible: &HashSet<Uuid>) -> Option<Node> {
    if !is_visible(&node, visible) {
        return None;
    }

    let prune_all = |nodes: Option<Vec<Node>>| {
        nodes.map(|nodes| {
            nodes
                .into_iter()
                .filter_map(|node| prune(node, visible))
                .collect()
        })
    };

    node.ancestors = prune_all(node.ancestors.take());
    node.descendants = prune_all(node.descendants.take());

    Some(node)
}
