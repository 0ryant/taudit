use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique identifier for a node in the authority graph.
pub type NodeId = usize;

/// Unique identifier for an edge in the authority graph.
pub type EdgeId = usize;

// ── Metadata key constants ─────────────────────────────
// Avoids stringly-typed bugs across crate boundaries.

pub const META_DIGEST: &str = "digest";
pub const META_PERMISSIONS: &str = "permissions";

// ── Shared helpers ─────────────────────────────────────

/// Returns true if `ref_str` is a SHA-pinned action reference.
/// Checks: contains `@`, part after `@` is >= 40 hex chars.
/// Single source of truth — used by both parser and rules.
pub fn is_sha_pinned(ref_str: &str) -> bool {
    ref_str.contains('@')
        && ref_str
            .split('@')
            .next_back()
            .map(|s| s.len() >= 40 && s.chars().all(|c| c.is_ascii_hexdigit()))
            .unwrap_or(false)
}

// ── Node types ──────────────────────────────────────────

/// Semantic kind of a graph node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Step,
    Secret,
    Artifact,
    Identity,
    Image,
}

/// Trust classification. Explicit on every node — not inferred from kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustZone {
    /// Code/config authored by the repo owner.
    FirstParty,
    /// Marketplace actions, external images (pinned).
    ThirdParty,
    /// Unpinned actions, fork PRs, user input.
    Untrusted,
}

impl TrustZone {
    /// Returns true if `self` is a lower trust level than `other`.
    pub fn is_lower_than(&self, other: &TrustZone) -> bool {
        self.rank() < other.rank()
    }

    fn rank(&self) -> u8 {
        match self {
            TrustZone::FirstParty => 2,
            TrustZone::ThirdParty => 1,
            TrustZone::Untrusted => 0,
        }
    }
}

/// A node in the authority graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,
    pub name: String,
    pub trust_zone: TrustZone,
    /// Flexible metadata: pinning status, digest, scope, permissions, etc.
    pub metadata: HashMap<String, String>,
}

// ── Edge types ──────────────────────────────────────────

/// Edge semantics model authority/data flow — not syntactic YAML relations.
/// Design test: "Can authority propagate along this edge?"
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Step -> Secret or Identity (authority granted).
    HasAccessTo,
    /// Step -> Artifact (data flows out).
    Produces,
    /// Artifact -> Step (authority flows from artifact to consuming step).
    Consumes,
    /// Step -> Image/Action (execution delegation).
    UsesImage,
    /// Step -> Step (cross-job or action boundary).
    DelegatesTo,
}

/// A directed edge in the authority graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub id: EdgeId,
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
}

// ── Pipeline source ─────────────────────────────────────

/// Where the pipeline definition came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineSource {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
}

// ── The graph ───────────────────────────────────────────

/// Directed authority graph. Nodes are pipeline elements (steps, secrets,
/// artifacts, identities, images). Edges model authority/data flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityGraph {
    pub source: PipelineSource,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

impl AuthorityGraph {
    pub fn new(source: PipelineSource) -> Self {
        Self {
            source,
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Add a node, returns its ID.
    pub fn add_node(
        &mut self,
        kind: NodeKind,
        name: impl Into<String>,
        trust_zone: TrustZone,
    ) -> NodeId {
        let id = self.nodes.len();
        self.nodes.push(Node {
            id,
            kind,
            name: name.into(),
            trust_zone,
            metadata: HashMap::new(),
        });
        id
    }

    /// Add a node with metadata, returns its ID.
    pub fn add_node_with_metadata(
        &mut self,
        kind: NodeKind,
        name: impl Into<String>,
        trust_zone: TrustZone,
        metadata: HashMap<String, String>,
    ) -> NodeId {
        let id = self.nodes.len();
        self.nodes.push(Node {
            id,
            kind,
            name: name.into(),
            trust_zone,
            metadata,
        });
        id
    }

    /// Add a directed edge, returns its ID.
    pub fn add_edge(&mut self, from: NodeId, to: NodeId, kind: EdgeKind) -> EdgeId {
        let id = self.edges.len();
        self.edges.push(Edge { id, from, to, kind });
        id
    }

    /// Outgoing edges from a node.
    pub fn edges_from(&self, id: NodeId) -> impl Iterator<Item = &Edge> {
        self.edges.iter().filter(move |e| e.from == id)
    }

    /// Incoming edges to a node.
    pub fn edges_to(&self, id: NodeId) -> impl Iterator<Item = &Edge> {
        self.edges.iter().filter(move |e| e.to == id)
    }

    /// All authority-bearing source nodes (Secret + Identity).
    /// These are the BFS start set for propagation analysis.
    pub fn authority_sources(&self) -> impl Iterator<Item = &Node> {
        self.nodes
            .iter()
            .filter(|n| matches!(n.kind, NodeKind::Secret | NodeKind::Identity))
    }

    /// All nodes of a given kind.
    pub fn nodes_of_kind(&self, kind: NodeKind) -> impl Iterator<Item = &Node> {
        self.nodes.iter().filter(move |n| n.kind == kind)
    }

    /// All nodes in a given trust zone.
    pub fn nodes_in_zone(&self, zone: TrustZone) -> impl Iterator<Item = &Node> {
        self.nodes.iter().filter(move |n| n.trust_zone == zone)
    }

    /// Get a node by ID.
    pub fn node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(id)
    }

    /// Get an edge by ID.
    pub fn edge(&self, id: EdgeId) -> Option<&Edge> {
        self.edges.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_simple_graph() {
        let mut g = AuthorityGraph::new(PipelineSource {
            file: "deploy.yml".into(),
            repo: None,
            git_ref: None,
        });

        let secret = g.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
        let step_build = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        let artifact = g.add_node(NodeKind::Artifact, "dist.tar.gz", TrustZone::FirstParty);
        let step_deploy = g.add_node(NodeKind::Step, "deploy", TrustZone::ThirdParty);

        g.add_edge(step_build, secret, EdgeKind::HasAccessTo);
        g.add_edge(step_build, artifact, EdgeKind::Produces);
        g.add_edge(artifact, step_deploy, EdgeKind::Consumes);

        assert_eq!(g.nodes.len(), 4);
        assert_eq!(g.edges.len(), 3);
        assert_eq!(g.authority_sources().count(), 1);
        assert_eq!(g.edges_from(step_build).count(), 2);
        assert_eq!(g.edges_from(artifact).count(), 1); // Consumes flows artifact -> step
    }

    #[test]
    fn trust_zone_ordering() {
        assert!(TrustZone::Untrusted.is_lower_than(&TrustZone::FirstParty));
        assert!(TrustZone::ThirdParty.is_lower_than(&TrustZone::FirstParty));
        assert!(TrustZone::Untrusted.is_lower_than(&TrustZone::ThirdParty));
        assert!(!TrustZone::FirstParty.is_lower_than(&TrustZone::FirstParty));
    }
}
