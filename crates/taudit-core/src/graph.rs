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
pub const META_IDENTITY_SCOPE: &str = "identity_scope";
pub const META_INFERRED: &str = "inferred";
/// Marks an Image node as a job container (not a `uses:` action).
pub const META_CONTAINER: &str = "container";
/// Marks an Identity node as OIDC-capable (`permissions: id-token: write`).
pub const META_OIDC: &str = "oidc";
/// Marks a Secret node whose value is interpolated into a CLI flag argument (e.g. `-var "key=$(SECRET)"`).
/// CLI flag values appear in pipeline log output even when ADO secret masking is active,
/// because the command string is logged before masking runs and Terraform itself logs `-var` values.
pub const META_CLI_FLAG_EXPOSED: &str = "cli_flag_exposed";
/// Graph-level metadata: identifies the trigger type (e.g. `pull_request_target`, `pr`).
pub const META_TRIGGER: &str = "trigger";
/// Marks a Step that writes to the environment gate (`$GITHUB_ENV`, ADO `##vso[task.setvariable]`).
pub const META_WRITES_ENV_GATE: &str = "writes_env_gate";
/// Marks a Step that performs cryptographic provenance attestation (e.g. `actions/attest-build-provenance`).
pub const META_ATTESTS: &str = "attests";
/// Marks a Secret node sourced from an ADO variable group (vs inline pipeline variable).
pub const META_VARIABLE_GROUP: &str = "variable_group";
/// Marks an Image node as a self-hosted agent pool (pool.name on ADO; runs-on: self-hosted on GHA).
pub const META_SELF_HOSTED: &str = "self_hosted";
/// Marks a Step that performs a `checkout: self` (ADO) or default `actions/checkout` on a PR context.
pub const META_CHECKOUT_SELF: &str = "checkout_self";
/// Marks an Identity node as an ADO service connection.
pub const META_SERVICE_CONNECTION: &str = "service_connection";
/// Marks an Identity node as implicitly injected by the platform (e.g. ADO System.AccessToken).
/// Implicit tokens are structurally accessible to all tasks by platform design — exposure
/// to untrusted steps is Info-level (structural) rather than Critical (misconfiguration).
pub const META_IMPLICIT: &str = "implicit";
/// Marks a Step that belongs to an ADO deployment job whose `environment:` is
/// configured with required approvals — a manual gate that breaks automatic
/// authority propagation. Findings whose path crosses such a node have their
/// severity reduced by one step (Critical → High → Medium → Low).
pub const META_ENV_APPROVAL: &str = "env_approval";
/// Records the parent job name on every Step node, enabling per-job subgraph
/// filtering (e.g. `taudit map --job build`) and downstream consumers that
/// need to attribute steps back to their containing job. Set by both the GHA
/// and ADO parsers on every Step they create within a job's scope.
pub const META_JOB_NAME: &str = "job_name";
/// Records the raw inline script body of a Step (the text from
/// `script:` / `bash:` / `powershell:` / `pwsh:` / `run:`). Stamped by parsers
/// when the step has an inline script. Used by command-line-leakage rules
/// (`vm_remote_exec_via_pipeline_secret`, `short_lived_sas_in_command_line`)
/// to inspect what the step actually shells out.
pub const META_SCRIPT_BODY: &str = "script_body";

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

/// Returns true if `image` is pinned to a Docker digest.
/// Docker digest format: `image@sha256:<64-hex-chars>`.
pub fn is_docker_digest_pinned(image: &str) -> bool {
    image.contains("@sha256:")
        && image
            .split("@sha256:")
            .nth(1)
            .map(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
            .unwrap_or(false)
}

// ── Graph-level precision markers ───────────────────────

/// How complete is this authority graph? Parsers set this based on whether
/// they could fully resolve all authority relationships in the pipeline YAML.
///
/// A `Partial` graph is still useful — it just tells the consumer that some
/// authority paths may be missing. This is better than silent incompleteness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityCompleteness {
    /// Parser resolved all authority relationships.
    Complete,
    /// Parser found constructs it couldn't fully resolve (e.g. secrets in
    /// shell strings, composite actions, reusable workflows). The graph
    /// captures what it can, but edges may be missing.
    Partial,
    /// Parser couldn't determine completeness.
    Unknown,
}

/// How broad is an identity's scope? Classifies the risk surface of tokens,
/// service principals, and OIDC identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityScope {
    /// Wide permissions: write-all, admin, or unscoped tokens.
    Broad,
    /// Narrow permissions: contents:read, specific scopes.
    Constrained,
    /// Scope couldn't be determined — treat as risky.
    Unknown,
}

impl IdentityScope {
    /// Classify an identity scope from a permissions string.
    pub fn from_permissions(perms: &str) -> Self {
        let p = perms.to_lowercase();
        if p.contains("write-all") || p.contains("admin") || p == "{}" || p.is_empty() {
            IdentityScope::Broad
        } else if p.contains("write") {
            // Any write permission = broad (conservative)
            IdentityScope::Broad
        } else if p.contains("read") {
            IdentityScope::Constrained
        } else {
            IdentityScope::Unknown
        }
    }
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
    /// Step -> Secret or Identity (authority granted at runtime).
    HasAccessTo,
    /// Step -> Artifact (data flows out).
    Produces,
    /// Artifact -> Step (authority flows from artifact to consuming step).
    Consumes,
    /// Step -> Image/Action (execution delegation).
    UsesImage,
    /// Step -> Step (cross-job or action boundary).
    DelegatesTo,
    /// Step -> Secret or Identity (credential written to disk, outliving the step's lifetime).
    /// Distinct from HasAccessTo: disk persistence is accessible to all subsequent steps
    /// and processes with filesystem access, not just the step that created it.
    PersistsTo,
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
    /// How complete is this graph? Set by the parser based on what it could resolve.
    pub completeness: AuthorityCompleteness,
    /// Human-readable reasons why the graph is Partial (if applicable).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completeness_gaps: Vec<String>,
    /// Graph-level metadata set by parsers (e.g. trigger type, platform-specific flags).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

impl AuthorityGraph {
    pub fn new(source: PipelineSource) -> Self {
        Self {
            source,
            nodes: Vec::new(),
            edges: Vec::new(),
            completeness: AuthorityCompleteness::Complete,
            completeness_gaps: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Mark the graph as partially complete with a reason.
    pub fn mark_partial(&mut self, reason: impl Into<String>) {
        self.completeness = AuthorityCompleteness::Partial;
        self.completeness_gaps.push(reason.into());
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
    fn completeness_default_is_complete() {
        let g = AuthorityGraph::new(PipelineSource {
            file: "test.yml".into(),
            repo: None,
            git_ref: None,
        });
        assert_eq!(g.completeness, AuthorityCompleteness::Complete);
        assert!(g.completeness_gaps.is_empty());
    }

    #[test]
    fn mark_partial_records_reason() {
        let mut g = AuthorityGraph::new(PipelineSource {
            file: "test.yml".into(),
            repo: None,
            git_ref: None,
        });
        g.mark_partial("secrets in run: block inferred, not precisely mapped");
        assert_eq!(g.completeness, AuthorityCompleteness::Partial);
        assert_eq!(g.completeness_gaps.len(), 1);
    }

    #[test]
    fn identity_scope_from_permissions() {
        assert_eq!(
            IdentityScope::from_permissions("write-all"),
            IdentityScope::Broad
        );
        assert_eq!(
            IdentityScope::from_permissions("{ contents: write }"),
            IdentityScope::Broad
        );
        assert_eq!(
            IdentityScope::from_permissions("{ contents: read }"),
            IdentityScope::Constrained
        );
        assert_eq!(
            IdentityScope::from_permissions("{ id-token: write }"),
            IdentityScope::Broad
        );
        assert_eq!(IdentityScope::from_permissions(""), IdentityScope::Broad);
        assert_eq!(
            IdentityScope::from_permissions("custom-scope"),
            IdentityScope::Unknown
        );
    }

    #[test]
    fn trust_zone_ordering() {
        assert!(TrustZone::Untrusted.is_lower_than(&TrustZone::FirstParty));
        assert!(TrustZone::ThirdParty.is_lower_than(&TrustZone::FirstParty));
        assert!(TrustZone::Untrusted.is_lower_than(&TrustZone::ThirdParty));
        assert!(!TrustZone::FirstParty.is_lower_than(&TrustZone::FirstParty));
    }
}
