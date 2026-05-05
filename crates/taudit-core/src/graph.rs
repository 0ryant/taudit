//! Authority-graph engine for `taudit-core`.
//!
//! ## What lives here
//!
//! The mutable engine: [`AuthorityGraph`] with its `add_node`, `add_edge`,
//! `mark_partial`, `stamp_edge_authority_summaries` impl, plus the structural
//! / semantic pin-validation helpers ([`is_sha_pinned`],
//! [`is_docker_digest_pinned`], [`is_pin_semantically_valid`]).
//!
//! ## What lives in `taudit-api`
//!
//! The **wire types** that compose the graph ([`Node`], [`Edge`],
//! [`PipelineSource`], [`ParamSpec`], [`AuthorityEdgeSummary`], the
//! [`NodeKind`] / [`EdgeKind`] / [`TrustZone`] / [`AuthorityCompleteness`] /
//! [`GapKind`] / [`IdentityScope`] enums, the [`NodeId`] / [`EdgeId`] type
//! aliases, and every `META_*` metadata-key constant) live in `taudit-api`.
//! They are re-exported below so every existing in-tree call site
//! (`use taudit_core::graph::NodeKind`) keeps compiling.
//!
//! `taudit-api` is the externally-stable contract surface; `taudit-core` is
//! workspace-internal. See `crates/taudit-core/src/lib.rs` for the API
//! stability docstring.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Re-exports of wire types (now owned by taudit-api) ─────────────────

pub use taudit_api::{
    serialize_string_map_sorted, AuthorityCompleteness, AuthorityEdgeSummary, Edge, EdgeId,
    EdgeKind, GapKind, IdentityScope, Node, NodeId, NodeKind, ParamSpec, PipelineSource, TrustZone,
    AUTHORITY_EDGE_SUMMARY_FIELD_MAX,
};

pub use taudit_api::{
    META_ADD_SPN_TO_ENV, META_ATTESTS, META_CACHE_KEY, META_CHECKOUT_REF, META_CHECKOUT_SELF,
    META_CLI_FLAG_EXPOSED, META_CONDITION, META_CONTAINER, META_DEPENDS_ON, META_DIGEST,
    META_DISPATCH_INPUTS, META_DOTENV_FILE, META_DOWNLOADS_ARTIFACT, META_ENVIRONMENT_NAME,
    META_ENVIRONMENT_URL, META_ENV_APPROVAL, META_ENV_GATE_WRITES_SECRET_VALUE, META_FORK_CHECK,
    META_GHA_ACTION, META_GHA_WITH_INPUTS, META_GITLAB_ALLOW_FAILURE, META_GITLAB_CACHE_KEY,
    META_GITLAB_CACHE_POLICY, META_GITLAB_DIND_SERVICE, META_GITLAB_EXTENDS, META_GITLAB_INCLUDES,
    META_GITLAB_TRIGGER_KIND, META_IDENTITY_SCOPE, META_IMPLICIT, META_INFERRED,
    META_INTERACTIVE_DEBUG, META_INTERPRETS_ARTIFACT, META_JOB_NAME, META_JOB_OUTPUTS, META_NEEDS,
    META_NO_WORKFLOW_PERMISSIONS, META_OIDC, META_OIDC_AUDIENCE, META_OIDC_AUDIENCES,
    META_PERMISSIONS, META_PLATFORM, META_READS_ENV, META_REPOSITORIES, META_RULES_PROTECTED_ONLY,
    META_SCRIPT_BODY, META_SECRETS_INHERIT, META_SELF_HOSTED, META_SERVICE_CONNECTION,
    META_SERVICE_CONNECTION_NAME, META_SETVARIABLE_ADO, META_TERRAFORM_AUTO_APPROVE, META_TRIGGER,
    META_TRIGGERS, META_VARIABLE_GROUP, META_WORKSPACE_CLEAN, META_WRITES_ENV_GATE,
};

// ── Shared helpers ─────────────────────────────────────

/// Returns true if `ref_str` is a SHA-pinned action reference.
/// Checks: contains `@`, part after `@` is >= 40 hex chars.
/// Single source of truth — used by both parser and rules.
///
/// This is a *structural* check — it accepts any 40+ hex character suffix
/// without verifying the SHA refers to a real commit. For a semantic check
/// that rejects obviously-bogus values like all-zero, see
/// [`is_pin_semantically_valid`].
pub fn is_sha_pinned(ref_str: &str) -> bool {
    ref_str.contains('@')
        && ref_str
            .split('@')
            .next_back()
            .map(|s| s.len() >= 40 && s.chars().all(|c| c.is_ascii_hexdigit()))
            .unwrap_or(false)
}

/// Returns true if `image` is pinned to a Docker digest.
/// Docker digest format: `image@sha256:<64-hex-chars-lowercase>`.
///
/// Truncated digests (e.g. `alpine@sha256:abc`) and uppercase hex are
/// rejected — Docker requires the full 64-character lowercase hex form.
pub fn is_docker_digest_pinned(image: &str) -> bool {
    image.contains("@sha256:")
        && image
            .split("@sha256:")
            .nth(1)
            .map(|h| {
                h.len() == 64
                    && h.chars()
                        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
            })
            .unwrap_or(false)
}

/// Returns true if `ref_str` looks both structurally pinned AND semantically
/// plausible. Layered on top of [`is_sha_pinned`] / [`is_docker_digest_pinned`]:
/// a structurally valid pin can still be obviously bogus (e.g. an all-zero SHA
/// is syntactically a 40-char hex string but does not refer to any real
/// commit; an attacker could use it to fake a "pinned" appearance).
///
/// Rules that want to flag impersonation attempts (rather than just laziness)
/// should call this in addition to / instead of the structural check.
///
/// Rejects:
/// - All-zero SHA-1 references (`actions/foo@0000…0000`).
/// - All-zero sha256 docker digests (`image@sha256:0000…0000`).
///
/// Anything else that passes the structural check passes here.
pub fn is_pin_semantically_valid(ref_str: &str) -> bool {
    // Docker digest form takes priority (the `@sha256:` prefix is unambiguous).
    if ref_str.contains("@sha256:") {
        if !is_docker_digest_pinned(ref_str) {
            return false;
        }
        let digest = ref_str.split("@sha256:").nth(1).unwrap_or("");
        return !digest.chars().all(|c| c == '0');
    }

    if !is_sha_pinned(ref_str) {
        return false;
    }
    let sha = ref_str.split('@').next_back().unwrap_or("");
    !sha.chars().all(|c| c == '0')
}

// ── AuthorityEdgeSummary helpers (engine-side) ─────────────────────────

fn truncate_edge_summary_field(s: &str) -> String {
    let max = AUTHORITY_EDGE_SUMMARY_FIELD_MAX;
    let n = s.chars().count();
    if n <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn trust_zone_snake_case(zone: TrustZone) -> String {
    match zone {
        TrustZone::FirstParty => "first_party".into(),
        TrustZone::ThirdParty => "third_party".into(),
        TrustZone::Untrusted => "untrusted".into(),
    }
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
    /// Typed categories for each completeness gap (parallel to `completeness_gaps`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completeness_gap_kinds: Vec<GapKind>,
    /// Graph-level metadata set by parsers (e.g. trigger type, platform-specific flags).
    /// Serialized in sorted-key order — see `Node.metadata` rationale.
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        serialize_with = "serialize_string_map_sorted"
    )]
    pub metadata: HashMap<String, String>,
    /// Top-level pipeline `parameters:` declarations, keyed by parameter name.
    /// Populated by parsers that surface parameter metadata (currently ADO).
    /// Empty for platforms / pipelines that don't declare parameters.
    /// Serialized in sorted-key order — see `Node.metadata` rationale.
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        serialize_with = "serialize_string_map_sorted"
    )]
    pub parameters: HashMap<String, ParamSpec>,
}

impl AuthorityGraph {
    pub fn new(source: PipelineSource) -> Self {
        Self {
            source,
            nodes: Vec::new(),
            edges: Vec::new(),
            completeness: AuthorityCompleteness::Complete,
            completeness_gaps: Vec::new(),
            completeness_gap_kinds: Vec::new(),
            metadata: HashMap::new(),
            parameters: HashMap::new(),
        }
    }

    /// Mark the graph as partially complete with a reason.
    pub fn mark_partial(&mut self, kind: GapKind, reason: impl Into<String>) {
        self.completeness = AuthorityCompleteness::Partial;
        self.completeness_gaps.push(reason.into());
        self.completeness_gap_kinds.push(kind);
    }

    /// Returns the most severe GapKind present, or None if the graph is complete/unknown.
    pub fn worst_gap_kind(&self) -> Option<GapKind> {
        self.completeness_gap_kinds
            .iter()
            .max_by_key(|k| match k {
                GapKind::Expression => 0u8,
                GapKind::Structural => 1,
                GapKind::Opaque => 2,
            })
            .copied()
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
        self.edges.push(Edge {
            id,
            from,
            to,
            kind,
            authority_summary: None,
        });
        id
    }

    /// Populate [`Edge::authority_summary`] for each **`HasAccessTo`** edge whose
    /// target is an **identity** node, from that node’s trust zone and
    /// allowlisted metadata (`identity_scope`, `permissions`). Idempotent.
    ///
    /// Called automatically at the end of every built-in [`crate::ports::PipelineParser`]
    /// implementation so `taudit graph --format json` and scan JSON include summaries.
    pub fn stamp_edge_authority_summaries(&mut self) {
        for edge in &mut self.edges {
            if edge.kind != EdgeKind::HasAccessTo {
                continue;
            }
            let Some(to_node) = self.nodes.get(edge.to) else {
                continue;
            };
            if to_node.kind != NodeKind::Identity {
                continue;
            }
            edge.authority_summary = Some(AuthorityEdgeSummary {
                trust_zone: Some(trust_zone_snake_case(to_node.trust_zone)),
                identity_scope: to_node
                    .metadata
                    .get(META_IDENTITY_SCOPE)
                    .map(|s| truncate_edge_summary_field(s)),
                permissions_summary: to_node
                    .metadata
                    .get(META_PERMISSIONS)
                    .map(|s| truncate_edge_summary_field(s)),
            });
        }
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
            commit_sha: None,
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
    fn stamp_edge_authority_summaries_on_has_access_to_identity() {
        let mut g = AuthorityGraph::new(PipelineSource {
            file: "ci.yml".into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        });
        let secret = g.add_node(NodeKind::Secret, "K", TrustZone::FirstParty);
        let mut id_meta = HashMap::new();
        id_meta.insert(META_IDENTITY_SCOPE.into(), "constrained".into());
        id_meta.insert(META_PERMISSIONS.into(), "read-all".into());
        let ident = g.add_node_with_metadata(
            NodeKind::Identity,
            "GITHUB_TOKEN",
            TrustZone::FirstParty,
            id_meta,
        );
        let step = g.add_node(NodeKind::Step, "s", TrustZone::FirstParty);
        let e_secret = g.add_edge(step, secret, EdgeKind::HasAccessTo);
        let e_ident = g.add_edge(step, ident, EdgeKind::HasAccessTo);

        g.stamp_edge_authority_summaries();

        assert!(g.edges[e_secret].authority_summary.is_none());
        let sum = g.edges[e_ident]
            .authority_summary
            .as_ref()
            .expect("identity edge summary");
        assert_eq!(sum.trust_zone.as_deref(), Some("first_party"));
        assert_eq!(sum.identity_scope.as_deref(), Some("constrained"));
        assert_eq!(sum.permissions_summary.as_deref(), Some("read-all"));
    }

    #[test]
    fn completeness_default_is_complete() {
        let g = AuthorityGraph::new(PipelineSource {
            file: "test.yml".into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
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
            commit_sha: None,
        });
        g.mark_partial(
            GapKind::Expression,
            "secrets in run: block inferred, not precisely mapped",
        );
        assert_eq!(g.completeness, AuthorityCompleteness::Partial);
        assert_eq!(g.completeness_gaps.len(), 1);
        assert_eq!(g.completeness_gap_kinds.len(), 1);
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

    // ── Pin validation (fuzz B3 regression) ─────────────────

    #[test]
    fn is_sha_pinned_accepts_lowercase_40_hex() {
        // 40 lowercase hex — the canonical legitimate form.
        assert!(is_sha_pinned(
            "actions/checkout@abc1234567890abcdef1234567890abcdef123456"
        ));
        // Mixed case is still structurally pinned (legitimate — Git accepts both).
        assert!(is_sha_pinned(
            "actions/checkout@ABCDEF1234567890abcdef1234567890ABCDEF12"
        ));
    }

    #[test]
    fn is_sha_pinned_structural_accepts_all_zero() {
        // Structural check is intentionally permissive — semantic rejection
        // happens in is_pin_semantically_valid. Documented in B3.
        assert!(is_sha_pinned(
            "actions/setup-python@0000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn is_sha_pinned_rejects_short_or_non_hex() {
        assert!(!is_sha_pinned("actions/checkout@v4"));
        assert!(!is_sha_pinned("actions/setup-node@a1b2c3"));
        // 60 chars but not all hex.
        assert!(!is_sha_pinned(
            "actions/checkout@somethingthatlookslikeashabutisntsha1234567890abcdef"
        ));
    }

    #[test]
    fn is_pin_semantically_valid_rejects_all_zero_sha() {
        // Fuzz B3 reproducer.
        assert!(!is_pin_semantically_valid(
            "actions/setup-python@0000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn is_pin_semantically_valid_accepts_real_looking_sha() {
        assert!(is_pin_semantically_valid(
            "actions/checkout@abc1234567890abcdef1234567890abcdef123456"
        ));
    }

    #[test]
    fn is_pin_semantically_valid_rejects_unpinned() {
        assert!(!is_pin_semantically_valid("actions/checkout@v4"));
        assert!(!is_pin_semantically_valid("actions/setup-node@a1b2c3"));
    }

    #[test]
    fn is_docker_digest_pinned_rejects_truncated() {
        // Fuzz B3 reproducer: previously accepted, now rejected.
        assert!(!is_docker_digest_pinned("alpine@sha256:abc"));
        // 65 chars (one too long).
        assert!(!is_docker_digest_pinned(
            "alpine@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcde"
        ));
        // 63 chars (one short).
        assert!(!is_docker_digest_pinned(
            "alpine@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc"
        ));
    }

    #[test]
    fn is_docker_digest_pinned_accepts_full_64_lowercase() {
        // Exactly 64 lowercase hex chars after `@sha256:`.
        assert!(is_docker_digest_pinned(
            "alpine@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
        ));
    }

    #[test]
    fn is_docker_digest_pinned_rejects_uppercase() {
        // Docker requires lowercase — uppercase indicates a hand-crafted /
        // tampered string and should not pass.
        assert!(!is_docker_digest_pinned(
            "alpine@sha256:ABC123DEF456ABC123DEF456ABC123DEF456ABC123DEF456ABC123DEF456ABCD"
        ));
    }

    #[test]
    fn is_pin_semantically_valid_rejects_all_zero_docker_digest() {
        assert!(!is_pin_semantically_valid(
            "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn is_pin_semantically_valid_accepts_real_docker_digest() {
        assert!(is_pin_semantically_valid(
            "alpine@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
        ));
    }
}
