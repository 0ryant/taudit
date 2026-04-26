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
/// Graph-level metadata: JSON-encoded array of `resources.repositories[]`
/// entries declared by the pipeline. Each entry is an object with fields
/// `alias`, `repo_type`, `name`, optional `ref`, and `used` (true when the
/// alias is referenced via `template: x@alias`, `extends: x@alias`, or
/// `checkout: alias` somewhere in the same pipeline file). Set by the ADO
/// parser; consumed by `template_extends_unpinned_branch`.
pub const META_REPOSITORIES: &str = "repositories";
/// Records the raw inline script body of a Step (the text from
/// `script:` / `bash:` / `powershell:` / `pwsh:` / `run:` / task
/// `inputs.script` / `inputs.Inline` / `inputs.inlineScript`). Stamped by
/// parsers when the step has an inline script. Consumed by script-aware
/// rules: `vm_remote_exec_via_pipeline_secret`,
/// `short_lived_sas_in_command_line`, `secret_to_inline_script_env_export`,
/// `secret_materialised_to_workspace_file`, `keyvault_secret_to_plaintext`,
/// `add_spn_with_inline_script`, `parameter_interpolation_into_shell`.
/// Stored verbatim — rules apply their own pattern matching.
pub const META_SCRIPT_BODY: &str = "script_body";
/// Records the name of the ADO service connection a step uses (the value of
/// `inputs.azureSubscription` / `inputs.connectedServiceName*`). Set on the
/// Step node itself (in addition to the Identity node it links to) so rules
/// can pattern-match on the connection name without traversing edges.
pub const META_SERVICE_CONNECTION_NAME: &str = "service_connection_name";
/// Marks a Step as performing `terraform apply ... -auto-approve` (either via
/// an inline script or via a `TerraformCLI` / `TerraformTask` task with
/// `command: apply` and `commandOptions` containing `auto-approve`).
pub const META_TERRAFORM_AUTO_APPROVE: &str = "terraform_auto_approve";
/// Marks a Step task that runs with `addSpnToEnvironment: true`, exposing
/// the federated SPN (idToken / servicePrincipalKey / servicePrincipalId /
/// tenantId) to the inline script body via environment variables.
pub const META_ADD_SPN_TO_ENV: &str = "add_spn_to_environment";

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
    /// SHA of the commit being analyzed; reproducibility hint when set.
    /// Parsers leave None; CI integrations populate this from the build env.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,
}

// ── The graph ───────────────────────────────────────────

/// Pipeline-level parameter declaration captured from a top-level
/// `parameters:` block. Used by rules that need to reason about whether
/// caller-supplied parameter values are constrained (`values:` allowlist)
/// or free-form (no allowlist on a string parameter — shell-injection risk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamSpec {
    /// Declared parameter type (`string`, `number`, `boolean`, `object`, etc.).
    /// Empty string when the YAML omitted `type:` (ADO defaults to string).
    pub param_type: String,
    /// True when the parameter declares a `values:` allowlist that constrains
    /// the set of acceptable inputs. When true, free-form shell injection is
    /// not possible because the runtime rejects any value outside the list.
    pub has_values_allowlist: bool,
}

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
    /// Top-level pipeline `parameters:` declarations, keyed by parameter name.
    /// Populated by parsers that surface parameter metadata (currently ADO).
    /// Empty for platforms / pipelines that don't declare parameters.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
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
            metadata: HashMap::new(),
            parameters: HashMap::new(),
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
