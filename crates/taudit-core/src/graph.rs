use serde::{Deserialize, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};

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
/// Marks a Step that reads from the runner-managed environment via an
/// `env.<NAME>` template reference — `${{ env.X }}` in a `with:` value,
/// inline script body, or step `env:` mapping. Distinct from `secrets.X`
/// references (which produce a HasAccessTo edge to a Secret node) — `env.X`
/// references can be sourced from the ambient runner environment, including
/// values laundered through `$GITHUB_ENV` by an earlier step. Stamped by
/// the GHA parser so `secret_via_env_gate_to_untrusted_consumer` can find
/// the gate-laundering chain that the explicit-secret rules miss.
pub const META_READS_ENV: &str = "reads_env";
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
/// Graph-level metadata: identifies the source platform of the parsed
/// pipeline. Set by every parser to its `platform()` value
/// (`"github-actions"`, `"azure-devops"`, `"gitlab"`). Allows platform-scoped
/// rules to gate their detection without parsing the source file path.
pub const META_PLATFORM: &str = "platform";
/// Graph-level metadata: marks a GitHub Actions workflow as having NO
/// top-level `permissions:` block declared. Set by the GHA parser when
/// `workflow.permissions` is absent so rules can detect the negative-space
/// "no permissions block at all" pattern (which leaves `GITHUB_TOKEN` at its
/// broad platform default — `contents: write`, `packages: write`, etc.).
pub const META_NO_WORKFLOW_PERMISSIONS: &str = "no_workflow_permissions";
/// Marks a Step in a GHA workflow as carrying an `if:` condition that
/// references the standard fork-check pattern
/// (`github.event.pull_request.head.repo.fork == false` or the equivalent
/// `head.repo.full_name == github.repository`). Stamped by the GHA parser so
/// rules can credit the step with the compensating control without
/// re-parsing the YAML expression. Bool stored as `"true"`.
pub const META_FORK_CHECK: &str = "fork_check";
/// Marks a GitLab CI job (Step node) whose `rules:` or `only:` clause
/// restricts execution to protected branches — either via an explicit
/// `if: $CI_COMMIT_REF_PROTECTED == "true"` rule, an `if: $CI_COMMIT_BRANCH
/// == $CI_DEFAULT_BRANCH` rule, or an `only: [main, ...]` allowlist of
/// platform-protected refs. Set by the GitLab parser. Absence on a
/// deployment job is a control gap.
pub const META_RULES_PROTECTED_ONLY: &str = "rules_protected_only";
/// Graph-level metadata: comma-joined list of every entry under `on:` (e.g.
/// `pull_request_target,issue_comment,workflow_run`). Distinct from
/// `META_TRIGGER` (singular) which is set only for `pull_request_target` /
/// ADO `pr` to preserve the existing `trigger_context_mismatch` contract.
/// Consumers of this list (e.g. `risky_trigger_with_authority`) must split on
/// `,` and treat each token as a trigger name.
pub const META_TRIGGERS: &str = "triggers";
/// Graph-level metadata: comma-joined list of `workflow_dispatch.inputs.*`
/// names declared by the workflow. Empty / absent if the workflow has no
/// `workflow_dispatch` trigger. Consumed by
/// `manual_dispatch_input_to_url_or_command` to taint-track input flow into
/// command lines, URLs, and `actions/checkout` refs.
pub const META_DISPATCH_INPUTS: &str = "dispatch_inputs";
/// Graph-level metadata: pipe-delimited list of `<job>\t<name>\t<source>`
/// records, one per `jobs.<id>.outputs.<name>`. Records are joined with `|`,
/// fields within a record with `\t`. `source` is one of `secret` (value
/// reads `secrets.*`), `oidc` (value references `steps.*.outputs.*` from a
/// step that holds an OIDC identity), `step_output` (any other
/// `steps.*.outputs.*`), or `literal`. Plain-text rather than JSON to keep
/// the parser crate free of `serde_json`. Consumed by
/// `sensitive_value_in_job_output`.
pub const META_JOB_OUTPUTS: &str = "job_outputs";
/// Step-level metadata: the value passed to `actions/checkout`'s `with.ref`
/// input (verbatim, including any `${{ … }}` expressions). Stamped only on
/// `actions/checkout` steps that supply a `ref:`. Consumed by
/// `manual_dispatch_input_to_url_or_command`.
pub const META_CHECKOUT_REF: &str = "checkout_ref";
/// Marks the synthetic Step node created for a job that delegates to a
/// reusable workflow with `secrets: inherit`. The whole secret bag forwards
/// to the callee regardless of what the callee actually consumes — when the
/// caller is fired by an attacker-controllable trigger this is a wide-open
/// exfiltration path. Set on the synthetic step node by the GHA parser.
pub const META_SECRETS_INHERIT: &str = "secrets_inherit";
/// Marks a Step that downloads a workflow artifact (typically
/// `actions/download-artifact` or `dawidd6/action-download-artifact`).
/// In `workflow_run`-triggered consumers, the originating run's artifacts
/// were produced from PR context — the consumer must treat their content as
/// untrusted input even when the consumer itself runs with elevated perms.
pub const META_DOWNLOADS_ARTIFACT: &str = "downloads_artifact";
/// Marks a Step whose body interprets artifact (or other untrusted file)
/// content into a privileged sink — `unzip`/`tar -x`, `cat`/`jq` piping
/// into `>> $GITHUB_ENV`/`>> $GITHUB_OUTPUT`, `eval`, posting to a PR
/// comment via `actions/github-script` `body:`/`issue_body:`, or evaluating
/// extracted text. Combined with `META_DOWNLOADS_ARTIFACT` upstream in the
/// same job and a `workflow_run`/`pull_request_target` trigger this is the
/// classic mypy_primer / coverage-comment artifact-RCE pattern.
pub const META_INTERPRETS_ARTIFACT: &str = "interprets_artifact";
/// Marks a Step that uses an interactive debug action (mxschmitt/action-tmate,
/// lhotari/action-upterm, actions/tmate, etc.). The cell value is the action
/// reference (e.g. `mxschmitt/action-tmate@v3`). A successful debug session
/// gives the operator an external SSH endpoint with the runner's full
/// environment loaded — every secret in scope, the checked-out HEAD, and
/// write access to whatever the GITHUB_TOKEN holds.
pub const META_INTERACTIVE_DEBUG: &str = "interactive_debug";
/// Marks a Step that calls `actions/cache` (or `actions/cache/save` /
/// `actions/cache/restore`). The cell value is the raw `key:` input from
/// the step's `with:` block. Consumed by `pr_specific_cache_key_in_default_branch_consumer`
/// to detect PR-derived cache keys (head_ref, head.ref, actor) that a
/// default-branch run can later restore — classic cache poisoning.
pub const META_CACHE_KEY: &str = "cache_key";
/// Records the OIDC audience (`aud:`) value of an `id_tokens:` entry on an
/// Identity node. GitLab CI emits one Identity per `id_tokens:` key; the
/// audience is what trades for downstream cloud creds (Vault path, AWS role,
/// etc), so audience reuse across MR-context and protected-context jobs is
/// the precise privilege-overscope signal. Set by the GitLab parser.
pub const META_OIDC_AUDIENCE: &str = "oidc_audience";
/// Records a Step's `environment:url:` value verbatim. Stamped by the GitLab
/// parser when the job declares an `environment:` mapping with a `url:`
/// field. Consumed by `untrusted_ci_var_in_shell_interpolation` because
/// `environment:url:` is rendered by the GitLab UI and any predefined-CI-var
/// interpolated into it is a stored-XSS / open-redirect sink.
pub const META_ENVIRONMENT_URL: &str = "environment_url";
/// Graph-level metadata: JSON-encoded array of `include:` entries declared by
/// a GitLab CI pipeline. Each entry is an object with fields:
/// - `kind`: one of `local`, `remote`, `template`, `project`, `component`
/// - `target`: the path/URL/project string
/// - `git_ref`: the resolved `ref:` value (only meaningful for `project` and
///   `remote`) — empty string when the include omits a `ref:`
///
/// Set by the GitLab parser; consumed by `unpinned_include_remote_or_branch_ref`.
pub const META_GITLAB_INCLUDES: &str = "gitlab_includes";
/// Marks a Step (GitLab job) that declares one or more `services:` entries
/// matching `docker:*-dind` or `docker:dind`. Combined with secret-bearing
/// HasAccessTo edges it indicates a runtime sandbox-escape primitive — any
/// inline build step can `docker run -v /:/host` from inside dind.
pub const META_GITLAB_DIND_SERVICE: &str = "gitlab_dind_service";
/// Marks a Step (GitLab job) declared with `allow_failure: true`. Used by
/// `security_job_silently_skipped` to detect scanner jobs that pass silently.
pub const META_GITLAB_ALLOW_FAILURE: &str = "gitlab_allow_failure";
/// Records the comma-joined list of `extends:` template names a GitLab job
/// inherits from. Used by scanner-name pattern matching in
/// `security_job_silently_skipped` because GitLab security templates are
/// usually consumed via `extends:` rather than by job-name match.
pub const META_GITLAB_EXTENDS: &str = "gitlab_extends";
/// Marks a Step (GitLab job) that defines a `trigger:` block (downstream /
/// child pipeline). Value is `"static"` for a fixed downstream `project:` or
/// `include:` of in-tree YAML, and `"dynamic"` when the include source is an
/// `artifact:` (dynamic child pipelines — code-injection sink).
pub const META_GITLAB_TRIGGER_KIND: &str = "gitlab_trigger_kind";
/// Records the literal `cache.key:` value declared on a GitLab job (or the
/// empty string if no cache is declared). Consumed by
/// `cache_key_crosses_trust_boundary` to detect cross-trust cache keys.
pub const META_GITLAB_CACHE_KEY: &str = "gitlab_cache_key";
/// Records the `cache.policy:` value declared on a GitLab job
/// (`pull` / `push` / `pull-push` / `pull_push`). When absent, the GitLab
/// runtime default is `pull-push`. Consumed by
/// `cache_key_crosses_trust_boundary`.
pub const META_GITLAB_CACHE_POLICY: &str = "gitlab_cache_policy";
/// Records the deployment environment name on a Step
/// (e.g. GitLab `environment.name:` / GHA `environment:`).
/// Used by rules that gate on production-like environment names.
pub const META_ENVIRONMENT_NAME: &str = "environment_name";
/// Records the GitLab `artifacts.reports.dotenv:` file path for a Step.
/// When set, the file's `KEY=value` lines are silently exported as
/// pipeline variables for every downstream job that consumes this job
/// via `needs:` or `dependencies:`. Consumed by
/// `dotenv_artifact_flows_to_privileged_deployment`.
pub const META_DOTENV_FILE: &str = "dotenv_file";
/// Records, on a Step, the upstream job names this step consumes via
/// GitLab `needs:` or `dependencies:`. Comma-separated job names.
/// Used to build dotenv-flow dependency chains across stages.
pub const META_NEEDS: &str = "needs";
/// Marks an Image node (self-hosted agent pool) as having workspace isolation
/// configured (`workspace: { clean: all }` or `workspace: { clean: true }` in
/// ADO). When present, the agent workspace is wiped between runs, mitigating
/// workspace poisoning attacks where a PR build leaves malicious files for the
/// next privileged pipeline run. Absence of this key on a self-hosted Image
/// node is the signal for `shared_self_hosted_pool_no_isolation`.
pub const META_WORKSPACE_CLEAN: &str = "workspace_clean";

// ── Shared helpers ─────────────────────────────────────

/// Serialize a `HashMap<String, V>` with keys in sorted order. The
/// in-memory representation stays a `HashMap` (cheaper insertion, hot
/// path on every parser); only the serialized form is canonicalised.
/// This is the single point of determinism control for graph metadata
/// emitted via JSON / SARIF / CloudEvents — without it, HashMap iteration
/// order leaks per-process randomness into every diff and cache key.
fn serialize_string_map_sorted<S, V>(
    map: &HashMap<String, V>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    V: Serialize,
{
    let sorted: BTreeMap<&String, &V> = map.iter().collect();
    sorted.serialize(serializer)
}

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
    /// Serialized in sorted-key order so JSON / SARIF / CloudEvents output
    /// is byte-deterministic across runs (HashMap iteration is randomised
    /// per process, which would otherwise break diffs and cache keys).
    #[serde(serialize_with = "serialize_string_map_sorted")]
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
