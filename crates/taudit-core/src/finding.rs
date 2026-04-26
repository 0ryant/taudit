use crate::graph::{AuthorityGraph, NodeId, NodeKind};
use crate::propagation::PropagationPath;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    fn rank(self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        }
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// MVP categories (1-5) are derivable from pipeline YAML alone.
/// Stretch categories (6-9) need heuristics or metadata enrichment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    // MVP
    AuthorityPropagation,
    OverPrivilegedIdentity,
    UnpinnedAction,
    UntrustedWithAuthority,
    ArtifactBoundaryCrossing,
    // Stretch — implemented
    FloatingImage,
    LongLivedCredential,
    /// Credential written to disk by a step (e.g. `persistCredentials: true` on a checkout).
    /// Disk-persisted credentials are accessible to all subsequent steps and any process
    /// with filesystem access, unlike runtime-only `HasAccessTo` authority.
    PersistedCredential,
    /// Dangerous trigger type (pull_request_target / pr) combined with secret/identity access.
    TriggerContextMismatch,
    /// Authority (secret/identity) flows into an opaque external workflow via DelegatesTo.
    CrossWorkflowAuthorityChain,
    /// Circular DelegatesTo chain — workflow calls itself transitively.
    AuthorityCycle,
    /// Privileged workflow (OIDC/broad identity) with no provenance attestation step.
    UpliftWithoutAttestation,
    /// Step writes to the environment gate ($GITHUB_ENV, pipeline variables) — authority can propagate.
    SelfMutatingPipeline,
    /// PR-triggered pipeline checks out the repository — attacker-controlled fork code lands on the runner.
    CheckoutSelfPrExposure,
    /// ADO variable group consumed by a PR-triggered job, crossing trust boundary.
    VariableGroupInPrJob,
    /// Self-hosted agent pool used in a PR-triggered job that also checks out the repository.
    SelfHostedPoolPrHijack,
    /// Broad-scope ADO service connection reachable from a PR-triggered job without OIDC.
    ServiceConnectionScopeMismatch,
    /// ADO `resources.repositories[]` entry referenced by an `extends:`,
    /// `template: x@alias`, or `checkout: alias` consumer resolves with no
    /// `ref:` (default branch) or a mutable branch ref (`refs/heads/<name>`).
    /// Whoever owns that branch can inject steps into the consuming pipeline.
    TemplateExtendsUnpinnedBranch,
    /// ADO `resources.repositories[]` entry pinned to a feature-class branch
    /// (anything outside the `main` / `master` / `release/*` / `hotfix/*`
    /// platform set). Feature branches typically have weaker push protection
    /// than the trunk, so any developer with write access to that branch can
    /// inject pipeline YAML that runs with the consumer's authority. Strictly
    /// stronger signal than `template_extends_unpinned_branch` — co-fires.
    TemplateRepoRefIsFeatureBranch,
    /// Pipeline step uses an Azure VM remote-exec primitive (Set-AzVMExtension /
    /// CustomScriptExtension, Invoke-AzVMRunCommand, az vm run-command, az vm extension set)
    /// where the executed command line interpolates a pipeline secret or a SAS token —
    /// pipeline-to-VM lateral movement primitive logged in plaintext to the VM and ARM.
    VmRemoteExecViaPipelineSecret,
    /// A SAS token freshly minted in-pipeline is interpolated into a CLI argument
    /// (commandToExecute / scriptArguments / --arguments / -ArgumentList) instead of
    /// passed via env var or stdin — argv ends up in /proc/*/cmdline, ETW, ARM status.
    ShortLivedSasInCommandLine,
    /// Pipeline secret value assigned to a shell variable inside an inline
    /// script (`export VAR=$(SECRET)`, `$X = "$(SECRET)"`). Once the value
    /// transits a shell variable, ADO's `$(SECRET)` log mask no longer
    /// applies — transcripts (`Start-Transcript`, `bash -x`, terraform debug
    /// logs) print the cleartext.
    SecretToInlineScriptEnvExport,
    /// Pipeline secret value written to a file under the agent workspace
    /// (`$(System.DefaultWorkingDirectory)`, `$(Build.SourcesDirectory)`,
    /// or relative paths) without `secureFile` task or chmod 600. The file
    /// persists in the agent workspace and is uploaded by
    /// `PublishPipelineArtifact` and crawlable by later steps.
    SecretMaterialisedToWorkspaceFile,
    /// PowerShell pulls a Key Vault secret with `-AsPlainText` (or
    /// `ConvertFrom-SecureString -AsPlainText`, or older
    /// `.SecretValueText` syntax) into a non-`SecureString` variable. The
    /// value never traverses the ADO variable-group boundary, so verbose
    /// Az/PS logging and error stack traces print the credential.
    ///
    /// Rule id is `keyvault_secret_to_plaintext` (single token "keyvault")
    /// rather than the snake_case derivation `key_vault_…` — matches the
    /// docs filename and the convention used in the corpus evidence.
    #[serde(rename = "keyvault_secret_to_plaintext")]
    KeyVaultSecretToPlaintext,
    /// `terraform apply -auto-approve` against a production-named service connection
    /// without an environment approval gate.
    TerraformAutoApproveInProd,
    /// `AzureCLI@2` task with `addSpnToEnvironment: true` AND an inline script —
    /// the script can launder federated SPN/OIDC tokens into pipeline variables.
    AddSpnWithInlineScript,
    /// A `type: string` pipeline parameter (no `values:` allowlist) is interpolated
    /// via `${{ parameters.X }}` into an inline shell/PowerShell script body —
    /// shell injection vector for anyone with "queue build".
    ParameterInterpolationIntoShell,
    /// A `run:` block fetches a remote script from a mutable URL (`refs/heads/`,
    /// `/main/`, `/master/`) and pipes it directly to a shell interpreter
    /// (`curl … | bash`, `wget … | sh`, `bash <(curl …)`, `deno run https://…`).
    /// Whoever controls that URL's content controls execution on the runner.
    RuntimeScriptFetchedFromFloatingUrl,
    /// Workflow trigger combines high-authority PR events
    /// (`pull_request_target`, `issue_comment`, or `workflow_run`) with a step
    /// whose `uses:` ref is a mutable branch/tag (not a 40-char SHA). Compromise
    /// of the action's default branch yields full repo write on the target repo.
    PrTriggerWithFloatingActionRef,
    /// A `workflow_run`-triggered workflow captures a value from an external
    /// API response (`gh pr view`, `gh api`, `curl api.github.com`) and writes
    /// it into `$GITHUB_ENV`/`$GITHUB_OUTPUT`/`$GITHUB_PATH` without sanitisation.
    /// A poisoned API field (branch name, title) injects environment variables
    /// into every subsequent step in the same job.
    UntrustedApiResponseToEnvSink,
    /// A `pull_request`-triggered workflow logs into a container registry via a
    /// floating (non-SHA-pinned) login action. The compromised action receives
    /// OIDC tokens or registry credentials, and the workflow then pushes a
    /// PR-controlled image to a shared registry.
    PrBuildPushesImageWithFloatingCredentials,
    /// Positive-invariant rule (GHA): the workflow declares neither a
    /// top-level nor a per-job `permissions:` block, leaving GITHUB_TOKEN at
    /// its broad platform default. Fires once per workflow file.
    NoWorkflowLevelPermissionsBlock,
    /// Positive-invariant rule (ADO): a job referencing a production-named
    /// service connection has no `environment:` binding, so it bypasses the
    /// only ADO-side approval gate regardless of whether `-auto-approve` is
    /// present. Strictly broader than `terraform_auto_approve_in_prod`.
    ProdDeployJobNoEnvironmentGate,
    /// Positive-invariant rule (cross-platform): a long-lived static
    /// credential is in scope but the workflow does not currently use any
    /// OIDC identity even though the target cloud supports federation.
    /// Advisory uplift on top of `long_lived_credential` that wires the
    /// existing `Recommendation::FederateIdentity` variant.
    LongLivedSecretWithoutOidcRecommendation,
    /// Positive-invariant rule (GHA): a PR-triggered workflow has multiple
    /// privileged jobs where SOME have the standard fork-check `if:` and
    /// OTHERS do not. Detects an intra-file inconsistency in defensive
    /// posture — the org has the right instinct but applied it unevenly.
    PullRequestWorkflowInconsistentForkCheck,
    /// Positive-invariant rule (GitLab): a job with a production-named
    /// `environment:` binding has no `rules:` / `only:` clause restricting
    /// it to protected branches. Deploy job runs (or attempts to run) on
    /// every pipeline trigger.
    GitlabDeployJobMissingProtectedBranchOnly,
    // Reserved — requires ADO/GH API enrichment beyond pipeline YAML
    /// Requires runtime network telemetry or policy enrichment — not detectable from YAML alone.
    #[doc(hidden)]
    EgressBlindspot,
    /// Requires external audit-sink configuration data — not detectable from YAML alone.
    #[doc(hidden)]
    MissingAuditTrail,
}

/// Routing: scope findings -> TsafeRemediation; isolation findings -> CellosRemediation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Recommendation {
    TsafeRemediation {
        command: String,
        explanation: String,
    },
    CellosRemediation {
        reason: String,
        spec_hint: String,
    },
    PinAction {
        current: String,
        pinned: String,
    },
    ReducePermissions {
        current: String,
        minimum: String,
    },
    FederateIdentity {
        static_secret: String,
        oidc_provider: String,
    },
    Manual {
        action: String,
    },
}

/// A finding is a concrete, actionable authority issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: FindingCategory,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PropagationPath>,
    pub nodes_involved: Vec<NodeId>,
    pub message: String,
    pub recommendation: Recommendation,
}

// ── Finding fingerprint ────────────────────────────────────
//
// Stable cross-run identifier for a finding. Surfaces in:
//
//   * SARIF `partialFingerprints[primaryLocationLineHash]`
//   * JSON  `findings[].fingerprint`
//   * CloudEvents extension attribute `tauditfindingfingerprint`
//
// SIEMs / suppression DBs / dedup pipelines key on this value to
// recognise "same finding seen on previous run". See
// `docs/finding-fingerprint.md` for the full contract.

/// Pull a custom-rule id out of a finding message of the form
/// `[<id>] rest of message`. Returns `None` if the message does not start
/// with a bracketed id. Mirrors the matching helper in
/// `taudit-report-sarif`; kept private so the surface stays minimal.
fn extract_custom_rule_id(message: &str) -> Option<&str> {
    if !message.starts_with('[') {
        return None;
    }
    let end = message.find(']')?;
    let id = &message[1..end];
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

/// Snake-case rule id derived from a `FindingCategory`. Delegates to
/// serde so the value tracks the serialized form across renames.
fn category_rule_id(category: &FindingCategory) -> String {
    serde_json::to_value(category)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Compute a stable cross-run fingerprint for a finding.
///
/// The fingerprint identifies "the same logical issue" across re-runs and
/// across non-cosmetic edits to the surrounding pipeline. Two runs against
/// the same input file produce the same fingerprint; a fix to the
/// underlying issue makes the fingerprint disappear; a tweak to the
/// finding's user-facing message does NOT change the fingerprint.
///
/// **Inputs (sensitive to):**
///   * Rule id — either a custom rule id parsed from a `[id] …` message
///     prefix, or the snake_case form of `finding.category`
///   * Source file path (`graph.source.file`)
///   * Finding category (snake_case)
///   * Identifying node names. Where the finding involves a `Secret` or
///     `Identity` node, the root authority name is used (collapses many
///     per-hop findings against one secret to a single fingerprint —
///     matches the existing SARIF dedup behaviour). Otherwise the names
///     of all involved nodes, sorted, are used.
///
/// **Inputs (insensitive to):**
///   * Wall-clock time
///   * The finding's `message` text — operators tweak phrasing without
///     wanting suppressions to break
///   * `taudit` version string
///   * Environment / host / cwd
///   * Pipeline file content hash — only the path matters
///
/// Stability guarantee: the format is stable within a major version
/// (1.x.y). A 2.0.0 release may change the algorithm; the JSON / SARIF
/// schemas surface the current major in their respective version fields.
///
/// Output: SHA-256 of the canonical input string, truncated to the first
/// 16 hex characters (64 bits — collision-resistant enough for finding
/// dedup, short enough to be human-glanceable in a SIEM table).
pub fn compute_fingerprint(finding: &Finding, graph: &AuthorityGraph) -> String {
    let rule_id = extract_custom_rule_id(&finding.message)
        .map(str::to_string)
        .unwrap_or_else(|| category_rule_id(&finding.category));

    let category = category_rule_id(&finding.category);
    let file = graph.source.file.as_str();

    // Prefer a single root authority (Secret / Identity) so per-hop
    // findings collapse to one fingerprint per underlying credential.
    let root_authority: Option<&str> = finding
        .nodes_involved
        .iter()
        .filter_map(|id| graph.node(*id))
        .find(|n| matches!(n.kind, NodeKind::Secret | NodeKind::Identity))
        .map(|n| n.name.as_str());

    let node_segment: String = match root_authority {
        Some(name) => name.to_string(),
        None => {
            let mut names: Vec<&str> = finding
                .nodes_involved
                .iter()
                .filter_map(|id| graph.node(*id))
                .map(|n| n.name.as_str())
                .collect();
            names.sort_unstable();
            names.dedup();
            names.join(",")
        }
    };

    // Canonical encoding: each component prefixed with a tag and joined
    // by `\x1f` (ASCII unit separator) so component boundaries cannot
    // alias across inputs (e.g. node name containing the literal
    // separator string used between fields).
    let canonical = format!(
        "v1\x1frule={rule_id}\x1ffile={file}\x1fcategory={category}\x1fnodes={node_segment}"
    );

    let digest = Sha256::digest(canonical.as_bytes());
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        use std::fmt::Write;
        // 8 bytes -> 16 hex chars
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;
    use crate::graph::{AuthorityGraph, NodeKind, PipelineSource, TrustZone};

    fn source(file: &str) -> PipelineSource {
        PipelineSource {
            file: file.to_string(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        }
    }

    fn make_finding(category: FindingCategory, msg: &str, nodes: Vec<NodeId>) -> Finding {
        Finding {
            severity: Severity::High,
            category,
            path: None,
            nodes_involved: nodes,
            message: msg.to_string(),
            recommendation: Recommendation::Manual {
                action: "fix it".to_string(),
            },
        }
    }

    #[test]
    fn fingerprint_is_stable_across_repeat_calls() {
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let s = graph.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
        let f = make_finding(
            FindingCategory::AuthorityPropagation,
            "AWS_KEY reaches third party",
            vec![s],
        );
        let a = compute_fingerprint(&f, &graph);
        let b = compute_fingerprint(&f, &graph);
        assert_eq!(a, b, "same finding must hash identically across calls");
        assert_eq!(a.len(), 16, "fingerprint is 16 hex chars");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_files_produce_different_fingerprints() {
        let mut g_a = AuthorityGraph::new(source("workflows/a.yml"));
        let mut g_b = AuthorityGraph::new(source("workflows/b.yml"));
        let s_a = g_a.add_node(NodeKind::Secret, "TOKEN", TrustZone::FirstParty);
        let s_b = g_b.add_node(NodeKind::Secret, "TOKEN", TrustZone::FirstParty);
        let f_a = make_finding(FindingCategory::UnpinnedAction, "msg", vec![s_a]);
        let f_b = make_finding(FindingCategory::UnpinnedAction, "msg", vec![s_b]);
        assert_ne!(
            compute_fingerprint(&f_a, &g_a),
            compute_fingerprint(&f_b, &g_b)
        );
    }

    #[test]
    fn different_rules_produce_different_fingerprints() {
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let s = graph.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
        let f1 = make_finding(FindingCategory::AuthorityPropagation, "msg", vec![s]);
        let f2 = make_finding(FindingCategory::UntrustedWithAuthority, "msg", vec![s]);
        assert_ne!(
            compute_fingerprint(&f1, &graph),
            compute_fingerprint(&f2, &graph)
        );
    }

    #[test]
    fn message_changes_do_not_affect_fingerprint() {
        // The whole point of cross-run dedup: an operator can re-word
        // the message text without breaking SIEM suppressions.
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let s = graph.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
        let f1 = make_finding(
            FindingCategory::AuthorityPropagation,
            "old phrasing of the message",
            vec![s],
        );
        let f2 = make_finding(
            FindingCategory::AuthorityPropagation,
            "completely different new phrasing",
            vec![s],
        );
        assert_eq!(
            compute_fingerprint(&f1, &graph),
            compute_fingerprint(&f2, &graph)
        );
    }

    #[test]
    fn per_hop_findings_against_same_authority_collapse() {
        // A single secret reaching N untrusted steps must yield the
        // SAME fingerprint each time so SIEM rolls up to one ticket.
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let secret = graph.add_node(NodeKind::Secret, "DEPLOY_TOKEN", TrustZone::FirstParty);
        let step_a = graph.add_node(NodeKind::Step, "deploy[0]", TrustZone::Untrusted);
        let step_b = graph.add_node(NodeKind::Step, "deploy[1]", TrustZone::Untrusted);

        let f_a = make_finding(
            FindingCategory::AuthorityPropagation,
            "DEPLOY_TOKEN reaches deploy[0]",
            vec![secret, step_a],
        );
        let f_b = make_finding(
            FindingCategory::AuthorityPropagation,
            "DEPLOY_TOKEN reaches deploy[1]",
            vec![secret, step_b],
        );
        assert_eq!(
            compute_fingerprint(&f_a, &graph),
            compute_fingerprint(&f_b, &graph),
            "per-hop findings against one secret must share a fingerprint"
        );
    }

    #[test]
    fn custom_rule_id_in_message_is_used() {
        // Custom rules carry id in `[id] message` prefix; fingerprint
        // must key on the custom id, not the category fallback.
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let s = graph.add_node(NodeKind::Secret, "X", TrustZone::FirstParty);
        let f_custom = make_finding(
            FindingCategory::UnpinnedAction,
            "[my_custom_rule] something happened",
            vec![s],
        );
        let f_plain = make_finding(FindingCategory::UnpinnedAction, "no prefix here", vec![s]);
        assert_ne!(
            compute_fingerprint(&f_custom, &graph),
            compute_fingerprint(&f_plain, &graph),
            "custom rule id must distinguish from category fallback"
        );
    }

    #[test]
    fn empty_node_list_still_produces_fingerprint() {
        // Categories like authority_cycle, floating_image, unpinned_action
        // may not carry an authority node — fingerprint must still work.
        let graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let f = make_finding(FindingCategory::UnpinnedAction, "no nodes here", vec![]);
        let fp = compute_fingerprint(&f, &graph);
        assert_eq!(fp.len(), 16);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
