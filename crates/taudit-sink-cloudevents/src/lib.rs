use serde::Serialize;
use taudit_core::error::TauditError;
use taudit_core::finding::{
    compute_finding_group_id, compute_fingerprint, rule_id_for, Finding, FindingCategory,
};
use taudit_core::graph::AuthorityGraph;
use taudit_core::ports::ReportSink;

// ---------------------------------------------------------------------------
// CloudEvents 1.0 envelope — hand-rolled, matches CellOS pattern.
// No dependency on cloudevents-sdk (0.9.x, pre-1.0, unstable API).
// ---------------------------------------------------------------------------

/// Minimal CloudEvents 1.0 JSON envelope.
#[derive(Debug, Clone, Serialize)]
pub struct CloudEventV1 {
    pub specversion: String,
    pub id: String,
    pub source: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datacontenttype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    // Extension attributes — CloudEvents 1.0 allows arbitrary top-level keys.
    /// Authority graph completeness: "complete", "partial", or "unknown".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tauditcompleteness: Option<String>,
    /// Structured per-gap detail for `Partial` graphs. Each entry pairs the
    /// typed `GapKind` (`expression` | `structural` | `opaque`, serde
    /// snake_case) with the original human-readable reason string. Lets SIEMs
    /// route or suppress events by gap *category* without parsing prose.
    /// Omitted entirely for `Complete` / `Unknown` graphs (no null, no empty
    /// array). Per CloudEvents 1.0, extension attribute names must be
    /// lowercase with no separators — hence `tauditcompletenessgaps`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tauditcompletenessgaps: Option<Vec<serde_json::Value>>,
    /// Stable cross-run finding fingerprint. 16 lowercase hex chars,
    /// byte-identical to SARIF `partialFingerprints[primaryLocationLineHash]`
    /// and JSON `findings[].fingerprint`. SIEMs key on this attribute to
    /// dedup findings across re-runs. Per CloudEvents 1.0, extension
    /// attribute names must be lowercase with no separators — hence
    /// `tauditfindingfingerprint` rather than the dashed/snaked form.
    pub tauditfindingfingerprint: String,
    /// Canonical snake_case rule id, byte-identical to JSON
    /// `findings[].rule_id` and SARIF `result.ruleId`. The CloudEvents
    /// `type` field stays scoped to the `FindingCategory` (so SIEM routing
    /// rules remain stable across rule additions); this extension exposes
    /// the precise rule that fired so consumers can filter / suppress at
    /// rule granularity. For custom YAML rules with a `[id] …` message
    /// prefix the bracketed id wins, matching `taudit_core::finding::
    /// rule_id_for`. Per CloudEvents 1.0 §3.1, extension attribute names
    /// must be lowercase with no separators — hence `tauditruleid`.
    pub tauditruleid: String,
    /// CI/CD platform of the underlying pipeline: `"ado"`, `"gha"`, or
    /// `"gitlab"`. Lets SIEM correlation rules route events by platform
    /// without re-parsing the `subject` (file path). Source: the resolved
    /// `Platform` variant for the scanned file, surfaced via
    /// `graph.metadata["platform"]`. Optional in v1 for backward-compat;
    /// always emitted by current taudit when the parser stamped the
    /// metadata key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tauditplatform: Option<String>,
    /// Stable UUID v5 over the fingerprint. Same value as JSON
    /// `findings[].finding_group_id` and SARIF `properties.findingGroupId`.
    /// SIEMs `SELECT DISTINCT ON (tauditfindinggroup)` to collapse
    /// per-hop findings against the same authority root into one event.
    /// CloudEvents 1.0 attribute names must be lowercase with no
    /// separators — hence `tauditfindinggroup` (no underscore).
    pub tauditfindinggroup: String,
    /// Shared correlation key for a single operator flow.
    pub correlationid: String,
    /// Repository that emitted the event.
    pub provenancerepo: String,
    /// Binary, command, or subsystem that produced the event.
    pub provenanceproducer: String,
    /// Producer version or schema version.
    pub provenanceversion: String,
    /// High-level evidence kind.
    pub provenancekind: String,
}

/// Event source identifier for taudit.
const EVENT_SOURCE: &str = "taudit";
const PROVENANCE_REPO: &str = "taudit";
const PROVENANCE_PRODUCER: &str = "taudit-sink-cloudevents";
const PROVENANCE_KIND: &str = "finding";

/// Map a FindingCategory to a CloudEvents type string.
fn event_type(category: FindingCategory) -> String {
    let suffix = match category {
        FindingCategory::AuthorityPropagation => "authority_propagation",
        FindingCategory::OverPrivilegedIdentity => "over_privileged_identity",
        FindingCategory::UnpinnedAction => "unpinned_action",
        FindingCategory::UntrustedWithAuthority => "untrusted_with_authority",
        FindingCategory::ArtifactBoundaryCrossing => "artifact_boundary_crossing",
        FindingCategory::FloatingImage => "floating_image",
        FindingCategory::LongLivedCredential => "long_lived_credential",
        FindingCategory::PersistedCredential => "persisted_credential",
        FindingCategory::TriggerContextMismatch => "trigger_context_mismatch",
        FindingCategory::CrossWorkflowAuthorityChain => "cross_workflow_authority_chain",
        FindingCategory::AuthorityCycle => "authority_cycle",
        FindingCategory::UpliftWithoutAttestation => "uplift_without_attestation",
        FindingCategory::SelfMutatingPipeline => "self_mutating_pipeline",
        FindingCategory::CheckoutSelfPrExposure => "checkout_self_pr_exposure",
        FindingCategory::VariableGroupInPrJob => "variable_group_in_pr_job",
        FindingCategory::SelfHostedPoolPrHijack => "self_hosted_pool_pr_hijack",
        FindingCategory::ServiceConnectionScopeMismatch => "service_connection_scope_mismatch",
        FindingCategory::TemplateExtendsUnpinnedBranch => "template_extends_unpinned_branch",
        FindingCategory::TemplateRepoRefIsFeatureBranch => "template_repo_ref_is_feature_branch",
        FindingCategory::VmRemoteExecViaPipelineSecret => "vm_remote_exec_via_pipeline_secret",
        FindingCategory::ShortLivedSasInCommandLine => "short_lived_sas_in_command_line",
        FindingCategory::SecretToInlineScriptEnvExport => "secret_to_inline_script_env_export",
        FindingCategory::SecretMaterialisedToWorkspaceFile => {
            "secret_materialised_to_workspace_file"
        }
        FindingCategory::KeyVaultSecretToPlaintext => "keyvault_secret_to_plaintext",
        FindingCategory::TerraformAutoApproveInProd => "terraform_auto_approve_in_prod",
        FindingCategory::AddSpnWithInlineScript => "add_spn_with_inline_script",
        FindingCategory::ParameterInterpolationIntoShell => "parameter_interpolation_into_shell",
        FindingCategory::RuntimeScriptFetchedFromFloatingUrl => {
            "runtime_script_fetched_from_floating_url"
        }
        FindingCategory::PrTriggerWithFloatingActionRef => "pr_trigger_with_floating_action_ref",
        FindingCategory::UntrustedApiResponseToEnvSink => "untrusted_api_response_to_env_sink",
        FindingCategory::PrBuildPushesImageWithFloatingCredentials => {
            "pr_build_pushes_image_with_floating_credentials"
        }
        FindingCategory::SecretViaEnvGateToUntrustedConsumer => {
            "secret_via_env_gate_to_untrusted_consumer"
        }
        FindingCategory::NoWorkflowLevelPermissionsBlock => "no_workflow_level_permissions_block",
        FindingCategory::ProdDeployJobNoEnvironmentGate => "prod_deploy_job_no_environment_gate",
        FindingCategory::LongLivedSecretWithoutOidcRecommendation => {
            "long_lived_secret_without_oidc_recommendation"
        }
        FindingCategory::PullRequestWorkflowInconsistentForkCheck => {
            "pull_request_workflow_inconsistent_fork_check"
        }
        FindingCategory::GitlabDeployJobMissingProtectedBranchOnly => {
            "gitlab_deploy_job_missing_protected_branch_only"
        }
        FindingCategory::TerraformOutputViaSetvariableShellExpansion => {
            "terraform_output_via_setvariable_shell_expansion"
        }
        FindingCategory::RiskyTriggerWithAuthority => "risky_trigger_with_authority",
        FindingCategory::SensitiveValueInJobOutput => "sensitive_value_in_job_output",
        FindingCategory::ManualDispatchInputToUrlOrCommand => {
            "manual_dispatch_input_to_url_or_command"
        }
        FindingCategory::SecretsInheritOverscopedPassthrough => {
            "secrets_inherit_overscoped_passthrough"
        }
        FindingCategory::UnsafePrArtifactInWorkflowRunConsumer => {
            "unsafe_pr_artifact_in_workflow_run_consumer"
        }
        FindingCategory::ScriptInjectionViaUntrustedContext => {
            "script_injection_via_untrusted_context"
        }
        FindingCategory::InteractiveDebugActionInAuthorityWorkflow => {
            "interactive_debug_action_in_authority_workflow"
        }
        FindingCategory::PrSpecificCacheKeyInDefaultBranchConsumer => {
            "pr_specific_cache_key_in_default_branch_consumer"
        }
        FindingCategory::GhCliWithDefaultTokenEscalating => "gh_cli_with_default_token_escalating",
        FindingCategory::CiJobTokenToExternalApi => "ci_job_token_to_external_api",
        FindingCategory::IdTokenAudienceOverscoped => "id_token_audience_overscoped",
        FindingCategory::UntrustedCiVarInShellInterpolation => {
            "untrusted_ci_var_in_shell_interpolation"
        }
        FindingCategory::UnpinnedIncludeRemoteOrBranchRef => {
            "unpinned_include_remote_or_branch_ref"
        }
        FindingCategory::DindServiceGrantsHostAuthority => "dind_service_grants_host_authority",
        FindingCategory::SecurityJobSilentlySkipped => "security_job_silently_skipped",
        FindingCategory::ChildPipelineTriggerInheritsAuthority => {
            "child_pipeline_trigger_inherits_authority"
        }
        FindingCategory::CacheKeyCrossesTrustBoundary => "cache_key_crosses_trust_boundary",
        FindingCategory::PatEmbeddedInGitRemoteUrl => "pat_embedded_in_git_remote_url",
        FindingCategory::CiTokenTriggersDownstreamWithVariablePassthrough => {
            "ci_token_triggers_downstream_with_variable_passthrough"
        }
        FindingCategory::DotenvArtifactFlowsToPrivilegedDeployment => {
            "dotenv_artifact_flows_to_privileged_deployment"
        }
        FindingCategory::SharedSelfHostedPoolNoIsolation => "shared_self_hosted_pool_no_isolation",
        FindingCategory::SetvariableIssecretFalse => "setvariable_issecret_false",
        FindingCategory::HomoglyphInActionRef => "homoglyph_in_action_ref",
        FindingCategory::GhaHelperPathSensitiveArgv => "gha_helper_path_sensitive_argv",
        FindingCategory::GhaHelperPathSensitiveStdin => "gha_helper_path_sensitive_stdin",
        FindingCategory::GhaHelperPathSensitiveEnv => "gha_helper_path_sensitive_env",
        FindingCategory::GhaPostAmbientEnvCleanupPath => "gha_post_ambient_env_cleanup_path",
        FindingCategory::GhaActionMintedSecretToHelper => "gha_action_minted_secret_to_helper",
        FindingCategory::GhaHelperUntrustedPathResolution => "gha_helper_untrusted_path_resolution",
        FindingCategory::GhaSecretOutputAfterHelperLogin => "gha_secret_output_after_helper_login",
        FindingCategory::LaterSecretMaterializedAfterPathMutation => {
            "later_secret_materialized_after_path_mutation"
        }
        FindingCategory::GhaSetupNodeCacheHelperPathHandoff => {
            "gha_setup_node_cache_helper_path_handoff"
        }
        FindingCategory::GhaSetupPythonCacheHelperPathHandoff => {
            "gha_setup_python_cache_helper_path_handoff"
        }
        FindingCategory::GhaSetupPythonPipInstallAuthorityEnv => {
            "gha_setup_python_pip_install_authority_env"
        }
        FindingCategory::GhaDockerSetupQemuPrivilegedDockerHelper => {
            "gha_docker_setup_qemu_privileged_docker_helper"
        }
        FindingCategory::GhaToolInstallerThenShellHelperAuthority => {
            "gha_tool_installer_then_shell_helper_authority"
        }
        FindingCategory::GhaWorkflowShellAuthorityConcentration => {
            "gha_workflow_shell_authority_concentration"
        }
        FindingCategory::GhaToolcacheAbsolutePathDowngrade => {
            "gha_toolcache_absolute_path_downgrade"
        }
        #[allow(deprecated)]
        FindingCategory::EgressBlindspot => "egress_blindspot",
        #[allow(deprecated)]
        FindingCategory::MissingAuditTrail => "missing_audit_trail",
    };
    format!("io.taudit.finding.{suffix}")
}

/// Build a CloudEvents 1.0 envelope for a single finding.
fn finding_to_event(
    finding: &Finding,
    graph: &AuthorityGraph,
    correlation_id: &str,
) -> CloudEventV1 {
    let data = serde_json::to_value(finding)
        .unwrap_or_else(|_| serde_json::Value::String(finding.message.clone()));

    let completeness_str = match graph.completeness {
        taudit_core::graph::AuthorityCompleteness::Complete => "complete",
        taudit_core::graph::AuthorityCompleteness::Partial => "partial",
        taudit_core::graph::AuthorityCompleteness::Unknown => "unknown",
    };

    // Surface the resolved CI/CD platform as an extension attribute when the
    // parser stamped `metadata["platform"]`. Permitted values: "ado", "gha",
    // "gitlab". Anything else is dropped — better to omit than to ship a
    // value SIEM rules can't pattern-match on.
    let tauditplatform = graph
        .metadata
        .get("platform")
        .and_then(|v| match v.as_str() {
            "ado" | "gha" | "gitlab" => Some(v.clone()),
            _ => None,
        });

    // Pair each typed `GapKind` with its prose reason. `completeness_gap_kinds`
    // and `completeness_gaps` are append-only parallel vectors maintained by
    // `AuthorityGraph::mark_partial`, so `.zip` yields one entry per gap with
    // the original ordering preserved. Emit as `Some(vec)` only when the graph
    // actually has gaps — `skip_serializing_if` then drops the attribute on
    // Complete / Unknown graphs (no null, no empty `[]`).
    let tauditcompletenessgaps = if graph.completeness_gap_kinds.is_empty() {
        None
    } else {
        Some(
            graph
                .completeness_gap_kinds
                .iter()
                .zip(graph.completeness_gaps.iter())
                .map(|(kind, reason)| serde_json::json!({"kind": kind, "reason": reason}))
                .collect::<Vec<_>>(),
        )
    };

    CloudEventV1 {
        specversion: "1.0".into(),
        id: uuid::Uuid::new_v4().to_string(),
        source: EVENT_SOURCE.into(),
        ty: event_type(finding.category),
        subject: Some(graph.source.file.clone()),
        datacontenttype: Some("application/json".into()),
        time: Some(chrono::Utc::now().to_rfc3339()),
        data: Some(data),
        tauditcompleteness: Some(completeness_str.into()),
        tauditcompletenessgaps,
        tauditfindingfingerprint: compute_fingerprint(finding, graph),
        tauditruleid: rule_id_for(finding),
        tauditplatform,
        tauditfindinggroup: finding
            .extras
            .finding_group_id
            .clone()
            .unwrap_or_else(|| compute_finding_group_id(&compute_fingerprint(finding, graph))),
        correlationid: correlation_id.to_string(),
        provenancerepo: PROVENANCE_REPO.into(),
        provenanceproducer: PROVENANCE_PRODUCER.into(),
        provenanceversion: env!("CARGO_PKG_VERSION").into(),
        provenancekind: PROVENANCE_KIND.into(),
    }
}

// ---------------------------------------------------------------------------
// ReportSink implementation — one JSONL line per finding.
// ---------------------------------------------------------------------------

/// Environment variable used as the inbound channel for a caller-supplied
/// correlation id. Set by CellOS supervisor or CI runners to thread the
/// caller's `correlationId` through to every emitted CloudEvent in this
/// scan, so the taudit findings can be joined to the upstream run that
/// triggered them. Falls back to a freshly minted `Uuid::new_v4()` when
/// unset.
///
/// Precedence (highest → lowest):
///   1. `CloudEventsJsonlSink { correlation_id: Some(_) }` — explicit
///      constructor argument wins (programmatic embedders).
///   2. `TAUDIT_CORRELATION_ID` env var — for CLI / CI use.
///   3. `Uuid::new_v4()` — preserves prior behaviour for unconfigured callers.
pub const CORRELATION_ID_ENV: &str = "TAUDIT_CORRELATION_ID";

/// JSONL CloudEvents sink — one event per finding.
///
/// Construct with `CloudEventsJsonlSink::default()` (or `::new()`) for the
/// historical "mint a fresh UUID per emit" behaviour, or with
/// `CloudEventsJsonlSink::with_correlation_id(Some("…"))` to thread a
/// caller-supplied correlation id through every event in the emission.
#[derive(Debug, Default, Clone)]
pub struct CloudEventsJsonlSink {
    /// Caller-supplied correlation id. When `Some`, takes precedence over
    /// the `TAUDIT_CORRELATION_ID` env var and the minted UUID fallback.
    correlation_id: Option<String>,
}

impl CloudEventsJsonlSink {
    /// Construct a sink with the default (unconfigured) correlation source —
    /// equivalent to `CloudEventsJsonlSink::default()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a sink with an explicit caller-supplied correlation id.
    /// `Some(id)` overrides both the `TAUDIT_CORRELATION_ID` env var and
    /// the UUID fallback; `None` defers to env var, then UUID.
    pub fn with_correlation_id(correlation_id: Option<String>) -> Self {
        Self { correlation_id }
    }

    /// Resolve the correlation id for one `emit` call using the documented
    /// precedence: explicit ctor arg → `TAUDIT_CORRELATION_ID` env var →
    /// minted `Uuid::new_v4()`.
    fn resolve_correlation_id(&self) -> String {
        self.correlation_id
            .clone()
            .or_else(|| std::env::var(CORRELATION_ID_ENV).ok())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
    }
}

impl<W: std::io::Write> ReportSink<W> for CloudEventsJsonlSink {
    fn emit(
        &self,
        w: &mut W,
        graph: &AuthorityGraph,
        findings: &[Finding],
    ) -> Result<(), TauditError> {
        let correlation_id = self.resolve_correlation_id();

        for finding in findings {
            let event = finding_to_event(finding, graph, &correlation_id);
            serde_json::to_writer(&mut *w, &event)
                .map_err(|e| TauditError::Report(format!("CloudEvents serialization: {e}")))?;
            writeln!(w).map_err(|e| TauditError::Report(e.to_string()))?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};
    use taudit_core::finding::{FindingExtras, Recommendation, Severity};
    use taudit_core::graph::{GapKind, PipelineSource};

    fn test_source() -> PipelineSource {
        PipelineSource {
            file: ".github/workflows/ci.yml".into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        }
    }

    fn test_finding(category: FindingCategory, severity: Severity) -> Finding {
        Finding {
            severity,
            category,
            path: None,
            nodes_involved: vec![0, 1],
            message: "test finding".into(),
            recommendation: Recommendation::Manual {
                action: "fix it".into(),
            },
            source: taudit_core::finding::FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        }
    }

    fn read_json(relative: &str) -> serde_json::Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative);
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        serde_json::from_str(&text)
            .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
    }

    #[test]
    fn emits_one_jsonl_line_per_finding() {
        let graph = AuthorityGraph::new(test_source());
        let findings = vec![
            test_finding(FindingCategory::UnpinnedAction, Severity::Medium),
            test_finding(FindingCategory::AuthorityPropagation, Severity::Critical),
        ];

        let mut buf = Vec::new();
        CloudEventsJsonlSink::default()
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2, "one JSONL line per finding");
    }

    #[test]
    fn each_line_is_valid_cloudevent() {
        let graph = AuthorityGraph::new(test_source());
        let findings = vec![test_finding(
            FindingCategory::OverPrivilegedIdentity,
            Severity::High,
        )];

        let mut buf = Vec::new();
        CloudEventsJsonlSink::default()
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        let event: serde_json::Value =
            serde_json::from_str(output.lines().next().unwrap()).unwrap();

        assert_eq!(event["specversion"], "1.0");
        assert_eq!(event["source"], "taudit");
        assert_eq!(event["type"], "io.taudit.finding.over_privileged_identity");
        assert_eq!(event["subject"], ".github/workflows/ci.yml");
        assert_eq!(event["datacontenttype"], "application/json");
        assert!(event["id"].is_string());
        assert!(event["time"].is_string());
        assert!(event["data"].is_object());
        assert_eq!(event["tauditcompleteness"], "complete");
        assert!(event["correlationid"].is_string());
        assert_eq!(event["provenancerepo"], "taudit");
        assert_eq!(event["provenanceproducer"], "taudit-sink-cloudevents");
        assert_eq!(event["provenancekind"], "finding");
    }

    #[test]
    fn partial_graph_sets_completeness_extension() {
        let mut graph = AuthorityGraph::new(test_source());
        // Use `Structural` — it represents the more impactful failure class
        // (unresolvable composite / reusable-workflow / extends / include),
        // and exercises a different `GapKind` variant than the parser-side
        // tests so this regression covers the full enum surface.
        graph.mark_partial(
            GapKind::Structural,
            "composite action ref unresolved at scan time",
        );
        let findings = vec![test_finding(
            FindingCategory::AuthorityPropagation,
            Severity::Critical,
        )];

        let mut buf = Vec::new();
        CloudEventsJsonlSink::default()
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        let event: serde_json::Value =
            serde_json::from_str(output.lines().next().unwrap()).unwrap();

        assert_eq!(event["tauditcompleteness"], "partial");

        // The new structured `tauditcompletenessgaps` extension must surface
        // the typed kind alongside the prose reason. Asserting both fields
        // on entry [0] guarantees the parallel-vector zip stays aligned and
        // the serde snake_case rename for `GapKind` is wired through.
        let gaps = event["tauditcompletenessgaps"]
            .as_array()
            .expect("tauditcompletenessgaps must be an array on Partial graphs");
        assert_eq!(gaps.len(), 1, "exactly one gap was recorded");
        assert_eq!(
            gaps[0]["kind"], "structural",
            "GapKind::Structural must serialize as snake_case `structural`",
        );
        assert_eq!(
            gaps[0]["reason"], "composite action ref unresolved at scan time",
            "original reason string must be preserved verbatim",
        );
    }

    #[test]
    fn data_payload_contains_finding_fields() {
        let graph = AuthorityGraph::new(test_source());
        let findings = vec![test_finding(
            FindingCategory::LongLivedCredential,
            Severity::Low,
        )];

        let mut buf = Vec::new();
        CloudEventsJsonlSink::default()
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        let event: serde_json::Value =
            serde_json::from_str(output.lines().next().unwrap()).unwrap();
        let data = &event["data"];

        assert_eq!(data["severity"], "low");
        assert_eq!(data["category"], "long_lived_credential");
        assert_eq!(data["message"], "test finding");
        assert!(data["recommendation"].is_object());
    }

    #[test]
    fn event_type_maps_all_categories() {
        let categories = vec![
            (
                FindingCategory::AuthorityPropagation,
                "io.taudit.finding.authority_propagation",
            ),
            (
                FindingCategory::OverPrivilegedIdentity,
                "io.taudit.finding.over_privileged_identity",
            ),
            (
                FindingCategory::UnpinnedAction,
                "io.taudit.finding.unpinned_action",
            ),
            (
                FindingCategory::UntrustedWithAuthority,
                "io.taudit.finding.untrusted_with_authority",
            ),
            (
                FindingCategory::ArtifactBoundaryCrossing,
                "io.taudit.finding.artifact_boundary_crossing",
            ),
            (
                FindingCategory::EgressBlindspot,
                "io.taudit.finding.egress_blindspot",
            ),
            (
                FindingCategory::MissingAuditTrail,
                "io.taudit.finding.missing_audit_trail",
            ),
            (
                FindingCategory::FloatingImage,
                "io.taudit.finding.floating_image",
            ),
            (
                FindingCategory::LongLivedCredential,
                "io.taudit.finding.long_lived_credential",
            ),
        ];

        for (cat, expected) in categories {
            assert_eq!(event_type(cat), expected);
        }
    }

    #[test]
    fn emitted_event_matches_cloudevent_schema() {
        let graph = AuthorityGraph::new(test_source());
        let findings = vec![test_finding(
            FindingCategory::AuthorityPropagation,
            Severity::Critical,
        )];

        let mut buf = Vec::new();
        CloudEventsJsonlSink::default()
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        let event = serde_json::from_str(output.lines().next().unwrap()).unwrap();
        let schema = read_json("contracts/schemas/taudit-cloudevent-finding-v1.schema.json");
        let validator =
            jsonschema::validator_for(&schema).expect("cloudevent schema should compile");
        let errors: Vec<String> = validator
            .iter_errors(&event)
            .map(|err| err.to_string())
            .collect();

        assert!(
            errors.is_empty(),
            "emitted event does not match CloudEvent schema:\n{}",
            errors.join("\n")
        );
    }

    #[test]
    fn checked_in_example_matches_cloudevent_schema() {
        let event = read_json("contracts/examples/over-privileged-finding.cloudevent.json");
        let schema = read_json("contracts/schemas/taudit-cloudevent-finding-v1.schema.json");
        let validator =
            jsonschema::validator_for(&schema).expect("cloudevent schema should compile");
        let errors: Vec<String> = validator
            .iter_errors(&event)
            .map(|err| err.to_string())
            .collect();

        assert!(
            errors.is_empty(),
            "checked-in CloudEvent example does not match schema:\n{}",
            errors.join("\n")
        );
    }

    #[test]
    fn emitted_event_matches_shared_envelope_schema() {
        let graph = AuthorityGraph::new(test_source());
        let findings = vec![test_finding(
            FindingCategory::AuthorityPropagation,
            Severity::Critical,
        )];

        let mut buf = Vec::new();
        CloudEventsJsonlSink::default()
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        let event = serde_json::from_str(output.lines().next().unwrap()).unwrap();
        let schema = read_json("contracts/schemas/ecosystem-evidence-envelope-v0.schema.json");
        let validator =
            jsonschema::validator_for(&schema).expect("shared envelope schema should compile");
        let errors: Vec<String> = validator
            .iter_errors(&event)
            .map(|err| err.to_string())
            .collect();

        assert!(
            errors.is_empty(),
            "emitted event does not match shared envelope schema:\n{}",
            errors.join("\n")
        );
    }

    #[test]
    fn checked_in_example_matches_shared_envelope_schema() {
        let event = read_json("contracts/examples/over-privileged-finding.cloudevent.json");
        let schema = read_json("contracts/schemas/ecosystem-evidence-envelope-v0.schema.json");
        let validator =
            jsonschema::validator_for(&schema).expect("shared envelope schema should compile");
        let errors: Vec<String> = validator
            .iter_errors(&event)
            .map(|err| err.to_string())
            .collect();

        assert!(
            errors.is_empty(),
            "checked-in CloudEvent example does not match shared envelope schema:\n{}",
            errors.join("\n")
        );
    }

    #[test]
    fn shared_envelope_example_matches_shared_envelope_schema() {
        let event = read_json("contracts/examples/ecosystem-evidence-envelope.example.json");
        let schema = read_json("contracts/schemas/ecosystem-evidence-envelope-v0.schema.json");
        let validator =
            jsonschema::validator_for(&schema).expect("shared envelope schema should compile");
        let errors: Vec<String> = validator
            .iter_errors(&event)
            .map(|err| err.to_string())
            .collect();

        assert!(
            errors.is_empty(),
            "checked-in shared envelope example does not match shared envelope schema:\n{}",
            errors.join("\n")
        );
    }

    #[test]
    fn findings_from_same_emit_share_correlation_id() {
        let graph = AuthorityGraph::new(test_source());
        let findings = vec![
            test_finding(FindingCategory::UnpinnedAction, Severity::Medium),
            test_finding(FindingCategory::AuthorityPropagation, Severity::Critical),
        ];

        let mut buf = Vec::new();
        CloudEventsJsonlSink::default()
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        let correlation_ids: Vec<String> = output
            .lines()
            .map(|line| {
                let event: serde_json::Value = serde_json::from_str(line).unwrap();
                event["correlationid"].as_str().unwrap().to_string()
            })
            .collect();

        assert_eq!(correlation_ids.len(), 2);
        assert_eq!(correlation_ids[0], correlation_ids[1]);
    }

    #[test]
    fn empty_findings_produces_empty_output() {
        let graph = AuthorityGraph::new(test_source());

        let mut buf = Vec::new();
        CloudEventsJsonlSink::default()
            .emit(&mut buf, &graph, &[])
            .unwrap();

        assert!(buf.is_empty(), "no findings = no output");
    }

    #[test]
    fn platform_metadata_surfaces_as_extension_attribute() {
        // taudit-cli stamps `graph.metadata["platform"]` to the canonical
        // short token after resolving the parser. The sink should mirror it
        // verbatim onto the CloudEvent envelope so SIEMs can route by
        // platform without re-parsing the subject.
        for token in &["ado", "gha", "gitlab"] {
            let mut graph = AuthorityGraph::new(test_source());
            graph
                .metadata
                .insert("platform".to_string(), (*token).to_string());
            let findings = vec![test_finding(
                FindingCategory::AuthorityPropagation,
                Severity::High,
            )];

            let mut buf = Vec::new();
            CloudEventsJsonlSink::default()
                .emit(&mut buf, &graph, &findings)
                .unwrap();

            let event: serde_json::Value =
                serde_json::from_str(std::str::from_utf8(&buf).unwrap().lines().next().unwrap())
                    .unwrap();
            assert_eq!(
                event["tauditplatform"], *token,
                "platform metadata must surface verbatim on the envelope"
            );
        }
    }

    #[test]
    fn missing_platform_metadata_omits_extension_attribute() {
        // Backward-compat: events for graphs that lack the metadata key
        // simply omit the attribute. SIEM consumers see absence, not "null".
        let graph = AuthorityGraph::new(test_source());
        assert!(!graph.metadata.contains_key("platform"));
        let findings = vec![test_finding(
            FindingCategory::AuthorityPropagation,
            Severity::High,
        )];

        let mut buf = Vec::new();
        CloudEventsJsonlSink::default()
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let event: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&buf).unwrap().lines().next().unwrap())
                .unwrap();
        assert!(
            event.get("tauditplatform").is_none(),
            "absent metadata must not emit the attribute (not even as null)"
        );
    }

    #[test]
    fn unrecognised_platform_value_is_dropped() {
        // Defence-in-depth: a metadata key written by some future code path
        // with a non-canonical value should not leak through. SIEM rules
        // pattern-match on the closed enum {ado,gha,gitlab}.
        let mut graph = AuthorityGraph::new(test_source());
        graph
            .metadata
            .insert("platform".to_string(), "circleci".to_string());
        let findings = vec![test_finding(
            FindingCategory::AuthorityPropagation,
            Severity::High,
        )];

        let mut buf = Vec::new();
        CloudEventsJsonlSink::default()
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let event: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&buf).unwrap().lines().next().unwrap())
                .unwrap();
        assert!(
            event.get("tauditplatform").is_none(),
            "unrecognised platform tokens must be dropped, not surfaced"
        );
    }

    /// Mirror of `taudit-report-json::tests::json_output_is_byte_deterministic_across_runs`.
    /// CloudEvents intentionally minted a fresh `id` (UUID v4) and `time` per
    /// event, so the envelope is non-deterministic by design on those two
    /// keys. Everything else — `tauditfindingfingerprint`, `tauditfindinggroup`,
    /// `tauditruleid`, `data`, `subject`, `tauditcompleteness`, etc — must be
    /// stable across re-runs of the same scan, mirroring the JSON contract.
    /// Strip `id` and `time` after parsing each event, then assert the
    /// remaining JSON is byte-equal across 9 runs.
    #[test]
    fn cloudevents_stable_bits_are_deterministic_across_runs() {
        use std::collections::HashMap;
        use taudit_core::graph::{EdgeKind, NodeKind, TrustZone};

        fn build_graph() -> (AuthorityGraph, Vec<Finding>) {
            let mut graph = AuthorityGraph::new(PipelineSource {
                file: "ci.yml".into(),
                repo: None,
                git_ref: None,
                commit_sha: None,
            });
            let secret_a = graph.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
            let secret_b = graph.add_node(NodeKind::Secret, "DEPLOY_TOKEN", TrustZone::FirstParty);
            let step = graph.add_node(NodeKind::Step, "deploy", TrustZone::FirstParty);
            graph.add_edge(step, secret_a, EdgeKind::HasAccessTo);
            graph.add_edge(step, secret_b, EdgeKind::HasAccessTo);
            if let Some(node) = graph.nodes.get_mut(step) {
                let mut meta: HashMap<String, String> = HashMap::new();
                meta.insert("z_field".into(), "z".into());
                meta.insert("a_field".into(), "a".into());
                meta.insert("m_field".into(), "m".into());
                meta.insert("k_field".into(), "k".into());
                meta.insert("c_field".into(), "c".into());
                node.metadata = meta;
            }
            graph
                .metadata
                .insert("trigger".into(), "pull_request".into());
            graph.metadata.insert("platform".into(), "gha".into());
            let findings = vec![Finding {
                severity: Severity::High,
                category: FindingCategory::AuthorityPropagation,
                path: None,
                nodes_involved: vec![secret_a, step],
                message: "AWS_KEY reaches deploy".into(),
                recommendation: Recommendation::Manual {
                    action: "scope it".into(),
                },
                source: taudit_core::finding::FindingSource::BuiltIn,
                extras: FindingExtras::default(),
            }];
            (graph, findings)
        }

        // Pin the correlation id so the only intentionally non-deterministic
        // bits left are `id` (UUID v4 per event) and `time` (RFC3339 now()).
        let sink = CloudEventsJsonlSink::with_correlation_id(Some("det-test-correlation".into()));

        fn emit_and_strip(sink: &CloudEventsJsonlSink) -> Vec<u8> {
            let (g, f) = build_graph();
            let mut buf = Vec::new();
            sink.emit(&mut buf, &g, &f).unwrap();
            // One JSONL line, parse → drop `id`/`time` → re-serialise canonically.
            let line = std::str::from_utf8(&buf).unwrap().lines().next().unwrap();
            let mut v: serde_json::Value = serde_json::from_str(line).unwrap();
            if let Some(obj) = v.as_object_mut() {
                obj.remove("id");
                obj.remove("time");
            }
            serde_json::to_vec(&v).unwrap()
        }

        let mut runs: Vec<Vec<u8>> = Vec::with_capacity(9);
        for _ in 0..9 {
            runs.push(emit_and_strip(&sink));
        }

        let first = &runs[0];
        for (i, run) in runs.iter().enumerate().skip(1) {
            assert_eq!(
                first, run,
                "run 0 and run {i} produced byte-different stable CloudEvent bits (non-determinism regression)"
            );
        }
    }

    #[test]
    fn rule_id_extension_matches_canonical_helper() {
        // Built-in finding: tauditruleid mirrors `rule_id_for` (snake_case
        // category). Custom-rule finding: the `[id]` message prefix wins.
        // This is the per-sink half of the cross-sink equality contract
        // covered end-to-end by `cross_sink_contract.rs`.
        let graph = AuthorityGraph::new(test_source());
        let mut custom = test_finding(FindingCategory::AuthorityPropagation, Severity::Critical);
        custom.message = "[my_custom_rule] some prose".into();
        custom.source = taudit_core::finding::FindingSource::Custom {
            source_file: std::path::PathBuf::from("rules/my_custom_rule.yaml"),
        };
        let findings = vec![
            test_finding(FindingCategory::OverPrivilegedIdentity, Severity::High),
            custom,
        ];

        let mut buf = Vec::new();
        CloudEventsJsonlSink::default()
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let lines: Vec<&str> = std::str::from_utf8(&buf).unwrap().lines().collect();
        let v0: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let v1: serde_json::Value = serde_json::from_str(lines[1]).unwrap();

        assert_eq!(v0["tauditruleid"], "over_privileged_identity");
        assert_eq!(v1["tauditruleid"], "my_custom_rule");
        // `type` field stays scoped to the FindingCategory — the custom-rule
        // finding's type is still `authority_propagation` for routing
        // stability, while the new extension surfaces the rule-level id.
        assert_eq!(v1["type"], "io.taudit.finding.authority_propagation");
    }

    #[test]
    fn unique_ids_per_event() {
        let graph = AuthorityGraph::new(test_source());
        let findings = vec![
            test_finding(FindingCategory::UnpinnedAction, Severity::Medium),
            test_finding(FindingCategory::UnpinnedAction, Severity::Medium),
        ];

        let mut buf = Vec::new();
        CloudEventsJsonlSink::default()
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        let ids: Vec<String> = output
            .lines()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                v["id"].as_str().unwrap().to_string()
            })
            .collect();

        assert_ne!(ids[0], ids[1], "each event must have a unique ID");
    }

    /// Parallel to `taudit-report-json`'s
    /// `every_finding_category_variant_validates_against_report_schema`.
    /// The pre-fix CloudEvent schema listed only 10 of the 63
    /// `FindingCategory` variants in `data.properties.category.enum`. A
    /// poisoned MR pipeline whose finding fired one of the missing 53
    /// produced a byte-valid event that strict-validating SIEMs rejected.
    /// Enumerate every variant, emit through the JSONL sink, and validate
    /// against the published CloudEvent schema.
    #[test]
    fn every_finding_category_variant_validates_against_cloudevent_schema() {
        use taudit_core::finding::FindingCategory as C;

        let all: Vec<C> = vec![
            C::AuthorityPropagation,
            C::OverPrivilegedIdentity,
            C::UnpinnedAction,
            C::UntrustedWithAuthority,
            C::ArtifactBoundaryCrossing,
            C::FloatingImage,
            C::LongLivedCredential,
            C::PersistedCredential,
            C::TriggerContextMismatch,
            C::CrossWorkflowAuthorityChain,
            C::AuthorityCycle,
            C::UpliftWithoutAttestation,
            C::SelfMutatingPipeline,
            C::CheckoutSelfPrExposure,
            C::VariableGroupInPrJob,
            C::SelfHostedPoolPrHijack,
            C::SharedSelfHostedPoolNoIsolation,
            C::ServiceConnectionScopeMismatch,
            C::TemplateExtendsUnpinnedBranch,
            C::TemplateRepoRefIsFeatureBranch,
            C::VmRemoteExecViaPipelineSecret,
            C::ShortLivedSasInCommandLine,
            C::SecretToInlineScriptEnvExport,
            C::SecretMaterialisedToWorkspaceFile,
            C::KeyVaultSecretToPlaintext,
            C::TerraformAutoApproveInProd,
            C::AddSpnWithInlineScript,
            C::ParameterInterpolationIntoShell,
            C::RuntimeScriptFetchedFromFloatingUrl,
            C::PrTriggerWithFloatingActionRef,
            C::UntrustedApiResponseToEnvSink,
            C::PrBuildPushesImageWithFloatingCredentials,
            C::SecretViaEnvGateToUntrustedConsumer,
            C::NoWorkflowLevelPermissionsBlock,
            C::ProdDeployJobNoEnvironmentGate,
            C::LongLivedSecretWithoutOidcRecommendation,
            C::PullRequestWorkflowInconsistentForkCheck,
            C::GitlabDeployJobMissingProtectedBranchOnly,
            C::TerraformOutputViaSetvariableShellExpansion,
            C::RiskyTriggerWithAuthority,
            C::SensitiveValueInJobOutput,
            C::ManualDispatchInputToUrlOrCommand,
            C::SecretsInheritOverscopedPassthrough,
            C::UnsafePrArtifactInWorkflowRunConsumer,
            C::ScriptInjectionViaUntrustedContext,
            C::InteractiveDebugActionInAuthorityWorkflow,
            C::PrSpecificCacheKeyInDefaultBranchConsumer,
            C::GhCliWithDefaultTokenEscalating,
            C::CiJobTokenToExternalApi,
            C::IdTokenAudienceOverscoped,
            C::UntrustedCiVarInShellInterpolation,
            C::UnpinnedIncludeRemoteOrBranchRef,
            C::DindServiceGrantsHostAuthority,
            C::SecurityJobSilentlySkipped,
            C::ChildPipelineTriggerInheritsAuthority,
            C::CacheKeyCrossesTrustBoundary,
            C::PatEmbeddedInGitRemoteUrl,
            C::CiTokenTriggersDownstreamWithVariablePassthrough,
            C::DotenvArtifactFlowsToPrivilegedDeployment,
            C::SetvariableIssecretFalse,
            C::HomoglyphInActionRef,
            C::GhaHelperPathSensitiveArgv,
            C::GhaHelperPathSensitiveStdin,
            C::GhaHelperPathSensitiveEnv,
            C::GhaPostAmbientEnvCleanupPath,
            C::GhaActionMintedSecretToHelper,
            C::GhaHelperUntrustedPathResolution,
            C::GhaSecretOutputAfterHelperLogin,
            C::LaterSecretMaterializedAfterPathMutation,
            C::GhaSetupNodeCacheHelperPathHandoff,
            C::GhaSetupPythonCacheHelperPathHandoff,
            C::GhaSetupPythonPipInstallAuthorityEnv,
            C::GhaDockerSetupQemuPrivilegedDockerHelper,
            C::GhaToolInstallerThenShellHelperAuthority,
            C::GhaWorkflowShellAuthorityConcentration,
            C::GhaToolcacheAbsolutePathDowngrade,
            C::EgressBlindspot,
            C::MissingAuditTrail,
        ];

        assert_eq!(
            all.len(),
            78,
            "FindingCategory enumeration is out of sync with the schema generator (expected 78, got {})",
            all.len()
        );

        let schema = read_json("contracts/schemas/taudit-cloudevent-finding-v1.schema.json");
        let validator =
            jsonschema::validator_for(&schema).expect("cloudevent schema should compile");

        for category in all {
            let graph = AuthorityGraph::new(test_source());
            let findings = vec![test_finding(category, Severity::Medium)];

            let mut buf = Vec::new();
            CloudEventsJsonlSink::default()
                .emit(&mut buf, &graph, &findings)
                .expect("sink emits");
            let output = String::from_utf8(buf).expect("output is UTF-8");
            let event: serde_json::Value = serde_json::from_str(output.lines().next().unwrap())
                .expect("emitted line is valid JSON");
            let errors: Vec<String> = validator
                .iter_errors(&event)
                .map(|err| err.to_string())
                .collect();
            assert!(
                errors.is_empty(),
                "category {category:?} produced an event that fails the published CloudEvent schema:\n{}",
                errors.join("\n")
            );
        }
    }
}
