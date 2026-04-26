use serde::Serialize;
use taudit_core::error::TauditError;
use taudit_core::finding::{
    compute_finding_group_id, compute_fingerprint, Finding, FindingCategory,
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
    /// Stable cross-run finding fingerprint. 16 lowercase hex chars,
    /// byte-identical to SARIF `partialFingerprints[primaryLocationLineHash]`
    /// and JSON `findings[].fingerprint`. SIEMs key on this attribute to
    /// dedup findings across re-runs. Per CloudEvents 1.0, extension
    /// attribute names must be lowercase with no separators — hence
    /// `tauditfindingfingerprint` rather than the dashed/snaked form.
    pub tauditfindingfingerprint: String,
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
        tauditfindingfingerprint: compute_fingerprint(finding, graph),
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

pub struct CloudEventsJsonlSink;

impl<W: std::io::Write> ReportSink<W> for CloudEventsJsonlSink {
    fn emit(
        &self,
        w: &mut W,
        graph: &AuthorityGraph,
        findings: &[Finding],
    ) -> Result<(), TauditError> {
        let correlation_id = uuid::Uuid::new_v4().to_string();

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
    use taudit_core::graph::PipelineSource;

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
        CloudEventsJsonlSink
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
        CloudEventsJsonlSink
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
        graph.mark_partial("inferred secret in run: block");
        let findings = vec![test_finding(
            FindingCategory::AuthorityPropagation,
            Severity::Critical,
        )];

        let mut buf = Vec::new();
        CloudEventsJsonlSink
            .emit(&mut buf, &graph, &findings)
            .unwrap();

        let output = String::from_utf8(buf).unwrap();
        let event: serde_json::Value =
            serde_json::from_str(output.lines().next().unwrap()).unwrap();

        assert_eq!(event["tauditcompleteness"], "partial");
    }

    #[test]
    fn data_payload_contains_finding_fields() {
        let graph = AuthorityGraph::new(test_source());
        let findings = vec![test_finding(
            FindingCategory::LongLivedCredential,
            Severity::Low,
        )];

        let mut buf = Vec::new();
        CloudEventsJsonlSink
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
        CloudEventsJsonlSink
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
        CloudEventsJsonlSink
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
        CloudEventsJsonlSink
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
        CloudEventsJsonlSink.emit(&mut buf, &graph, &[]).unwrap();

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
            CloudEventsJsonlSink
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
        CloudEventsJsonlSink
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
        CloudEventsJsonlSink
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

    #[test]
    fn unique_ids_per_event() {
        let graph = AuthorityGraph::new(test_source());
        let findings = vec![
            test_finding(FindingCategory::UnpinnedAction, Severity::Medium),
            test_finding(FindingCategory::UnpinnedAction, Severity::Medium),
        ];

        let mut buf = Vec::new();
        CloudEventsJsonlSink
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
}
