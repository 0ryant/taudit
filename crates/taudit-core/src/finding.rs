//! Finding-engine module for `taudit-core`.
//!
//! ## What lives here
//!
//! Engine-side logic for findings:
//!   * [`compute_fingerprint`] — stable cross-run fingerprint (v3, 128-bit).
//!   * [`compute_finding_group_id`] — UUID v5 over the fingerprint.
//!   * [`rule_id_for`] — single-source-of-truth rule-id resolver.
//!   * [`extract_custom_rule_id`] — strict bracketed-id parser used by the above.
//!
//! ## What lives in `taudit-api`
//!
//! The **wire types** ([`Finding`], [`FindingCategory`], [`Severity`],
//! [`Recommendation`], [`FindingSource`], [`FixEffort`], [`FindingExtras`])
//! and the [`downgrade_severity`] helper that operates purely on the
//! [`Severity`] enum live in `taudit-api`. They are re-exported below so
//! every existing in-tree call site (`use taudit_core::finding::Finding`)
//! keeps compiling.
//!
//! Symbols marked `#[doc(hidden)]` are required to be `pub` for inter-crate
//! visibility within this workspace, but are NOT part of the stable contract.
//! See `taudit-api` for the externally-stable contract surface and
//! `crates/taudit-core/src/lib.rs` for the API stability docstring.

use crate::graph::{AuthorityGraph, NodeKind};
use sha2::{Digest, Sha256};

// ── Re-exports of wire types (now owned by taudit-api) ─────────────────

pub use taudit_api::{
    downgrade_severity, Finding, FindingCategory, FindingExtras, FindingSource, FixEffort,
    PropagationPath, Recommendation, Severity,
};

// `NodeId` is re-exported via `crate::graph` (which itself re-exports
// from taudit-api). The local alias below keeps the original module-level
// path `taudit_core::finding::NodeId` resolvable for any downstream code.
pub use taudit_api::NodeId;

// ── Finding fingerprint ───────────────────────────────────────────────
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
/// with a bracketed id, or if the bracketed token is not a valid
/// snake_case identifier (`^[a-z][a-z0-9_]*$`).
///
/// **Why strict shape?** Built-in rule messages occasionally start with
/// `[high]` / `[critical]` for emphasis, or `[high blast-radius]` for
/// human-readable severity tags. Without a regex check those would
/// silently re-attribute the finding's `rule_id` away from its category
/// and into a phantom custom rule. Only the canonical custom-rule-id
/// shape (lowercase letter, then lowercase / digit / underscore) is
/// honoured.
pub(crate) fn extract_custom_rule_id(message: &str) -> Option<&str> {
    if !message.starts_with('[') {
        return None;
    }
    let end = message.find(']')?;
    let id = &message[1..end];
    if id.is_empty() {
        return None;
    }
    let mut chars = id.chars();
    let first = chars.next()?;
    if !first.is_ascii_lowercase() {
        return None;
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        return None;
    }
    Some(id)
}

/// Snake-case rule id derived from a `FindingCategory`. Explicit match —
/// NOT a serde round-trip — so a future `#[serde(tag)]` change cannot
/// silently reword every fingerprint in the wild. The
/// `every_category_returns_non_unknown_rule_id` test asserts every
/// variant returns a non-`"unknown"` snake_case id.
fn category_rule_id(category: &FindingCategory) -> &'static str {
    match category {
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
        FindingCategory::SharedSelfHostedPoolNoIsolation => "shared_self_hosted_pool_no_isolation",
        FindingCategory::ServiceConnectionScopeMismatch => "service_connection_scope_mismatch",
        FindingCategory::TemplateExtendsUnpinnedBranch => "template_extends_unpinned_branch",
        FindingCategory::TemplateRepoRefIsFeatureBranch => "template_repo_ref_is_feature_branch",
        FindingCategory::VmRemoteExecViaPipelineSecret => "vm_remote_exec_via_pipeline_secret",
        FindingCategory::ShortLivedSasInCommandLine => "short_lived_sas_in_command_line",
        FindingCategory::SecretToInlineScriptEnvExport => "secret_to_inline_script_env_export",
        FindingCategory::SecretMaterialisedToWorkspaceFile => {
            "secret_materialised_to_workspace_file"
        }
        // Note: this variant carries `#[serde(rename = "keyvault_secret_to_plaintext")]` —
        // the serde-rename target is the rule id, not the snake_case derivation.
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
        FindingCategory::GhaScriptInjectionToPrivilegedShell => {
            "gha_script_injection_to_privileged_shell"
        }
        FindingCategory::GhaWorkflowRunArtifactPoisoningToPrivilegedConsumer => {
            "gha_workflow_run_artifact_poisoning_to_privileged_consumer"
        }
        FindingCategory::GhaRemoteScriptInAuthorityJob => "gha_remote_script_in_authority_job",
        FindingCategory::GhaPatRemoteUrlWrite => "gha_pat_remote_url_write",
        FindingCategory::GhaIssueCommentCommandToWriteToken => {
            "gha_issue_comment_command_to_write_token"
        }
        FindingCategory::GhaPrBuildPushesPublishableImage => {
            "gha_pr_build_pushes_publishable_image"
        }
        FindingCategory::GhaManualDispatchRefToPrivilegedCheckout => {
            "gha_manual_dispatch_ref_to_privileged_checkout"
        }
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
        FindingCategory::GhaSetupGoCacheHelperPathHandoff => {
            "gha_setup_go_cache_helper_path_handoff"
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
        FindingCategory::GhaActionTokenEnvBeforeBareDownloadHelper => {
            "gha_action_token_env_before_bare_download_helper"
        }
        FindingCategory::GhaPostActionInputRetargetToCacheSave => {
            "gha_post_action_input_retarget_to_cache_save"
        }
        FindingCategory::GhaTerraformWrapperSensitiveOutput => {
            "gha_terraform_wrapper_sensitive_output"
        }
        FindingCategory::GhaCompositeBareHelperAfterPathInstallWithSecretEnv => {
            "gha_composite_bare_helper_after_path_install_with_secret_env"
        }
        FindingCategory::GhaPulumiPathResolvedCliWithAuthority => {
            "gha_pulumi_path_resolved_cli_with_authority"
        }
        FindingCategory::GhaPypiPublishOidcAfterPathMutation => {
            "gha_pypi_publish_oidc_after_path_mutation"
        }
        FindingCategory::GhaChangesetsPublishCommandWithAuthority => {
            "gha_changesets_publish_command_with_authority"
        }
        FindingCategory::GhaRubygemsReleaseGitTokenAndOidcHelper => {
            "gha_rubygems_release_git_token_and_oidc_helper"
        }
        FindingCategory::GhaCompositeEntrypointPathShadowWithSecretEnv => {
            "gha_composite_entrypoint_path_shadow_with_secret_env"
        }
        FindingCategory::GhaDockerBuildxAuthorityPathHandoff => {
            "gha_docker_buildx_authority_path_handoff"
        }
        FindingCategory::GhaGoogleDeployGcloudCredentialPath => {
            "gha_google_deploy_gcloud_credential_path"
        }
        FindingCategory::GhaDatadogTestVisibilityInstallerAuthority => {
            "gha_datadog_test_visibility_installer_authority"
        }
        FindingCategory::GhaKubernetesHelperKubeconfigAuthority => {
            "gha_kubernetes_helper_kubeconfig_authority"
        }
        FindingCategory::GhaAzureCompanionHelperAuthority => "gha_azure_companion_helper_authority",
        FindingCategory::GhaCreatePrGitTokenPathHandoff => "gha_create_pr_git_token_path_handoff",
        FindingCategory::GhaImportGpgPrivateKeyHelperPath => {
            "gha_import_gpg_private_key_helper_path"
        }
        FindingCategory::GhaSshAgentPrivateKeyToPathHelper => {
            "gha_ssh_agent_private_key_to_path_helper"
        }
        FindingCategory::GhaMacosCodesignCertSecurityPath => {
            "gha_macos_codesign_cert_security_path"
        }
        FindingCategory::GhaPagesDeployTokenUrlToGitHelper => {
            "gha_pages_deploy_token_url_to_git_helper"
        }
        FindingCategory::GhaWorkflowRunArtifactMetadataToPrivilegedApi => {
            "gha_workflow_run_artifact_metadata_to_privileged_api"
        }
        FindingCategory::GhaWorkflowRunArtifactReportToPrComment => {
            "gha_workflow_run_artifact_report_to_pr_comment"
        }
        FindingCategory::GhaWorkflowRunArtifactToBuildScanPublish => {
            "gha_workflow_run_artifact_to_build_scan_publish"
        }
        FindingCategory::GhaFloatingRemoteScriptBeforePublishSink => {
            "gha_floating_remote_script_before_publish_sink"
        }
        FindingCategory::GhaTokenRemoteUrlWithTraceOrProcessExposure => {
            "gha_token_remote_url_with_trace_or_process_exposure"
        }
        FindingCategory::GhaEnvCredentialHelperConfigRedirectBeforeAuthority => {
            "gha_env_credential_helper_config_redirect_before_authority"
        }
        FindingCategory::GhaEnvNodeOptionsCodeInjectionBeforeNodeAuthority => {
            "gha_env_node_options_code_injection_before_node_authority"
        }
        FindingCategory::GhaEnvDyldOrLdLibraryPathBeforeCredentialHelper => {
            "gha_env_dyld_or_ld_library_path_before_credential_helper"
        }
        FindingCategory::GhaWorkflowCallContainerImageInputSecretsInherit => {
            "gha_workflow_call_container_image_input_secrets_inherit"
        }
        FindingCategory::GhaWorkflowCallRunnerLabelInputPrivilegeEscalation => {
            "gha_workflow_call_runner_label_input_privilege_escalation"
        }
        FindingCategory::GhaContainerImageAttackerInfluencedWithSecretEnv => {
            "gha_container_image_attacker_influenced_with_secret_env"
        }
        FindingCategory::GhaAttestationSubjectDigestFromStepOutputUnverified => {
            "gha_attestation_subject_digest_from_step_output_unverified"
        }
        FindingCategory::GhaAttestationSubjectPathWorkspaceGlobWithPrTrigger => {
            "gha_attestation_subject_path_workspace_glob_with_pr_trigger"
        }
        FindingCategory::GhaAttestationConfigDrivenGateFromWorkspaceFile => {
            "gha_attestation_config_driven_gate_from_workspace_file"
        }
        FindingCategory::GhaTelemetryPrOrIssueTextToExternalSink => {
            "gha_telemetry_pr_or_issue_text_to_external_sink"
        }
        FindingCategory::GhaTelemetryDebugFlagWithSecretEnv => {
            "gha_telemetry_debug_flag_with_secret_env"
        }
        FindingCategory::GhaTelemetryAutonomousAgentInputFromUntrustedEvent => {
            "gha_telemetry_autonomous_agent_input_from_untrusted_event"
        }
        FindingCategory::GhaWorkflowRunArtifactToBlobStorageToken => {
            "gha_workflow_run_artifact_to_blob_storage_token"
        }
        FindingCategory::GhaApiWorkflowRunArtifactToAutonomousAgentToGitPush => {
            "gha_api_workflow_run_artifact_to_autonomous_agent_to_git_push"
        }
        FindingCategory::GhaManifestNpmLifecycleHookPrTriggerWithToken => {
            "gha_manifest_npm_lifecycle_hook_pr_trigger_with_token"
        }
        FindingCategory::GhaManifestPythonMBuildWithPrCredentials => {
            "gha_manifest_python_m_build_with_pr_credentials"
        }
        FindingCategory::GhaManifestCargoBuildRsPullRequestWithToken => {
            "gha_manifest_cargo_build_rs_pull_request_with_token"
        }
        FindingCategory::GhaManifestMakefileWithPrTriggerAndSecrets => {
            "gha_manifest_makefile_with_pr_trigger_and_secrets"
        }
        FindingCategory::GhaManifestSubmodulesRecursiveWithPrAuthority => {
            "gha_manifest_submodules_recursive_with_pr_authority"
        }
        FindingCategory::GhaCrossrepoWorkflowCallFloatingRefCascade => {
            "gha_crossrepo_workflow_call_floating_ref_cascade"
        }
        FindingCategory::GhaCrossrepoSecretsInheritUnreviewedCallee => {
            "gha_crossrepo_secrets_inherit_unreviewed_callee"
        }
        FindingCategory::GhaToolcacheAbsolutePathDowngrade => {
            "gha_toolcache_absolute_path_downgrade"
        }
        FindingCategory::EgressBlindspot => "egress_blindspot",
        FindingCategory::MissingAuditTrail => "missing_audit_trail",
    }
}

/// Workspace-internal rule-id resolver for a finding. Single source of
/// truth used by JSON, SARIF, CloudEvents, and baseline sinks.
///
/// Returns the snake_case rule id reported alongside this finding. When the
/// finding's message starts with a bracketed snake_case identifier
/// (`[my_rule] ...`), the bracketed id wins so custom YAML rules surface
/// their declared id. Otherwise the rule id is the snake_case form of the
/// finding's `category` (the same string serde uses to serialize the
/// category enum).
///
/// **API stability:** marked `#[doc(hidden)]` because `taudit-core` is a
/// workspace-internal library — see the module-level docstring on
/// `crates/taudit-core/src/lib.rs`. External consumers should read the
/// `rule_id` field from the JSON / SARIF / CloudEvents output instead.
#[doc(hidden)]
pub fn rule_id_for(finding: &Finding) -> String {
    extract_custom_rule_id(&finding.message)
        .map(str::to_string)
        .unwrap_or_else(|| category_rule_id(&finding.category).to_string())
}

/// Stable UUID v5 over the finding fingerprint. Two findings whose
/// fingerprints match (same rule + file + root authority) produce the
/// same `finding_group_id` — that is the whole point: SIEMs and triage
/// dashboards collapse N hops against a single secret into one row.
///
/// The UUID v5 namespace is a fixed UUID v4 derived once and embedded
/// here. Treating the namespace as load-bearing is intentional: any
/// future change here would break every consumer that has stored a
/// `finding_group_id`. Bump only at a major version.
///
/// **API stability:** marked `#[doc(hidden)]` because `taudit-core` is a
/// workspace-internal library. External consumers should read the
/// `finding_group_id` field from the JSON / SARIF / CloudEvents output.
#[doc(hidden)]
pub fn compute_finding_group_id(fingerprint: &str) -> String {
    // UUID v5 = SHA-1(namespace || name), with version + variant bits set.
    // Implemented inline so taudit-core stays free of the `uuid` crate
    // dependency (workspace already depends on it from the CLI; core
    // remains zero-IO and minimal).
    const NAMESPACE: [u8; 16] = [
        0x6c, 0x6f, 0xd0, 0xa3, 0x82, 0x44, 0x4f, 0x29, 0xb1, 0x9a, 0x09, 0xc8, 0x7e, 0x49, 0x55,
        0x21,
    ];

    use sha1::{Digest as Sha1Digest, Sha1};
    let mut hasher = Sha1::new();
    Sha1Digest::update(&mut hasher, NAMESPACE);
    Sha1Digest::update(&mut hasher, fingerprint.as_bytes());
    let hash = hasher.finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    // RFC 4122 §4.3: set version to 5 (bits 12-15 of time_hi_and_version)
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    // RFC 4122 §4.4: set variant to RFC 4122 (bits 6-7 of clock_seq_hi)
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

/// Compute a stable cross-run fingerprint for a finding.
///
/// The fingerprint identifies "the same logical issue" across re-runs and
/// across non-cosmetic edits to the surrounding pipeline. Two runs against
/// the same input file produce the same fingerprint; a fix to the
/// underlying issue makes the fingerprint disappear; a tweak to the
/// finding's user-facing message does NOT change the fingerprint.
///
/// **Algorithm version `v3`** (replaces v2 from v0.9.1, in turn replacing
/// v1 from earlier).
///
/// v3 changes vs v2:
///   1. Output truncated to 16 bytes (32 hex chars / 128 bits) instead of
///      8 bytes (16 hex chars / 64 bits). v2's 64-bit truncation gave a
///      ~2³² birthday-collision frontier — single-digit hours of laptop
///      compute. An attacker who can read `.taudit-suppressions.yml`
///      (public on every OSS repo) could craft a Critical finding whose
///      fingerprint matched a benign waiver and ship unreviewed code. v3
///      raises the work factor to ~2⁶⁴, well past any practical attack.
///   2. `graph.source.file` is normalised to forward-slash form before
///      hashing. A Windows scan emitting `workflows\ci.yml` and a Linux
///      baseline scanning `workflows/ci.yml` now produce identical
///      fingerprints for the same logical issue.
///   3. Out-of-range `NodeId` values in `nodes_involved` emit a
///      `<missing:N>` sentinel instead of being silently dropped. Two
///      findings whose `nodes_involved` differ only by elided positions
///      produce different fingerprints rather than aliasing.
///   4. `extras.fingerprint_anchor` mixes a per-finding stable token into
///      the canonical string. Rules whose findings carry no graph-node
///      anchor (workflow-level invariants, repository-alias rules) set
///      this to a discriminating string (alias name, identity name) so
///      multiple instances within one file produce distinct fingerprints.
///
/// **Inputs (sensitive to):**
///   * Rule id — either a custom rule id parsed from a `[id] …` message
///     prefix (only when the bracketed token matches `^[a-z][a-z0-9_]*$`),
///     or the snake_case form of `finding.category`
///   * Source file path (`graph.source.file`) — normalised to forward-slash
///     so cross-platform scans agree, but never collapsed to a basename
///   * Finding category (snake_case)
///   * Root-authority node name — Secret/Identity name when one is
///     involved, empty string otherwise
///   * Ordered involved-node names — every node in `nodes_involved`;
///     out-of-range ids surface as `<missing:N>` sentinels rather than
///     silently disappearing
///   * `extras.fingerprint_anchor` — per-finding discriminator for rules
///     without a natural graph-node anchor
///
/// **Inputs (insensitive to):**
///   * Wall-clock time
///   * The finding's `message` text — operators tweak phrasing without
///     wanting suppressions to break (custom-rule-id prefix is read out
///     of the message, but only if it is a valid snake_case identifier)
///   * `taudit` version string
///   * Environment / host / cwd
///   * Pipeline file content hash — only the path matters
///
/// Stability guarantee: the v3 algorithm is stable for the v1.1+ line.
/// v2 (16-hex) suppressions DO NOT carry forward — a one-time
/// re-baselining is required when upgrading from any v0.x or v1.0 release.
/// CHANGELOG and `docs/finding-fingerprint.md` flag the break explicitly.
///
/// Output: SHA-256 of the canonical input string, truncated to the first
/// 32 hex characters (128 bits — far past collision-attack feasibility,
/// still short enough to be glanceable in a SIEM table).
///
/// **API stability:** marked `#[doc(hidden)]` because `taudit-core` is a
/// workspace-internal library — see `crates/taudit-core/src/lib.rs`.
/// External consumers should read the `fingerprint` field from the JSON /
/// SARIF / CloudEvents output instead.
#[doc(hidden)]
pub fn compute_fingerprint(finding: &Finding, graph: &AuthorityGraph) -> String {
    let rule_id = extract_custom_rule_id(&finding.message)
        .map(str::to_string)
        .unwrap_or_else(|| category_rule_id(&finding.category).to_string());

    let category = category_rule_id(&finding.category);

    // v3 normalisation: collapse `\` to `/` so a Windows scan and a Linux
    // baseline of the same logical pipeline produce identical fingerprints.
    // Documented in the docstring above; tested by
    // `fingerprint_is_stable_across_path_separator_styles`.
    let file_normalised: String = graph.source.file.replace('\\', "/");

    // Root authority name (if any) — always emitted as its own component,
    // empty string when no Secret/Identity is involved. Distinct field so
    // a finding whose root_authority differs from a sibling's is
    // recognisably different even when the involved-node list happens to
    // overlap.
    let root_authority: String = finding
        .nodes_involved
        .iter()
        .filter_map(|id| graph.node(*id))
        .find(|n| matches!(n.kind, NodeKind::Secret | NodeKind::Identity))
        .map(|n| n.name.clone())
        .unwrap_or_default();

    // Ordered involved-node names. Order is preserved (NOT sorted) — for
    // authority_propagation findings the convention is `[source, sink]`,
    // so two findings hitting the same secret but reaching different
    // untrusted steps produce different fingerprints (the v1 collision
    // class). Out-of-range NodeId surfaces as `<missing:N>` so two
    // findings whose `nodes_involved` differ only by elided positions do
    // not alias.
    let nodes_ordered: String = finding
        .nodes_involved
        .iter()
        .map(|id| match graph.node(*id) {
            Some(n) => n.name.as_str().to_string(),
            None => format!("<missing:{id}>"),
        })
        .collect::<Vec<_>>()
        .join(",");

    let anchor = finding
        .extras
        .fingerprint_anchor
        .as_deref()
        .unwrap_or_default();

    // Canonical encoding: every component prefixed with a tag and joined
    // by `\x1f` (ASCII unit separator) so component boundaries cannot
    // alias across inputs. Algorithm version baked into the prefix so a
    // future change to the contract is detectable from the canonical
    // string alone.
    let canonical = format!(
        "v3\x1frule={rule_id}\x1ffile={file_normalised}\x1fcategory={category}\x1froot={root_authority}\x1fnodes={nodes_ordered}\x1fanchor={anchor}"
    );

    let digest = Sha256::digest(canonical.as_bytes());
    let mut out = String::with_capacity(32);
    for byte in &digest[..16] {
        use std::fmt::Write;
        // 16 bytes -> 32 hex chars (128-bit truncation)
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
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
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
        assert_eq!(a.len(), 32, "fingerprint is 32 hex chars (v3 = 128-bit)");
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
    fn per_hop_findings_against_same_authority_are_distinct() {
        // v2 contract: a single secret reaching N distinct untrusted steps
        // produces N distinct fingerprints. Each (secret, step) pair is its
        // own remediation-distinct finding — collapsing them (the v1
        // behaviour) hid genuinely different exposure surfaces. SIEMs that
        // want a per-secret rollup can group on root_authority client-side.
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
        assert_ne!(
            compute_fingerprint(&f_a, &graph),
            compute_fingerprint(&f_b, &graph),
            "per-hop findings against one secret must produce distinct \
             fingerprints — sink identity is part of the issue"
        );
    }

    #[test]
    fn same_secret_same_sink_remains_stable_across_calls() {
        // Re-running the SAME finding (same secret, same sink, same file)
        // must still produce the same fingerprint — that is the entire
        // point of cross-run dedup. The v2 change adds inputs but does not
        // introduce non-determinism.
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let secret = graph.add_node(NodeKind::Secret, "DEPLOY_TOKEN", TrustZone::FirstParty);
        let step = graph.add_node(NodeKind::Step, "deploy[0]", TrustZone::Untrusted);
        let f = make_finding(
            FindingCategory::AuthorityPropagation,
            "msg",
            vec![secret, step],
        );
        assert_eq!(
            compute_fingerprint(&f, &graph),
            compute_fingerprint(&f, &graph)
        );
    }

    #[test]
    fn r2_attack2_two_files_same_secret_name_distinct_fingerprints() {
        // R2 attack #2 reproducer: two genuinely different findings in two
        // different pipeline files that share a secret NAME must produce
        // different fingerprints. The earlier (pre-v0.9.1) algorithm could
        // collide here; the v2 algorithm explicitly includes file path so
        // the names cannot alias across files.
        let mut g_a = AuthorityGraph::new(source("workflows/a.yml"));
        let mut g_b = AuthorityGraph::new(source("workflows/b.yml"));
        let s_a = g_a.add_node(NodeKind::Secret, "MY_SECRET", TrustZone::FirstParty);
        let sink_a = g_a.add_node(NodeKind::Step, "evil/action", TrustZone::Untrusted);
        let s_b = g_b.add_node(NodeKind::Secret, "MY_SECRET", TrustZone::FirstParty);
        let sink_b = g_b.add_node(
            NodeKind::Step,
            "different-evil/action",
            TrustZone::Untrusted,
        );

        let f_a = make_finding(
            FindingCategory::AuthorityPropagation,
            "MY_SECRET reaches evil/action",
            vec![s_a, sink_a],
        );
        let f_b = make_finding(
            FindingCategory::AuthorityPropagation,
            "MY_SECRET reaches different-evil/action",
            vec![s_b, sink_b],
        );
        assert_ne!(
            compute_fingerprint(&f_a, &g_a),
            compute_fingerprint(&f_b, &g_b),
            "two genuinely different findings must not share a fingerprint \
             just because the secret name overlaps"
        );
    }

    #[test]
    fn root_authority_segment_is_always_present_even_when_empty() {
        // Findings without any Secret/Identity (e.g. floating_image) MUST
        // still produce a stable fingerprint. The empty-root case is its
        // own equivalence class — two such findings with the same node
        // list collapse to the same fingerprint; differing node lists
        // produce different fingerprints.
        let mut g = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let img_a = g.add_node(NodeKind::Image, "alpine:latest", TrustZone::ThirdParty);
        let img_b = g.add_node(NodeKind::Image, "ubuntu:22.04", TrustZone::ThirdParty);
        let f_a = make_finding(FindingCategory::FloatingImage, "msg-a", vec![img_a]);
        let f_b = make_finding(FindingCategory::FloatingImage, "msg-b", vec![img_b]);
        let fp_a = compute_fingerprint(&f_a, &g);
        let fp_b = compute_fingerprint(&f_b, &g);
        assert_ne!(
            fp_a, fp_b,
            "two distinct floating-image findings must not collide"
        );
        assert_eq!(fp_a.len(), 32);
        assert_eq!(fp_b.len(), 32);
    }

    #[test]
    fn node_order_is_significant() {
        // The fingerprint preserves caller order in nodes_involved. A
        // finding emitted as [secret, step] is semantically different from
        // [step, secret] (source vs sink role) and produces a different
        // fingerprint. Rules must therefore stay consistent in the order
        // they push nodes — every built-in does today.
        let mut g = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let s = g.add_node(NodeKind::Secret, "K", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "use", TrustZone::Untrusted);
        let forward = make_finding(FindingCategory::AuthorityPropagation, "x", vec![s, step]);
        let reverse = make_finding(FindingCategory::AuthorityPropagation, "x", vec![step, s]);
        assert_ne!(
            compute_fingerprint(&forward, &g),
            compute_fingerprint(&reverse, &g),
            "node order must influence the fingerprint so role swap is detectable"
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
    fn finding_group_id_is_deterministic_uuid_v5() {
        // Same fingerprint -> same group id, byte-identical.
        let g1 = compute_finding_group_id("5edb30f4db3b5fa3");
        let g2 = compute_finding_group_id("5edb30f4db3b5fa3");
        assert_eq!(g1, g2);
        // UUID v5 shape: 8-4-4-4-12 hex chars with version=5 nibble.
        assert_eq!(g1.len(), 36);
        // Position 14 is the version nibble — must be '5' for v5.
        assert_eq!(
            g1.chars().nth(14),
            Some('5'),
            "expected v5 marker, got {g1}"
        );
        // Position 19 is the variant nibble — must be one of 8/9/a/b.
        let variant = g1.chars().nth(19).unwrap();
        assert!(
            matches!(variant, '8' | '9' | 'a' | 'b'),
            "expected RFC 4122 variant, got {variant}"
        );
        // Different fingerprint -> different group id.
        assert_ne!(g1, compute_finding_group_id("a3c8d9e1f2b4c5d6"));
    }

    #[test]
    fn with_time_to_fix_attaches_effort() {
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let s = graph.add_node(NodeKind::Secret, "X", TrustZone::FirstParty);
        let f = make_finding(FindingCategory::UnpinnedAction, "msg", vec![s])
            .with_time_to_fix(FixEffort::Trivial);
        assert_eq!(f.extras.time_to_fix, Some(FixEffort::Trivial));
    }

    #[test]
    fn with_compensating_control_downgrades_and_records_original() {
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let s = graph.add_node(NodeKind::Secret, "X", TrustZone::FirstParty);
        let f = make_finding(FindingCategory::TriggerContextMismatch, "msg", vec![s])
            .with_compensating_control("fork check present");
        // Default High in make_finding -> downgraded to Medium.
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.extras.original_severity, Some(Severity::High));
        assert_eq!(f.extras.compensating_controls.len(), 1);
    }

    #[test]
    fn empty_node_list_still_produces_fingerprint() {
        // Categories like authority_cycle, floating_image, unpinned_action
        // may not carry an authority node — fingerprint must still work.
        let graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let f = make_finding(FindingCategory::UnpinnedAction, "no nodes here", vec![]);
        let fp = compute_fingerprint(&f, &graph);
        assert_eq!(fp.len(), 32);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── v3 hardening: 128-bit, path normalisation, sentinel, anchor ─────

    #[test]
    fn fingerprint_is_32_hex_chars() {
        // v3 truncates SHA-256 to 16 bytes (128 bits) so the
        // birthday-collision frontier moves from ~2³² (single-digit hours
        // on a laptop, the v2 attack surface) to ~2⁶⁴ (impractical).
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let s = graph.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
        let f = make_finding(FindingCategory::AuthorityPropagation, "msg", vec![s]);
        let fp = compute_fingerprint(&f, &graph);
        assert_eq!(fp.len(), 32, "v3 fingerprint is 32 lowercase hex chars");
        assert!(
            fp.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "fingerprint must be lowercase hex: {fp}"
        );
    }

    #[test]
    fn fingerprint_is_stable_across_path_separator_styles() {
        // A Windows scan emits `workflows\ci.yml`; a Linux baseline
        // catalogues the same file as `workflows/ci.yml`. v3 normalises
        // separators before hashing so the two fingerprints match.
        let mut g_win = AuthorityGraph::new(source("workflows\\ci.yml"));
        let mut g_lin = AuthorityGraph::new(source("workflows/ci.yml"));
        let s_win = g_win.add_node(NodeKind::Secret, "TOKEN", TrustZone::FirstParty);
        let s_lin = g_lin.add_node(NodeKind::Secret, "TOKEN", TrustZone::FirstParty);
        let f_win = make_finding(FindingCategory::AuthorityPropagation, "msg", vec![s_win]);
        let f_lin = make_finding(FindingCategory::AuthorityPropagation, "msg", vec![s_lin]);
        assert_eq!(
            compute_fingerprint(&f_win, &g_win),
            compute_fingerprint(&f_lin, &g_lin),
            "Windows-separator and POSIX-separator paths must produce identical fingerprints"
        );
    }

    #[test]
    fn every_category_returns_non_unknown_rule_id() {
        // Hand-list every variant. If a new variant is added without
        // updating `category_rule_id`, the explicit match above will not
        // compile — this test then catches any drift.
        let all = [
            FindingCategory::AuthorityPropagation,
            FindingCategory::OverPrivilegedIdentity,
            FindingCategory::UnpinnedAction,
            FindingCategory::UntrustedWithAuthority,
            FindingCategory::ArtifactBoundaryCrossing,
            FindingCategory::FloatingImage,
            FindingCategory::LongLivedCredential,
            FindingCategory::PersistedCredential,
            FindingCategory::TriggerContextMismatch,
            FindingCategory::CrossWorkflowAuthorityChain,
            FindingCategory::AuthorityCycle,
            FindingCategory::UpliftWithoutAttestation,
            FindingCategory::SelfMutatingPipeline,
            FindingCategory::CheckoutSelfPrExposure,
            FindingCategory::VariableGroupInPrJob,
            FindingCategory::SelfHostedPoolPrHijack,
            FindingCategory::SharedSelfHostedPoolNoIsolation,
            FindingCategory::ServiceConnectionScopeMismatch,
            FindingCategory::TemplateExtendsUnpinnedBranch,
            FindingCategory::TemplateRepoRefIsFeatureBranch,
            FindingCategory::VmRemoteExecViaPipelineSecret,
            FindingCategory::ShortLivedSasInCommandLine,
            FindingCategory::SecretToInlineScriptEnvExport,
            FindingCategory::SecretMaterialisedToWorkspaceFile,
            FindingCategory::KeyVaultSecretToPlaintext,
            FindingCategory::TerraformAutoApproveInProd,
            FindingCategory::AddSpnWithInlineScript,
            FindingCategory::ParameterInterpolationIntoShell,
            FindingCategory::RuntimeScriptFetchedFromFloatingUrl,
            FindingCategory::PrTriggerWithFloatingActionRef,
            FindingCategory::UntrustedApiResponseToEnvSink,
            FindingCategory::PrBuildPushesImageWithFloatingCredentials,
            FindingCategory::SecretViaEnvGateToUntrustedConsumer,
            FindingCategory::NoWorkflowLevelPermissionsBlock,
            FindingCategory::ProdDeployJobNoEnvironmentGate,
            FindingCategory::LongLivedSecretWithoutOidcRecommendation,
            FindingCategory::PullRequestWorkflowInconsistentForkCheck,
            FindingCategory::GitlabDeployJobMissingProtectedBranchOnly,
            FindingCategory::TerraformOutputViaSetvariableShellExpansion,
            FindingCategory::RiskyTriggerWithAuthority,
            FindingCategory::SensitiveValueInJobOutput,
            FindingCategory::ManualDispatchInputToUrlOrCommand,
            FindingCategory::SecretsInheritOverscopedPassthrough,
            FindingCategory::UnsafePrArtifactInWorkflowRunConsumer,
            FindingCategory::ScriptInjectionViaUntrustedContext,
            FindingCategory::InteractiveDebugActionInAuthorityWorkflow,
            FindingCategory::PrSpecificCacheKeyInDefaultBranchConsumer,
            FindingCategory::GhCliWithDefaultTokenEscalating,
            FindingCategory::GhaScriptInjectionToPrivilegedShell,
            FindingCategory::GhaWorkflowRunArtifactPoisoningToPrivilegedConsumer,
            FindingCategory::GhaRemoteScriptInAuthorityJob,
            FindingCategory::GhaPatRemoteUrlWrite,
            FindingCategory::GhaIssueCommentCommandToWriteToken,
            FindingCategory::GhaPrBuildPushesPublishableImage,
            FindingCategory::GhaManualDispatchRefToPrivilegedCheckout,
            FindingCategory::CiJobTokenToExternalApi,
            FindingCategory::IdTokenAudienceOverscoped,
            FindingCategory::UntrustedCiVarInShellInterpolation,
            FindingCategory::UnpinnedIncludeRemoteOrBranchRef,
            FindingCategory::DindServiceGrantsHostAuthority,
            FindingCategory::SecurityJobSilentlySkipped,
            FindingCategory::ChildPipelineTriggerInheritsAuthority,
            FindingCategory::CacheKeyCrossesTrustBoundary,
            FindingCategory::PatEmbeddedInGitRemoteUrl,
            FindingCategory::CiTokenTriggersDownstreamWithVariablePassthrough,
            FindingCategory::DotenvArtifactFlowsToPrivilegedDeployment,
            FindingCategory::SetvariableIssecretFalse,
            FindingCategory::HomoglyphInActionRef,
            FindingCategory::GhaHelperPathSensitiveArgv,
            FindingCategory::GhaHelperPathSensitiveStdin,
            FindingCategory::GhaHelperPathSensitiveEnv,
            FindingCategory::GhaPostAmbientEnvCleanupPath,
            FindingCategory::GhaActionMintedSecretToHelper,
            FindingCategory::GhaHelperUntrustedPathResolution,
            FindingCategory::GhaSecretOutputAfterHelperLogin,
            FindingCategory::LaterSecretMaterializedAfterPathMutation,
            FindingCategory::GhaSetupNodeCacheHelperPathHandoff,
            FindingCategory::GhaSetupPythonCacheHelperPathHandoff,
            FindingCategory::GhaSetupPythonPipInstallAuthorityEnv,
            FindingCategory::GhaSetupGoCacheHelperPathHandoff,
            FindingCategory::GhaDockerSetupQemuPrivilegedDockerHelper,
            FindingCategory::GhaToolInstallerThenShellHelperAuthority,
            FindingCategory::GhaWorkflowShellAuthorityConcentration,
            FindingCategory::GhaActionTokenEnvBeforeBareDownloadHelper,
            FindingCategory::GhaPostActionInputRetargetToCacheSave,
            FindingCategory::GhaTerraformWrapperSensitiveOutput,
            FindingCategory::GhaCompositeBareHelperAfterPathInstallWithSecretEnv,
            FindingCategory::GhaPulumiPathResolvedCliWithAuthority,
            FindingCategory::GhaPypiPublishOidcAfterPathMutation,
            FindingCategory::GhaChangesetsPublishCommandWithAuthority,
            FindingCategory::GhaRubygemsReleaseGitTokenAndOidcHelper,
            FindingCategory::GhaCompositeEntrypointPathShadowWithSecretEnv,
            FindingCategory::GhaDockerBuildxAuthorityPathHandoff,
            FindingCategory::GhaGoogleDeployGcloudCredentialPath,
            FindingCategory::GhaDatadogTestVisibilityInstallerAuthority,
            FindingCategory::GhaKubernetesHelperKubeconfigAuthority,
            FindingCategory::GhaAzureCompanionHelperAuthority,
            FindingCategory::GhaCreatePrGitTokenPathHandoff,
            FindingCategory::GhaImportGpgPrivateKeyHelperPath,
            FindingCategory::GhaSshAgentPrivateKeyToPathHelper,
            FindingCategory::GhaMacosCodesignCertSecurityPath,
            FindingCategory::GhaPagesDeployTokenUrlToGitHelper,
            FindingCategory::GhaToolcacheAbsolutePathDowngrade,
            FindingCategory::EgressBlindspot,
            FindingCategory::MissingAuditTrail,
        ];
        for cat in all {
            let id = category_rule_id(&cat);
            assert_ne!(id, "unknown", "category {cat:?} returned `unknown` rule id");
            assert!(
                !id.is_empty() && id.chars().next().is_some_and(|c| c.is_ascii_lowercase()),
                "category {cat:?} returned non-snake_case id: {id}"
            );
            for c in id.chars() {
                assert!(
                    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_',
                    "category {cat:?} returned id with non-snake_case char: {id}"
                );
            }
        }
    }

    #[test]
    fn extract_custom_rule_id_rejects_emphasis_phrases() {
        // Built-in messages may be prefixed with `[high blast-radius]` or
        // `[Critical]` for emphasis. The strict shape filter must NOT
        // attribute those to a phantom custom rule.
        assert_eq!(extract_custom_rule_id("[high blast-radius] message"), None);
        assert_eq!(extract_custom_rule_id("[Critical] message"), None);
        assert_eq!(extract_custom_rule_id("[my-rule] message"), None); // dash
        assert_eq!(extract_custom_rule_id("[1pass] message"), None); // leading digit
        assert_eq!(extract_custom_rule_id("[] message"), None);
        assert_eq!(extract_custom_rule_id("no bracket"), None);

        // Canonical custom-rule ids ARE accepted.
        assert_eq!(extract_custom_rule_id("[my_rule] message"), Some("my_rule"));
        assert_eq!(
            extract_custom_rule_id("[r2_attack3] message"),
            Some("r2_attack3")
        );
        assert_eq!(extract_custom_rule_id("[v3check] message"), Some("v3check"));
        assert_eq!(
            extract_custom_rule_id("[no_prod_pat] hit"),
            Some("no_prod_pat")
        );
    }

    #[test]
    fn out_of_range_nodeid_does_not_collide() {
        // Two findings whose `nodes_involved` differ only by
        // out-of-range NodeId positions must NOT alias. Pre-v3 the
        // `filter_map(graph.node)` silently elided missing ids; v3
        // emits a `<missing:N>` sentinel.
        let graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        // No nodes added — every NodeId we pass below is out of range.
        let f_a = make_finding(FindingCategory::AuthorityCycle, "msg", vec![999_001]);
        let f_b = make_finding(FindingCategory::AuthorityCycle, "msg", vec![999_002]);
        let fp_a = compute_fingerprint(&f_a, &graph);
        let fp_b = compute_fingerprint(&f_b, &graph);
        assert_ne!(
            fp_a, fp_b,
            "out-of-range NodeId must NOT silently elide; sentinel must \
             differ across distinct ids"
        );
    }

    #[test]
    fn fingerprint_anchor_distinguishes_otherwise_identical_findings() {
        // Two findings of the same rule in the same file with NO graph
        // nodes — pre-v3 they collided. The v3 anchor field gives rules
        // with no natural graph node a per-finding discriminator.
        let graph = AuthorityGraph::new(source("azure-pipelines.yml"));
        let mut f_a = make_finding(
            FindingCategory::TemplateExtendsUnpinnedBranch,
            "ADO repo alias 'platform' resolves to mutable branch",
            vec![],
        );
        f_a.extras.fingerprint_anchor = Some("platform".to_string());
        let mut f_b = make_finding(
            FindingCategory::TemplateExtendsUnpinnedBranch,
            "ADO repo alias 'security-scan' resolves to mutable branch",
            vec![],
        );
        f_b.extras.fingerprint_anchor = Some("security-scan".to_string());
        assert_ne!(
            compute_fingerprint(&f_a, &graph),
            compute_fingerprint(&f_b, &graph),
            "same rule, same file, different anchor must produce distinct \
             fingerprints"
        );
    }

    // ── Golden fingerprints (pin the v3 algorithm contract) ─────────────
    //
    // Hand-computed v3 fingerprints for three (FindingCategory, graph
    // fixture) combinations. Any change to the algorithm — input set,
    // tag prefixes, separator, version label, truncation length — flips
    // these literals and forces a deliberate update + a CHANGELOG entry.
    // Do NOT update these literals casually.

    #[test]
    fn golden_authority_propagation_fingerprint() {
        let mut graph = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let secret = graph.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
        let step = graph.add_node(NodeKind::Step, "deploy[0]", TrustZone::Untrusted);
        let f = make_finding(
            FindingCategory::AuthorityPropagation,
            "AWS_KEY reaches deploy[0]",
            vec![secret, step],
        );
        let fp = compute_fingerprint(&f, &graph);
        assert_eq!(
            fp, "19cfd717b43ce7d3de5d6292eed1f635",
            "v3 golden authority_propagation fingerprint changed — update CHANGELOG and re-baseline downstream consumers before changing this literal"
        );
    }

    #[test]
    fn golden_floating_image_fingerprint() {
        let mut g = AuthorityGraph::new(source(".github/workflows/ci.yml"));
        let img = g.add_node(NodeKind::Image, "alpine:latest", TrustZone::ThirdParty);
        let f = make_finding(FindingCategory::FloatingImage, "msg-a", vec![img]);
        let fp = compute_fingerprint(&f, &g);
        assert_eq!(
            fp, "ceacd10b83991a7b4d607643f68d5131",
            "v3 golden floating_image fingerprint changed — update CHANGELOG \
             and re-baseline downstream consumers before changing this literal"
        );
    }

    #[test]
    fn golden_template_extends_unpinned_branch_fingerprint() {
        // Anchor-bearing finding (no graph nodes); pins the
        // `\x1fanchor=` segment behaviour.
        let graph = AuthorityGraph::new(source("azure-pipelines.yml"));
        let mut f = make_finding(
            FindingCategory::TemplateExtendsUnpinnedBranch,
            "ADO repo alias 'platform' resolves to mutable branch",
            vec![],
        );
        f.extras.fingerprint_anchor = Some("platform".to_string());
        let fp = compute_fingerprint(&f, &graph);
        assert_eq!(
            fp, "7ef16fae1dd4aff3986fe61b9903a186",
            "v3 golden template_extends_unpinned_branch fingerprint changed \
             — update CHANGELOG and re-baseline before changing this literal"
        );
    }
}

#[cfg(test)]
mod source_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn built_in_serializes_as_string() {
        let s = FindingSource::BuiltIn;
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v, serde_json::json!("built-in"));
    }

    #[test]
    fn custom_serializes_with_path_payload() {
        let s = FindingSource::Custom {
            source_file: PathBuf::from("/policies/no_prod_pat.yml"),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"custom": {"source_file": "/policies/no_prod_pat.yml"}})
        );
    }

    #[test]
    fn finding_round_trip_preserves_built_in_source() {
        let f = Finding {
            severity: Severity::High,
            category: FindingCategory::AuthorityPropagation,
            path: None,
            nodes_involved: vec![],
            message: "x".into(),
            recommendation: Recommendation::Manual {
                action: "fix".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        };
        let s = serde_json::to_string(&f).unwrap();
        // Encoded as the literal `"source":"built-in"` — operators eyeballing
        // raw JSON immediately see "this is a shipped rule".
        assert!(
            s.contains("\"source\":\"built-in\""),
            "built-in source must serialise as \"built-in\": {s}"
        );
        let f2: Finding = serde_json::from_str(&s).unwrap();
        assert_eq!(f2.source, FindingSource::BuiltIn);
    }

    #[test]
    fn finding_round_trip_preserves_custom_source_with_path() {
        let path = PathBuf::from("/work/invariants/no_prod_pat.yml");
        let f = Finding {
            severity: Severity::Critical,
            category: FindingCategory::AuthorityPropagation,
            path: None,
            nodes_involved: vec![],
            message: "[no_prod_pat] hit".into(),
            recommendation: Recommendation::Manual {
                action: "fix".into(),
            },
            source: FindingSource::Custom {
                source_file: path.clone(),
            },
            extras: FindingExtras::default(),
        };
        let s = serde_json::to_string(&f).unwrap();
        assert!(
            s.contains("\"custom\""),
            "custom source must serialise with `custom` key: {s}"
        );
        assert!(
            s.contains("/work/invariants/no_prod_pat.yml"),
            "custom source must include the loader path: {s}"
        );
        let f2: Finding = serde_json::from_str(&s).unwrap();
        assert_eq!(
            f2.source,
            FindingSource::Custom { source_file: path },
            "round-trip must preserve custom source path"
        );
    }

    #[test]
    fn missing_source_field_deserializes_as_built_in() {
        // Backward-compat: pre-provenance JSON omits the field entirely; the
        // serde default makes it `BuiltIn`. Without this, every old
        // suppression DB would fail to parse on upgrade.
        let json = r#"{
            "severity": "high",
            "category": "authority_propagation",
            "nodes_involved": [],
            "message": "old-format finding",
            "recommendation": {"type": "manual", "action": "review"}
        }"#;
        let f: Finding = serde_json::from_str(json).expect("legacy JSON must parse");
        assert_eq!(f.source, FindingSource::BuiltIn);
    }
}
