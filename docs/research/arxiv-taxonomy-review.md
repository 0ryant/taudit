# arXiv taudit taxonomy review

Date: 2026-06-01
Lane: R2
Scope: `docs/research/arxiv-taudit-rule-map.csv` rows with
`mapping_status=needs_author_review`

## Evidence ceiling

This is a source-local review artifact. It does not change the CSV map, does
not claim paper-author validation, and does not claim benchmark correctness.
Rows marked safe below are only safe to promote from `needs_author_review` to
`proposed` as taudit-side taxonomy recommendations.

Observed input count: 36 rows.

## Summary

| Group | Count | Use |
| --- | ---: | --- |
| Safe to promote to proposed | 15 | Direct enough to treat as source-local proposed mappings. |
| Keep needs author review | 10 | Plausible mapping, but class boundary or evidence strength still needs maintainer judgment. |
| Out of scope or needs method note | 11 | Do not count as direct paper-taxonomy coverage without an explicit method note or exclusion. |

## Safe to promote to proposed

These rows have a direct source-local fit to the mapped class, subject to the
evidence ceiling above.

| Rule ID | Proposed class | Rationale |
| --- | --- | --- |
| `oidc_identity_in_untrusted_context` | `PTW` | The finding is explicitly an untrusted trigger context reaching OIDC identity authority. |
| `cross_workflow_authority_chain` | `PTW` | Reusable workflow delegation carries secrets or identity into another callable authority boundary. |
| `authority_cycle` | `CFW` | The finding is a workflow delegation cycle, which is a control-flow/configuration failure. |
| `docker_socket_exposed_to_ci_step` | `GRCW` | Host Docker socket exposure gives a CI step runner-host authority. |
| `privileged_container_in_ci_step` | `GRCW` | Privileged container execution weakens the runner isolation boundary. |
| `pull_request_workflow_inconsistent_fork_check` | `CFW` | The finding is inconsistent fork-guard control flow on authority-bearing PR jobs. |
| `gha_workflow_run_artifact_report_to_pr_comment` | `AIW` | A privileged consumer trusts PR-context artifact report content before comment publication. |
| `gha_container_image_attacker_influenced_with_secret_env` | `UDW` | An attacker-influenced container image is dependency material under credential-bearing execution. |
| `gha_manifest_submodules_recursive_with_pr_authority` | `UDW` | PR-mutable `.gitmodules` controls recursive dependency checkout under authority. |
| `gha_manual_dispatch_ref_to_privileged_checkout` | `IW` | Operator input controls checkout ref selection inside a privileged job. |
| `homoglyph_in_action_ref` | `UDW` | Confusable action identity is a dependency identity weakness. |
| `gha_tool_installer_then_shell_helper_authority` | `IW` | Installed helper resolution flows into workflow-authored shell execution with authority. |
| `gha_identity_cosign_certificate_identity_repo_only_no_ref` | `AIW` | Artifact verification accepts repo-only identity without ref binding. |
| `gha_runner_lifecycle_self_hosted_pr_no_isolation` | `GRCW` | PR-triggered self-hosted runner execution lacks workspace/process isolation. |
| `gha_verifier_gh_attestation_missing_source_digest_check` | `AIW` | Attestation verification lacks local artifact digest binding. |

## Keep needs author review

These rows are plausible, but should stay `needs_author_review` until a
maintainer chooses the class boundary.

| Rule ID | Current class | Rationale |
| --- | --- | --- |
| `uplift_without_attestation` | `HGW` | The rule is explicitly Info-level and lacks an immediate exploitation path; decide whether missing provenance attestation counts as HGW coverage or advisory-only evidence. |
| `long_lived_secret_without_oidc_recommendation` | `HGW` | This is an OIDC migration recommendation layered on an existing static-secret finding; avoid double-counting it as a separate weakness without review. |
| `gha_post_ambient_env_cleanup_path` | `IW` | Cleanup-path retargeting via ambient env is injection-adjacent, but the affected sink is a post-cleanup path rather than ordinary command/script execution. |
| `gha_setup_node_cache_helper_path_handoff` | `AIW` | Cache helper PATH handoff is source-led hardening evidence; decide whether it is artifact integrity or helper-resolution exposure. |
| `gha_setup_python_cache_helper_path_handoff` | `AIW` | Same cache-helper boundary as setup-node, with Python helper resolution. |
| `gha_setup_go_cache_helper_path_handoff` | `AIW` | Same cache-helper boundary as setup-node, with Go helper resolution. |
| `gha_setup_python_pip_install_authority_env` | `SEW` | Ambient credential authority around package install is not the same as observed secret exposure. |
| `gha_workflow_shell_authority_concentration` | `EPW` | Shell authority concentration may indicate risky design, but it is not necessarily excessive permission scope. |
| `gha_docker_setup_qemu_privileged_docker_helper` | `GRCW` | Docker helper privilege is runner-related, but the finding is helper-boundary and PATH-shape dependent. |
| `gha_docker_buildx_authority_path_handoff` | `GRCW` | Docker Buildx authority handoff is runner-adjacent, but also helper-resolution and build-secret boundary evidence. |

## Out of scope or needs method note

These rows should either stay out of detection-volume counts or be counted only
with an explicit method note explaining the taudit-specific extension.

| Rule ID | Current class | Recommendation | Rationale |
| --- | --- | --- | --- |
| `gha_telemetry_pr_or_issue_text_to_external_sink` | `out_of_scope` | Keep out of scope. | Telemetry of untrusted text to an external sink is not a direct paper-taxonomy class. |
| `gha_crossforge_mirror_checkout_with_token_push` | `out_of_scope` | Keep out of scope. | Cross-forge mirror mutation is a repository-boundary concern outside the direct paper classes. |
| `gha_telemetry_autonomous_agent_input_from_untrusted_event` | `IW` | Needs method note. | Counting prompt injection as `IW` requires saying the method extends injection to autonomous-agent inputs. |
| `gha_api_workflow_run_artifact_to_autonomous_agent_to_git_push` | `AIW` | Needs method note. | The chain starts with a workflow-run artifact but the exploit model depends on autonomous-agent interpretation and later git/API mutation. |
| `gha_pulumi_path_resolved_cli_with_authority` | `SEW` | Needs method note. | The rule observes PATH-resolved helper authority, not direct secret disclosure. |
| `gha_pypi_publish_oidc_after_path_mutation` | `SEW` | Needs method note. | The rule observes publish/OIDC authority after PATH mutation, not direct secret disclosure. |
| `gha_changesets_publish_command_with_authority` | `SEW` | Needs method note. | The rule models package-manager helper authority rather than observed secret exposure. |
| `gha_rubygems_release_git_token_and_oidc_helper` | `SEW` | Needs method note. | The rule models helper authority under release credentials, not direct secret exposure. |
| `gha_datadog_test_visibility_installer_authority` | `SEW` | Needs method note. | The rule models installer/runtime helper authority under API-key scope, not direct secret exposure. |
| `gha_crossrepo_org_credential_multiplexing` | `PTW` | Needs method note. | This is an aggregate multi-repo blast-radius finding; paper-style per-workflow counts need a stated aggregation policy. |
| `gha_temporal_oidc_freshness_across_multistep_build` | `HGW` | Needs method note. | Static evidence can flag OIDC freshness risk, but token lifetime and cache behavior partly depend on provider/runtime state. |

## Residual risks

- The paper-author taxonomy has not been revalidated by the authors.
- `PTW` is retained as the canonical paper label while the upstream raw CSV label
  may be `TMW`; this artifact does not resolve that naming mismatch.
- Rows in the method-note group may be valuable taudit findings but should not
  inflate paper-taxonomy coverage without a written methodology deviation.
- This review did not inspect full-corpus emissions, FP/FN labels, or upstream
  benchmark inclusion status.
