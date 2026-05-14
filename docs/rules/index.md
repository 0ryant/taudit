# taudit Rule Reference

Built-in rule definitions are registered for `taudit explain`. The table below is the customer-facing rule catalogue; `gha_toolcache_absolute_path_downgrade` is a precision guard documented so helper-PATH findings do not over-fire. Run `taudit explain` to inspect the current catalogue, or `taudit explain <rule-id>` for a description in the terminal.

## Top-level commands

| Command | Purpose |
|---------|---------|
| `taudit scan` | Run the emitting built-in rules (and optional custom rules via `--rules-dir`); produces a report. |
| [`taudit verify`](../verify.md) | Policy-driven enforcement entrypoint for CI gates. Exit 0 = clean, 1 = violation, 2 = config error. Runs only `--policy` invariants by default. |
| `taudit map` | Render the authority graph (text table or DOT). |
| `taudit diff` | Compare findings between two pipeline versions. |
| `taudit explain` | Describe one or all built-in rules. |

Platforms: **GHA** = GitHub Actions · **ADO** = Azure DevOps · **GL** = GitLab CI

| Rule | Severity | Category | Platform |
|------|----------|----------|----------|
| [authority_propagation](authority_propagation.md) | Critical / High | Propagation | GHA, ADO, GL |
| [over_privileged_identity](over_privileged_identity.md) | High | Privilege | GHA, ADO, GL |
| [unpinned_action](unpinned_action.md) | High | Supply Chain | GHA, ADO |
| [homoglyph_in_action_ref](homoglyph_in_action_ref.md) | High | Supply Chain | GHA only |
| [untrusted_with_authority](untrusted_with_authority.md) | Critical / Info | Propagation | GHA, ADO, GL |
| [artifact_boundary_crossing](artifact_boundary_crossing.md) | High | Supply Chain | GHA, ADO, GL |
| [floating_image](floating_image.md) | Medium | Supply Chain | GHA, ADO, GL |
| [long_lived_credential](long_lived_credential.md) | High | Credentials | GHA, ADO, GL |
| [persisted_credential](persisted_credential.md) | Critical | Credentials | GHA |
| [trigger_context_mismatch](trigger_context_mismatch.md) | Critical / High | Privilege | GHA, ADO, GL |
| [cross_workflow_authority_chain](cross_workflow_authority_chain.md) | Critical | Propagation | GHA, ADO |
| [authority_cycle](authority_cycle.md) | High | Configuration | GHA, ADO |
| [uplift_without_attestation](uplift_without_attestation.md) | Info | Supply Chain | GHA, ADO |
| [self_mutating_pipeline](self_mutating_pipeline.md) | Critical / High / Medium | Injection | GHA, ADO |
| [checkout_self_pr_exposure](checkout_self_pr_exposure.md) | High | Supply Chain | GHA, ADO |
| [variable_group_in_pr_job](variable_group_in_pr_job.md) | Critical | Privilege | ADO only |
| [self_hosted_pool_pr_hijack](self_hosted_pool_pr_hijack.md) | Critical | Injection | ADO only |
| [shared_self_hosted_pool_no_isolation](shared_self_hosted_pool_no_isolation.md) | High | Injection | ADO only |
| [service_connection_scope_mismatch](service_connection_scope_mismatch.md) | High | Privilege | ADO only |
| [template_extends_unpinned_branch](template_extends_unpinned_branch.md) | High | Supply Chain | ADO only |
| [template_repo_ref_is_feature_branch](template_repo_ref_is_feature_branch.md) | High | Supply Chain | ADO only |
| [vm_remote_exec_via_pipeline_secret](vm_remote_exec_via_pipeline_secret.md) | High | Credentials | ADO only |
| [short_lived_sas_in_command_line](short_lived_sas_in_command_line.md) | Medium | Credentials | ADO only |
| [secret_to_inline_script_env_export](secret_to_inline_script_env_export.md) | High | Credentials | ADO only |
| [setvariable_issecret_false](setvariable_issecret_false.md) | High | Credentials | ADO only |
| [secret_materialised_to_workspace_file](secret_materialised_to_workspace_file.md) | High | Credentials | ADO only |
| [keyvault_secret_to_plaintext](keyvault_secret_to_plaintext.md) | Medium | Credentials | ADO only |
| [terraform_auto_approve_in_prod](terraform_auto_approve_in_prod.md) | Critical | Configuration | ADO only |
| [add_spn_with_inline_script](add_spn_with_inline_script.md) | High | Credentials | ADO only |
| [parameter_interpolation_into_shell](parameter_interpolation_into_shell.md) | Medium | Injection | ADO only |
| [terraform_output_via_setvariable_shell_expansion](terraform_output_via_setvariable_shell_expansion.md) | High | Injection | ADO only |
| [secret_via_env_gate_to_untrusted_consumer](secret_via_env_gate_to_untrusted_consumer.md) | Critical | Propagation | GHA |
| [no_workflow_level_permissions_block](no_workflow_level_permissions_block.md) | Medium | Configuration | GHA only |
| [prod_deploy_job_no_environment_gate](prod_deploy_job_no_environment_gate.md) | High | Privilege | ADO only |
| [long_lived_secret_without_oidc_recommendation](long_lived_secret_without_oidc_recommendation.md) | Info | Credentials | GHA, ADO, GL |
| [pull_request_workflow_inconsistent_fork_check](pull_request_workflow_inconsistent_fork_check.md) | High / Medium | Privilege | GHA only |
| [gitlab_deploy_job_missing_protected_branch_only](gitlab_deploy_job_missing_protected_branch_only.md) | Medium | Configuration | GitLab only |
| [runtime_script_fetched_from_floating_url](runtime_script_fetched_from_floating_url.md) | High | Injection / Supply Chain | GHA |
| [pr_trigger_with_floating_action_ref](pr_trigger_with_floating_action_ref.md) | Critical | Privilege / Supply Chain | GHA |
| [untrusted_api_response_to_env_sink](untrusted_api_response_to_env_sink.md) | High | Injection | GHA |
| [pr_build_pushes_image_with_floating_credentials](pr_build_pushes_image_with_floating_credentials.md) | High | Supply Chain / Credentials | GHA |
| [gha_helper_path_sensitive_argv](gha_helper_path_sensitive_argv.md) | High | Credentials | GHA |
| [gha_helper_path_sensitive_stdin](gha_helper_path_sensitive_stdin.md) | High | Credentials | GHA |
| [gha_helper_path_sensitive_env](gha_helper_path_sensitive_env.md) | High | Credentials | GHA |
| [gha_post_ambient_env_cleanup_path](gha_post_ambient_env_cleanup_path.md) | Medium | Cleanup | GHA |
| [gha_action_minted_secret_to_helper](gha_action_minted_secret_to_helper.md) | High | Credentials | GHA |
| [gha_helper_untrusted_path_resolution](gha_helper_untrusted_path_resolution.md) | Medium | Supply Chain | GHA |
| [gha_secret_output_after_helper_login](gha_secret_output_after_helper_login.md) | High | Credentials | GHA |
| [later_secret_materialized_after_path_mutation](later_secret_materialized_after_path_mutation.md) | High | Credentials | GHA |
| [gha_setup_node_cache_helper_path_handoff](gha_setup_node_cache_helper_path_handoff.md) | Medium | Cache | GHA |
| [gha_setup_python_cache_helper_path_handoff](gha_setup_python_cache_helper_path_handoff.md) | Medium | Cache | GHA |
| [gha_setup_python_pip_install_authority_env](gha_setup_python_pip_install_authority_env.md) | Medium | Credentials | GHA |
| [gha_setup_go_cache_helper_path_handoff](gha_setup_go_cache_helper_path_handoff.md) | Medium | Cache | GHA |
| [gha_docker_setup_qemu_privileged_docker_helper](gha_docker_setup_qemu_privileged_docker_helper.md) | High | Docker | GHA |
| [gha_tool_installer_then_shell_helper_authority](gha_tool_installer_then_shell_helper_authority.md) | Medium | Workflow Shell | GHA |
| [gha_workflow_shell_authority_concentration](gha_workflow_shell_authority_concentration.md) | Medium | Workflow Shell | GHA |
| [gha_action_token_env_before_bare_download_helper](gha_action_token_env_before_bare_download_helper.md) | High | Credentials | GHA |
| [gha_post_action_input_retarget_to_cache_save](gha_post_action_input_retarget_to_cache_save.md) | Medium | Cache | GHA |
| [gha_terraform_wrapper_sensitive_output](gha_terraform_wrapper_sensitive_output.md) | Medium | Credentials | GHA |
| [gha_composite_bare_helper_after_path_install_with_secret_env](gha_composite_bare_helper_after_path_install_with_secret_env.md) | Medium | Workflow Shell | GHA |
| [gha_pulumi_path_resolved_cli_with_authority](gha_pulumi_path_resolved_cli_with_authority.md) | High | Credentials | GHA |
| [gha_pypi_publish_oidc_after_path_mutation](gha_pypi_publish_oidc_after_path_mutation.md) | High | Credentials | GHA |
| [gha_changesets_publish_command_with_authority](gha_changesets_publish_command_with_authority.md) | High | Credentials | GHA |
| [gha_rubygems_release_git_token_and_oidc_helper](gha_rubygems_release_git_token_and_oidc_helper.md) | High | Credentials | GHA |
| [gha_composite_entrypoint_path_shadow_with_secret_env](gha_composite_entrypoint_path_shadow_with_secret_env.md) | Medium | Workflow Shell | GHA |
| [gha_docker_buildx_authority_path_handoff](gha_docker_buildx_authority_path_handoff.md) | High | Docker | GHA |
| [gha_google_deploy_gcloud_credential_path](gha_google_deploy_gcloud_credential_path.md) | High | Credentials | GHA |
| [gha_datadog_test_visibility_installer_authority](gha_datadog_test_visibility_installer_authority.md) | Medium | Credentials | GHA |
| [gha_kubernetes_helper_kubeconfig_authority](gha_kubernetes_helper_kubeconfig_authority.md) | High | Kubernetes | GHA |
| [gha_azure_companion_helper_authority](gha_azure_companion_helper_authority.md) | High | Azure | GHA |
| [gha_create_pr_git_token_path_handoff](gha_create_pr_git_token_path_handoff.md) | High | Credentials | GHA |
| [gha_import_gpg_private_key_helper_path](gha_import_gpg_private_key_helper_path.md) | High | Credentials | GHA |
| [gha_ssh_agent_private_key_to_path_helper](gha_ssh_agent_private_key_to_path_helper.md) | High | Credentials | GHA |
| [gha_macos_codesign_cert_security_path](gha_macos_codesign_cert_security_path.md) | High | Credentials | GHA |
| [gha_pages_deploy_token_url_to_git_helper](gha_pages_deploy_token_url_to_git_helper.md) | High | Credentials | GHA |
| [gha_manifest_npm_lifecycle_hook_pr_trigger_with_token](gha_manifest_npm_lifecycle_hook_pr_trigger_with_token.md) | High | Manifest-as-Code | GHA |
| [gha_manifest_python_m_build_with_pr_credentials](gha_manifest_python_m_build_with_pr_credentials.md) | High | Manifest-as-Code | GHA |
| [gha_manifest_cargo_build_rs_pull_request_with_token](gha_manifest_cargo_build_rs_pull_request_with_token.md) | High | Manifest-as-Code | GHA |
| [gha_manifest_makefile_with_pr_trigger_and_secrets](gha_manifest_makefile_with_pr_trigger_and_secrets.md) | High | Manifest-as-Code | GHA |
| [gha_manifest_submodules_recursive_with_pr_authority](gha_manifest_submodules_recursive_with_pr_authority.md) | High | Manifest-as-Code | GHA |
| [gha_crossrepo_workflow_call_floating_ref_cascade](gha_crossrepo_workflow_call_floating_ref_cascade.md) | High | Manifest-as-Code | GHA |
| [gha_crossrepo_secrets_inherit_unreviewed_callee](gha_crossrepo_secrets_inherit_unreviewed_callee.md) | High | Manifest-as-Code | GHA |
| [gha_toolcache_absolute_path_downgrade](gha_toolcache_absolute_path_downgrade.md) | Info | Precision | GHA |
| [risky_trigger_with_authority](risky_trigger_with_authority.md) | High | Privilege | GHA |
| [sensitive_value_in_job_output](sensitive_value_in_job_output.md) | Critical / High | Credentials | GHA |
| [manual_dispatch_input_to_url_or_command](manual_dispatch_input_to_url_or_command.md) | High | Injection | GHA |
| [secrets_inherit_overscoped_passthrough](secrets_inherit_overscoped_passthrough.md) | High | Privilege | GHA |
| [unsafe_pr_artifact_in_workflow_run_consumer](unsafe_pr_artifact_in_workflow_run_consumer.md) | High | Supply Chain | GHA |
| [script_injection_via_untrusted_context](script_injection_via_untrusted_context.md) | Critical | Injection | GHA |
| [interactive_debug_action_in_authority_workflow](interactive_debug_action_in_authority_workflow.md) | High | Credentials | GHA |
| [pr_specific_cache_key_in_default_branch_consumer](pr_specific_cache_key_in_default_branch_consumer.md) | High | Supply Chain | GHA |
| [gh_cli_with_default_token_escalating](gh_cli_with_default_token_escalating.md) | High | Privilege | GHA |
| [gha_script_injection_to_privileged_shell](gha_script_injection_to_privileged_shell.md) | Critical | Injection | GHA |
| [gha_workflow_run_artifact_poisoning_to_privileged_consumer](gha_workflow_run_artifact_poisoning_to_privileged_consumer.md) | Critical | Artifact | GHA |
| [gha_remote_script_in_authority_job](gha_remote_script_in_authority_job.md) | Critical | Supply Chain | GHA |
| [gha_pat_remote_url_write](gha_pat_remote_url_write.md) | High | Credentials | GHA |
| [gha_workflow_run_artifact_metadata_to_privileged_api](gha_workflow_run_artifact_metadata_to_privileged_api.md) | High | Artifact | GHA |
| [gha_workflow_run_artifact_report_to_pr_comment](gha_workflow_run_artifact_report_to_pr_comment.md) | High | Artifact | GHA |
| [gha_workflow_run_artifact_to_build_scan_publish](gha_workflow_run_artifact_to_build_scan_publish.md) | High | Artifact | GHA |
| [gha_floating_remote_script_before_publish_sink](gha_floating_remote_script_before_publish_sink.md) | High | Supply Chain | GHA |
| [gha_token_remote_url_with_trace_or_process_exposure](gha_token_remote_url_with_trace_or_process_exposure.md) | High | Credentials | GHA |
| [gha_env_credential_helper_config_redirect_before_authority](gha_env_credential_helper_config_redirect_before_authority.md) | High | Credentials | GHA |
| [gha_env_node_options_code_injection_before_node_authority](gha_env_node_options_code_injection_before_node_authority.md) | High | Injection | GHA |
| [gha_env_dyld_or_ld_library_path_before_credential_helper](gha_env_dyld_or_ld_library_path_before_credential_helper.md) | High | Injection | GHA |
| [gha_workflow_call_container_image_input_secrets_inherit](gha_workflow_call_container_image_input_secrets_inherit.md) | High | Privilege | GHA |
| [gha_workflow_call_runner_label_input_privilege_escalation](gha_workflow_call_runner_label_input_privilege_escalation.md) | High | Privilege | GHA |
| [gha_container_image_attacker_influenced_with_secret_env](gha_container_image_attacker_influenced_with_secret_env.md) | High | Supply Chain | GHA |
| [gha_attestation_subject_digest_from_step_output_unverified](gha_attestation_subject_digest_from_step_output_unverified.md) | High | Attestation | GHA |
| [gha_attestation_subject_path_workspace_glob_with_pr_trigger](gha_attestation_subject_path_workspace_glob_with_pr_trigger.md) | High | Attestation | GHA |
| [gha_attestation_config_driven_gate_from_workspace_file](gha_attestation_config_driven_gate_from_workspace_file.md) | High | Attestation | GHA |
| [gha_telemetry_pr_or_issue_text_to_external_sink](gha_telemetry_pr_or_issue_text_to_external_sink.md) | Medium | Telemetry | GHA |
| [gha_telemetry_debug_flag_with_secret_env](gha_telemetry_debug_flag_with_secret_env.md) | High | Telemetry | GHA |
| [gha_telemetry_autonomous_agent_input_from_untrusted_event](gha_telemetry_autonomous_agent_input_from_untrusted_event.md) | High | Autonomous Agent | GHA |
| [gha_workflow_run_artifact_to_blob_storage_token](gha_workflow_run_artifact_to_blob_storage_token.md) | High | Artifact | GHA |
| [gha_api_workflow_run_artifact_to_autonomous_agent_to_git_push](gha_api_workflow_run_artifact_to_autonomous_agent_to_git_push.md) | High | Autonomous Agent | GHA |
| [gha_issue_comment_command_to_write_token](gha_issue_comment_command_to_write_token.md) | High | Privilege | GHA |
| [gha_pr_build_pushes_publishable_image](gha_pr_build_pushes_publishable_image.md) | High | Supply Chain | GHA |
| [gha_manual_dispatch_ref_to_privileged_checkout](gha_manual_dispatch_ref_to_privileged_checkout.md) | High | Injection | GHA |
| [ci_job_token_to_external_api](ci_job_token_to_external_api.md) | High | Credentials | GitLab CI |
| [id_token_audience_overscoped](id_token_audience_overscoped.md) | High | Privilege | GitLab CI |
| [untrusted_ci_var_in_shell_interpolation](untrusted_ci_var_in_shell_interpolation.md) | High | Injection | GitLab CI |
| [unpinned_include_remote_or_branch_ref](unpinned_include_remote_or_branch_ref.md) | High | Supply Chain | GitLab CI |
| [dind_service_grants_host_authority](dind_service_grants_host_authority.md) | High | Isolation | GitLab CI |
| [security_job_silently_skipped](security_job_silently_skipped.md) | Medium | Supply Chain | GitLab CI |
| [child_pipeline_trigger_inherits_authority](child_pipeline_trigger_inherits_authority.md) | High | Privilege | GitLab CI |
| [cache_key_crosses_trust_boundary](cache_key_crosses_trust_boundary.md) | High | Supply Chain | GitLab CI |
| [pat_embedded_in_git_remote_url](pat_embedded_in_git_remote_url.md) | High | Credentials | GitLab CI |
| [ci_token_triggers_downstream_with_variable_passthrough](ci_token_triggers_downstream_with_variable_passthrough.md) | Medium | Propagation | GitLab CI |
| [dotenv_artifact_flows_to_privileged_deployment](dotenv_artifact_flows_to_privileged_deployment.md) | High | Propagation | GitLab CI |

## Severity key

| Severity | CVSS range | Meaning |
|----------|-----------|---------|
| Critical | 9.0–10.0 | Active exploitation path — fix immediately |
| High | 7.0–8.9 | Significant risk — fix within the sprint |
| Medium | 4.0–6.9 | Real risk but requires additional conditions |
| Low | 0.1–3.9 | Hygiene finding — low direct exploit potential |
| Info | 0.0 | Best-practice gap — no immediate risk |

Rules marked **ADO only** fire exclusively on Azure DevOps pipeline YAML.
All other rules fire on both GitHub Actions and Azure DevOps.

## Severity graduation

Several rules graduate severity based on context rather than emitting a fixed level:

- **authority_propagation** — Critical for untrusted sinks or OIDC sources; High for SHA-pinned third-party sinks; Medium for SHA-pinned sink with constrained (read-only) identity. Downgraded one step when the propagation path crosses an ADO environment approval gate.
- **untrusted_with_authority** — Critical for explicit secrets and service connections; Info for ADO `System.AccessToken` (platform-injected, structural).
- **trigger_context_mismatch** — Critical for `pull_request_target`; High for ADO `pr:` trigger.
- **self_mutating_pipeline** — Critical for untrusted steps; High when the step also holds secrets or identity; Medium otherwise.
- **cross_workflow_authority_chain** — Critical for Untrusted target workflows; High for ThirdParty.
- **over_privileged_identity** — High for Broad scope; Medium for Unknown scope. Suppressed to Info when the workflow's broad GITHUB_TOKEN is narrowed by a per-job `permissions:` override (the runtime identity is the narrower one).
- **terraform_auto_approve_in_prod** — Critical when no environment gate; downgraded to Medium when the job has any `environment:` binding (gate's approver list is invisible from YAML, so the finding stays visible at lower severity).
- **checkout_self_pr_exposure** — High when the same job has any privileged step (secret/identity access or env-gate write); downgraded to Info when the job has none (checkout is read-only for lint/test/analysis).
- **trigger_context_mismatch** — Critical for `pull_request_target` and High for ADO `pr:` (as above), then downgraded one tier when every privileged step in the workflow carries the standard fork-check `if:`.
- **pull_request_workflow_inconsistent_fork_check** — High when 2+ privileged jobs are unguarded; Medium when only one is.

---

## Authority invariants

The rule definitions above are taudit's **built-in authority invariants** —
declarative properties the authority graph must satisfy. You can extend
this set with **custom authority invariants**: YAML files loaded with
`taudit scan --invariants-dir <path>` that evaluate against the same
propagation paths as the built-ins.

Use `taudit invariants list [--invariants-dir <path>]` to print every
invariant that will run on the next scan (built-in plus custom).

- **Concept, schema, and predicate reference** → [Authority Invariants](../authority-invariants.md)
- **Starter library** (5 copy-and-edit examples) → [`invariants/starter/`](../../invariants/starter/)

> The previous name for this feature was *custom rules*; `--rules-dir` is
> preserved as a permanent alias for `--invariants-dir`.
