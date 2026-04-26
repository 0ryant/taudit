# taudit Rule Reference

61 built-in rules. Run `taudit explain <rule-id>` for a description in the terminal.

## Top-level commands

| Command | Purpose |
|---------|---------|
| `taudit scan` | Run the 61 built-in rules (and optional custom rules via `--rules-dir`); produces a report. |
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
| [secret_materialised_to_workspace_file](secret_materialised_to_workspace_file.md) | High | Credentials | ADO only |
| [keyvault_secret_to_plaintext](keyvault_secret_to_plaintext.md) | Medium | Credentials | ADO only |
| [terraform_auto_approve_in_prod](terraform_auto_approve_in_prod.md) | Critical | Configuration | ADO only |
| [addspn_with_inline_script](addspn_with_inline_script.md) | High | Credentials | ADO only |
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
| [risky_trigger_with_authority](risky_trigger_with_authority.md) | High | Privilege | GHA |
| [sensitive_value_in_job_output](sensitive_value_in_job_output.md) | Critical / High | Credentials | GHA |
| [manual_dispatch_input_to_url_or_command](manual_dispatch_input_to_url_or_command.md) | High | Injection | GHA |
| [secrets_inherit_overscoped_passthrough](secrets_inherit_overscoped_passthrough.md) | High | Privilege | GHA |
| [unsafe_pr_artifact_in_workflow_run_consumer](unsafe_pr_artifact_in_workflow_run_consumer.md) | High | Supply Chain | GHA |
| [script_injection_via_untrusted_context](script_injection_via_untrusted_context.md) | Critical | Injection | GHA |
| [interactive_debug_action_in_authority_workflow](interactive_debug_action_in_authority_workflow.md) | High | Credentials | GHA |
| [pr_specific_cache_key_in_default_branch_consumer](pr_specific_cache_key_in_default_branch_consumer.md) | High | Supply Chain | GHA |
| [gh_cli_with_default_token_escalating](gh_cli_with_default_token_escalating.md) | High | Privilege | GHA |
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

The 52 rules above are taudit's **built-in authority invariants** —
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
