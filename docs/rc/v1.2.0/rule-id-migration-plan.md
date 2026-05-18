# v1.2.0-rc.1 Rule ID Migration / Alias Plan

Status: L4-10 plan and backcompat probe for helper-authority rule IDs.

## Inputs

- [ADR 0005](../../adr/0005-authority-edge-classifier-and-witness-handoff.md) says some helper rules may need migration or aliases as ADR 0005 canonicalizes helper-resolution authority edges.
- [ADR 0011](../../adr/0011-ordered-authority-evidence-model.md) makes ordered helper evidence the rule contract: prior mutable channel, later authority materialization, helper execution, and authority transport.
- [ADR 0012](../../adr/0012-public-output-identity-contract.md) makes `rule_id` public identity owned by L4 core and projected by JSON, SARIF, CloudEvents, baselines, suppressions, and terminal triage.
- [L4-05/L4-10](code-complete-lanes.md) require helper rules to avoid PATH-only findings and require migration or aliasing for any canonical helper-rule rename.
- Current implementation evidence: `crates/taudit-core/src/finding.rs::rule_id_for` and `category_rule_id`.

## Current Helper-Rule ID Inventory

Do not rename these IDs for v1.2.0-rc.1. Treat them as the public IDs currently emitted by `rule_id_for`.

| Current ID | Role | Rename risk | L4-10 decision |
| --- | --- | --- | --- |
| `gha_helper_path_sensitive_argv` | Transport-specific helper authority via argv | Could be renamed to a longer ADR 0005 transport name. | Keep. Existing ID is concise, transport-specific, and customer-facing. |
| `gha_helper_path_sensitive_stdin` | Transport-specific helper authority via stdin | Same transport-name temptation. | Keep. |
| `gha_helper_path_sensitive_env` | Transport-specific helper authority via env | Same transport-name temptation. | Keep. |
| `gha_action_minted_secret_to_helper` | Action-minted secret reaches helper | Could be folded into transport-specific helper rules. | Keep unless semantics are fully subsumed; otherwise old ID becomes an alias. |
| `gha_helper_untrusted_path_resolution` | Helper resolves through an untrusted path | Could be renamed into ordered-evidence umbrella language. | Keep as the path-resolution-specific ID. |
| `gha_secret_output_after_helper_login` | Helper login emits a secret output | Could be renamed into origin/transport language. | Keep as the login-output-specific ID. |
| `later_secret_materialized_after_path_mutation` | Shared ordered-evidence timing predicate surfaced as a rule ID | ADR 0005 backlog names a canonical umbrella shape, which could tempt a rename. | Keep current emitted ID; document any future umbrella name as an alias unless a major-version break is approved. |
| `gha_setup_node_cache_helper_path_handoff` | setup-node cache helper handoff | Could be folded into a generic cache-helper rule. | Keep unless semantics merge; if merged, old ID becomes an accepted alias. |
| `gha_setup_python_cache_helper_path_handoff` | setup-python cache helper handoff | Could be folded into a generic cache-helper rule. | Keep unless semantics merge; if merged, old ID becomes an accepted alias. |
| `gha_setup_python_pip_install_authority_env` | setup-python pip-install with authority env | Could be renamed toward transport/origin language. | Keep. |
| `gha_setup_go_cache_helper_path_handoff` | setup-go cache helper handoff | Could be folded into generic cache-helper language. | Keep unless semantics merge; if merged, old ID becomes an accepted alias. |
| `gha_docker_setup_qemu_privileged_docker_helper` | Docker/QEMU helper authority | Could be folded into a generic Docker-helper rule. | Keep. |
| `gha_tool_installer_then_shell_helper_authority` | Installer-to-shell helper authority | Could be split by helper name. | Keep as canonical; individual helpers remain match variants, not rule IDs. |
| `gha_workflow_shell_authority_concentration` | Broad workflow-shell authority classifier | Could be split by sink name. | Keep as canonical bucket; sink names remain match variants unless a new rule has distinct semantics. |
| `gha_action_token_env_before_bare_download_helper` | Token env before bare download helper | Could be folded into env/config redirect family. | Keep unless a future semantic merge has an explicit alias entry. |
| `gha_composite_bare_helper_after_path_install_with_secret_env` | Composite helper after path install with secret env | Could be shortened aesthetically. | Keep; every token carries the handoff shape. |
| `gha_pulumi_path_resolved_cli_with_authority` | Pulumi CLI authority through path resolution | Could be folded into generic deploy helper rule. | Keep as product-specific helper sink. |
| `gha_pypi_publish_oidc_after_path_mutation` | PyPI publish with OIDC after path mutation | Could be folded into package-publish helper bucket. | Keep as package/ecosystem-specific rule. |
| `gha_changesets_publish_command_with_authority` | Changesets publish command under authority | Could be folded into workflow-shell authority. | Keep unless semantics are intentionally merged. |
| `gha_rubygems_release_git_token_and_oidc_helper` | RubyGems release helper with git token/OIDC | Could be folded into package-publish helper bucket. | Keep as ecosystem-specific rule. |
| `gha_composite_entrypoint_path_shadow_with_secret_env` | Composite entrypoint path shadow with secret env | Could be renamed into generic path-shadow language. | Keep as composite-entrypoint-specific rule. |
| `gha_docker_buildx_authority_path_handoff` | Docker Buildx authority path handoff | Could be folded into Docker-helper rule. | Keep as Buildx-specific rule. |
| `gha_google_deploy_gcloud_credential_path` | gcloud deploy credential path | Could be folded into cloud-helper bucket. | Keep as product-specific helper sink. |
| `gha_datadog_test_visibility_installer_authority` | Datadog installer authority | Could be folded into installer authority rule. | Keep as product-specific helper sink. |
| `gha_kubernetes_helper_kubeconfig_authority` | Kubernetes helper with kubeconfig authority | Could be folded into deploy-helper bucket. | Keep as deploy-helper-specific rule. |
| `gha_azure_companion_helper_authority` | Azure companion helper authority | Could be folded into cloud-helper bucket. | Keep as product-specific helper sink. |
| `gha_create_pr_git_token_path_handoff` | create-pull-request git token path handoff | Could be folded into git-helper bucket. | Keep as action/product-specific rule. |
| `gha_import_gpg_private_key_helper_path` | GPG private-key helper path | Could be folded into signing-helper bucket. | Keep as signing-helper-specific rule. |
| `gha_ssh_agent_private_key_to_path_helper` | SSH private key to path helper | Could be folded into credential-file helper bucket. | Keep as SSH-specific rule. |
| `gha_macos_codesign_cert_security_path` | macOS codesign cert/security path | Could be folded into signing-helper bucket. | Keep as platform/product-specific rule. |
| `gha_pages_deploy_token_url_to_git_helper` | Pages deploy token URL to git helper | Could be folded into git-helper bucket. | Keep as product-specific rule. |
| `gha_env_credential_helper_config_redirect_before_authority` | credential-helper config redirect before authority | Could be folded into helper path rules. | Keep as env/config redirect rule. |
| `gha_env_node_options_code_injection_before_node_authority` | NODE_OPTIONS code injection before Node authority | Could be folded into env/config redirect family. | Keep as Node-specific env authority rule. |
| `gha_env_dyld_or_ld_library_path_before_credential_helper` | dynamic-library path before credential helper | Could be folded into generic path authority language. | Keep as loader-path-specific helper rule. |

Catalog-only aliases from research, such as `gha_sigstore_helper_after_installer_path`, `gha_cosign_sign_oidc_with_mutable_path`, and `gha_gh_release_token_to_mutable_path_helper`, remain suppressed/catalog aliases. They must not appear as emitted built-in rule IDs in v1.2.0-rc.1.

## Alias And Migration Policy

Default policy: keep the first public helper-rule ID unless the current name is materially wrong. Aesthetic improvements do not justify a rename because `rule_id` participates in public identity.

If a same-semantics rename is proposed during 1.x:

1. Keep emitting the old ID from `rule_id_for`.
2. Add the new name only as a docs/search/explain alias.
3. Do not feed alias names into fingerprint, suppression-key, or finding-group computation.
4. Add tests proving old emitted IDs remain stable.

If a semantic split creates a genuinely new rule:

1. Emit a new rule ID only for the new semantic shape.
2. Keep the old ID for the old shape where it still exists.
3. Do not silently migrate old suppressions or baselines to the new rule; require an explicit operator re-baseline or future migration command.
4. Document old-to-new relationships in rule docs and release notes.

If a breaking rename is unavoidable:

1. Require a major-version decision before changing `rule_id_for`.
2. Provide an explicit migration table and operator command or recipe.
3. State that fingerprints, suppression keys, finding group IDs, SARIF alerts, CloudEvents joins, suppressions, and baselines may need regeneration.

## Surface Impact

| Surface | Compatibility rule |
| --- | --- |
| Fingerprints | `rule_id` is a fingerprint input. Alias strings must never change fingerprint input. A changed emitted rule ID is a fingerprint break. |
| Suppression keys | `rule_id` is part of `sk1` input. Alias strings must not change `suppression_key`; a changed emitted rule ID invalidates old keys. |
| Finding group IDs | Derived from `fingerprint`; any rule-ID fingerprint break also changes `finding_group_id`. |
| Suppressions | Current lookup is by `fingerprint` or `suppression_key`; `rule_id` is display/audit context. Old IDs in suppression files stay meaningful if emitted IDs stay stable. If emitted IDs change, operators need regenerated locators. |
| Baselines | Baseline entries key by `fingerprint` and record `rule_id` for audit. If emitted IDs change, existing baseline entries no longer match current findings. |
| SARIF | `runs[].results[].ruleId` must remain the emitted canonical ID. Any alias belongs in SARIF rule metadata only after an L5 contract decision; do not change result `ruleId` in 1.x for same-semantics renames. |
| CloudEvents | `tauditruleid` must remain the emitted canonical ID. Event `type` is category-scoped routing and must not be used as a rule-ID alias surface. |
| Docs and explain | Rule docs, rule index, and `taudit explain` may accept aliases, but each alias must redirect to the emitted canonical ID and say whether it is catalog-only, deprecated, or a semantic predecessor. |

## Backcompat Probe

Add a focused test in `crates/taudit-core/src/finding.rs` that asserts `rule_id_for` returns the current helper-authority IDs above. This locks the backcompat surface without renaming production variants or touching parser, CLI, report, sink, schema, or evidence modules.

Exact target:

```bash
cargo test -p taudit-core finding::fingerprint_tests::helper_authority_rule_ids_stay_backcompat_stable
```

Broader scoped target after Rust changes:

```bash
cargo test -p taudit-core finding
```

## Residual Risk

- This plan does not implement docs/explain alias lookup; it defines the policy for the future worker that owns that surface.
- Parallel L4/L5 work may add new helper categories after this probe. New helper IDs should be appended to this inventory and the focused test before RC lock.
- Catalog-only aliases are based on current research docs. If a suppressed alias becomes a distinct rule, it needs its own rule ID and migration note.
