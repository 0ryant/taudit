# v1 SARIF Rule ID — Lock Decisions

**Status:** Sweep of all 26 rule IDs currently defined on `main` (`crates/taudit-report-sarif/src/lib.rs::RULE_DEFS`).

**Strategic context:** taudit has 2 customers and is about to onboard more. Once a SARIF rule ID lands in a customer's GitHub Code Scanning suppression config (`paths-ignore` style filters keyed on `rules/<id>`), renaming the rule silently breaks the suppression. The cost of a wrong rename is paid by every customer who already pinned the old name; the cost of a wrong "keep" is mild aesthetic friction in our docs.

**Decision bias:** **KEEP unless there is a substantive correctness or precision problem with the current name.** Aesthetic improvements do not clear the bar. Per `engineering-doctrine/principles/semantic-versioning.md` §9, public surface renames require a deprecation window and a major bump — neither is appropriate before v1 lock.

**Method:** Each rule was scored against four criteria:

1. **snake_case format** — required for consistency with peers.
2. **Specificity** — does a developer skimming GitHub Code Scanning intuit the detection from the ID alone?
3. **Platform prefix** — should ADO-only rules carry an `ado_` prefix?
4. **Length** — anything over 40 characters reads as a sentence.

---

## Cross-cutting decision: NO platform prefix

**Question:** Should ADO-only rules be renamed to `ado_<rule>` (e.g. `ado_variable_group_in_pr_job`)?

**Decision:** **NO** prefix. Keep all rules unprefixed.

**Rationale:**
- The current 26-rule set has no platform prefix. Introducing one for ADO rules creates an inconsistency — now reviewers must remember "GHA rules are unprefixed; ADO rules are prefixed; cross-platform rules are unprefixed." This is exactly the cognitive load `engineering-doctrine/principles/naming-and-repo-layout.md` §2 warns against ("avoid clever abbreviations shared across org boundaries").
- The rule's `tags: &["security", "credentials", "azure-devops"]` field already carries the platform classification. SARIF consumers that want to filter by platform should filter on tags, not parse the ID.
- Renaming 9 ADO rules to add a prefix is a breaking change against current customer suppressions for zero correctness gain.
- If we ever ship a GitLab-only rule, the same reasoning will apply — let the tag carry the platform.

**Decision lockedfor v1.** Future platform-specific rules ship without prefix; their `tags` field carries the platform.

---

## Per-rule decisions (26 rules)

| # | Current ID | Length | Decision | Rationale |
|---|------------|--------|----------|-----------|
| 1 | `authority_propagation` | 21 | **KEEP** | Core taudit term. Customers reference. |
| 2 | `over_privileged_identity` | 24 | **KEEP** | Standard security vocabulary. |
| 3 | `unpinned_action` | 15 | **KEEP** | Industry-standard term (GitHub Actions). |
| 4 | `untrusted_with_authority` | 24 | **KEEP** | Reads as a sentence; precise. |
| 5 | `artifact_boundary_crossing` | 26 | **KEEP** | SLSA / supply-chain term of art. |
| 6 | `floating_image` | 14 | **KEEP** | Industry-standard container term. |
| 7 | `long_lived_credential` | 21 | **KEEP** | OIDC / cred-rotation vocabulary. |
| 8 | `persisted_credential` | 20 | **KEEP** | Distinct from #25 — refers to checkout `persistCredentials`. |
| 9 | `trigger_context_mismatch` | 24 | **KEEP** | Precise; covers both GHA `pull_request_target` and ADO PR triggers. |
| 10 | `cross_workflow_authority_chain` | 30 | **KEEP** | Long but each token earns its place. |
| 11 | `authority_cycle` | 15 | **KEEP** | Concise and precise. |
| 12 | `uplift_without_attestation` | 26 | **KEEP** | "Uplift" is taudit-specific; documented in DOCTRINE.md. |
| 13 | `self_mutating_pipeline` | 22 | **KEEP** | Covers `GITHUB_ENV` + ADO `setvariable`. |
| 14 | `variable_group_in_pr_job` | 24 | **KEEP** | ADO-specific without prefix per cross-cutting rule above. |
| 15 | `self_hosted_pool_pr_hijack` | 26 | **KEEP** | Precise threat model in 4 tokens. |
| 16 | `service_connection_scope_mismatch` | 33 | **KEEP** | ADO-specific concept; "service connection" is the user-visible name. |
| 17 | `template_extends_unpinned_branch` | 32 | **KEEP** | Pre-flagged candidate; see notes below. |
| 18 | `vm_remote_exec_via_pipeline_secret` | 34 | **KEEP** | Pre-flagged candidate; see notes below. |
| 19 | `short_lived_sas_in_command_line` | 31 | **KEEP** | Length is justified; every token disambiguates. |
| 20 | `checkout_self_pr_exposure` | 25 | **KEEP** | "checkout self" is the ADO syntax users will recognize. |
| 21 | `secret_to_inline_script_env_export` | 35 | **KEEP** | Pre-flagged candidate; see notes below. |
| 22 | `secret_materialised_to_workspace_file` | 38 | **KEEP** | Pre-flagged candidate; see notes below. |
| 23 | `keyvault_secret_to_plaintext` | 28 | **KEEP** | Domain-specific Key Vault terminology is appropriate. |
| 24 | `terraform_auto_approve_in_prod` | 30 | **KEEP** | Each token disambiguates against close neighbors. |
| 25 | `add_spn_with_inline_script` | 26 | **KEEP** | Pre-flagged candidate; see notes below. |
| 26 | `parameter_interpolation_into_shell` | 35 | **KEEP** | Precise injection-class label; matches ADO terminology. |

**Result: 0 renames. 26 KEEPs.**

**Why no renames at all?** The strategic value of this sweep is the *audit*: confirming for the next 2-N customers that we've reviewed every ID against the 4-criterion bar and that nothing here is a placeholder. Every candidate I considered renaming offered an aesthetic gain but cost a customer suppression. None cleared the bar.

---

## Notes on pre-flagged candidates

The user pre-flagged 5 IDs for explicit review. My rationale for keeping each:

### `add_spn_with_inline_script` — KEEP

**Considered:** `azurecli_addspn_inline_script`, `addspn_environment_inline_script`.

**Decision:** Keep. "SPN" (Service Principal) is the term ADO docs and the Azure CLI use; users reading the rule in GitHub Code Scanning will recognize it immediately. The `azurecli_` prefix variant adds 8 chars and a coupling to one of three task families that can trigger the detection (`AzureCLI@2`, `AzurePowerShell@5`, `AzureCLI@1`). The `_environment` variant duplicates the implicit subject (`addSpnToEnvironment` is the only `addSpn` flag in ADO) without adding information.

### `secret_materialised_to_workspace_file` — KEEP

**Considered:** `secret_written_to_file`, `secret_persisted_to_workspace`.

**Decision:** Keep. `secret_written_to_file` loses the "workspace" specificity — the rule fires on `$(System.DefaultWorkingDirectory)` / `$(Build.SourcesDirectory)` paths, not arbitrary writes (writing to `/tmp/` does not fire). `secret_persisted_to_workspace` collides semantically with the existing `persisted_credential` rule (#8). Length is 38 chars (within budget). UK spelling (`materialised`) matches the existing rule docs and the user is the only English speaker who will care.

### `secret_to_inline_script_env_export` — KEEP

**Considered:** `secret_exported_in_inline_script`.

**Decision:** Keep. The shorter variant loses the `env_` specificity — the rule is narrowly about *environment variable* assignment, not about general inline-script exposure (which is covered by other rules in the same group). Customers triaging a finding will benefit from knowing it's the env-var path before they open the rule doc.

### `vm_remote_exec_via_pipeline_secret` — KEEP

The user described this as "long but descriptive" — agreed. Every token disambiguates: `vm_` (scope), `remote_exec_` (action class), `via_pipeline_secret` (data flow). Removing any one token produces collisions with neighboring rules. Length 34 is within budget.

### `template_extends_unpinned_branch` — KEEP

**Considered:** `unpinned_template_repository`.

**Decision:** Keep. The user asked whether "branch" is right when the trigger can also be a no-`ref` case. The rule's full description already covers both: missing `ref:` defaults to the repo's default branch, which is structurally a branch reference. Renaming to `unpinned_template_repository` loses the specificity of *what* is unpinned (the branch reference, not the repository identity itself — the repository is correctly identified by alias). The current name is correct.

---

## Verification

- All 26 IDs are snake_case (`^[a-z][a-z0-9_]*$`). ✓
- No ID exceeds 40 characters (max is 38: `secret_materialised_to_workspace_file`). ✓
- No two IDs collide on first three tokens. ✓
- All ADO-specific rules carry the `azure-devops` tag. ✓
- All pre-flagged candidates explicitly addressed. ✓

---

## Migration / merge notes

**There are no renames to apply.** This document exists primarily as the audit trail customers and future-us can point to that confirms every ID was reviewed against the v1 bar. No action required at merge time for any of the four ADO rule worktrees.

If a future rule ships and the reviewer is tempted to deviate from the cross-cutting "no platform prefix" decision above, this document is the precedent to point at.

---

## References

- `engineering-doctrine/principles/semantic-versioning.md` §9 (deprecation before removal)
- `engineering-doctrine/principles/naming-and-repo-layout.md` §2 (convention over novelty)
- `crates/taudit-report-sarif/src/lib.rs::RULE_DEFS` — canonical rule list
- `docs/rules/` — per-rule documentation referenced from SARIF `helpUri`
