# taudit Rule Reference

20 built-in rules. Run `taudit explain <rule-id>` for a description in the terminal.

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
| [service_connection_scope_mismatch](service_connection_scope_mismatch.md) | High | Privilege | ADO only |
| [secret_to_inline_script_env_export](secret_to_inline_script_env_export.md) | High | Credentials | ADO only |
| [secret_materialised_to_workspace_file](secret_materialised_to_workspace_file.md) | High | Credentials | ADO only |
| [keyvault_secret_to_plaintext](keyvault_secret_to_plaintext.md) | Medium | Credentials | ADO only |

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
- **over_privileged_identity** — High for Broad scope; Medium for Unknown scope.

---

See also: [Custom Rule Format](../custom-rules.md)
