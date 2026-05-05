# Helper-resolution authority-edge backlog (ADR 0005)

Tasks for implementing [ADR 0005](../adr/0005-authority-edge-classifier-and-witness-handoff.md). The goal is to make taudit the classifier/prioritizer for authority edges while keeping witness execution outside taudit.

Disclosure/CVE-oriented tooling is internal-only. Any witness-spec command, disclosure score, CVE workflow metadata, private source anchor, or canary detail must be hidden behind an explicit feature gate or internal build flag and omitted from default downstream/customer output.

## Research and writing lanes

| ID | Owner | Task | Acceptance | Verify |
|----|-------|------|------------|--------|
| R1 | Researcher | Catalog source anchors for initial actions: Firebase, Azure, Cloudflare, Docker login, npm publish, ECR login, setup-gcloud, GoReleaser, Codecov, Teleport. | Each action has pinned versions/SHAs, helper invocation notes, authority transport, and source/witness status. | Catalog fixture review; links or local notes under `docs/research/`. |
| R2 | Researcher | Normalize hosted-runner witness observations into catalog fields. | `witness_status`, `observed_helper`, `observed_authority_transport`, `canary_only`, and `pinned_sha` are available for witnessed actions. | JSON/TOML catalog validates against schema. |
| R3 | Researcher | Write internal disclosure-score factor notes for each initial action. | Each entry records why technical score and disclosure score can diverge; disclosure factors are not emitted by default reports. | Review against ADR 0005 scoring table and feature-gate checklist. |
| R4 | Researcher | Index Algol handoff rulesets: `/Users/rytilcock/prj/algol/docs/research/taudit-authority-confusion-ruleset-handoff.md` and `/Users/rytilcock/prj/algol/docs/research/taudit-corpus-lead-hunt-ruleset.md`; current normalized output is [`2026-05-05-algol-rule-intake-index.md`](2026-05-05-algol-rule-intake-index.md). | Canonical rule IDs, match shapes, evidence levels, exclusions, and candidate-specific profiles are normalized into taudit backlog/catalog entries with duplicates merged against existing rules. | Cross-check the index against the two Algol docs and this backlog; no duplicate rule IDs or alias-only tasks. |
| W1 | Writer | Produce customer-safe report copy templates for helper authority findings. | Templates include earlier mutable channel, later authority, helper sink, transport, why it matters, same-job caveat, and remediation without CVE/disclosure language. | Snapshot tests or docs examples. |
| W2 | Writer | Produce internal-only disclosure/witness copy templates. | Templates include witness next action and disclosure routing only under the internal feature gate. | Feature-gated snapshot tests. |
| W3 | Writer | Update user-facing docs after the first implementation slice. | Docs explain taudit/Algol/witness split and labels: product candidate, workflow misconfiguration, hardening, demo, suppressed expected behavior. | `docs/` link check or golden-path smoke if CLI docs change. |

## Implementation tasks

| ID | Priority | Area | Task | Acceptance | Verify |
|----|----------|------|------|------------|--------|
| A1 | P0 | Schema | Add authority timing model (`AuthorityEvent`, phase, event kind) or equivalent graph metadata. | Rules can test `PathMutation.step_index < SecretMaterialized.step_index <= HelperExecution.step_index` without ad hoc string matching. | Unit tests for ordered and reversed steps. |
| A2 | P0 | Schema | Add `HelperResolution`, `AuthorityTransport`, and `AuthorityOrigin` enums. | Findings can distinguish bare command, shell string, toolkit lookup, absolute/toolcache/action-owned path, explicit ambient mode, argv/stdin/env/file/OIDC transport, and caller/action-minted origins. | Serde/schema tests and Rust exhaustiveness coverage. |
| A3 | P0 | Catalog | Add action intelligence catalog plus schema. | Offline scan can match initial catalog entries without network access. | Validate catalog fixtures in CI. |
| A4 | P0 | Rules | Add canonical `GHA_HELPER_PATH_LATER_AUTHORITY` umbrella rule. | Does not fire for PATH mutation alone; fires only with prior mutable resolution plus later sensitive helper authority transport. | Positive/negative GHA fixtures. |
| A5 | P0 | Rules | Split transport-specific findings: argv, stdin, env, credential file, OIDC env. | Transport-specific rule IDs and severities appear in JSON/SARIF/terminal consistently. | Cross-sink contract tests. |
| A6 | P1 | Downgrades | Add absolute/toolcache/action-owned/explicit-mode downgrades and suppressors. | `setup-gcloud skip_install`, GoReleaser toolcache, Codecov `use_pypi`, and action-owned paths do not rank as lead findings without stronger evidence. | Regression fixtures for each downgrade. |
| A7 | P1 | Scoring | Add default `technical_score` and internal-only `disclosure_score`. | Technical scores expose authority-edge factors by default; disclosure scores require the internal feature gate. | Deterministic scoring unit tests plus feature-gate output tests. |
| A8 | P1 | Reporting | Add same-job objection field and caveat text. | Reports say the issue is later materialization into a prior-step-selected helper, not same-job isolation. | Snapshot tests for terminal/JSON where applicable. |
| A9 | P1 | Witness handoff | Add feature-gated `taudit witness-spec` for helper-authority findings. | Emits machine-readable expected observations and canary placeholders only in internal mode; does not execute witness. | CLI integration test with sample scan JSON and default-mode rejection test. |
| A10 | P2 | Labels | Add finding labels for product action candidate, workflow misconfiguration, hardening recommendation, demo, and suppressed expected behavior. | Reports and SARIF properties distinguish product-action candidates from workflow-only issues without CVE language. | JSON schema and SARIF property tests. |
| A11 | P2 | Migration | Alias or migrate first-pass helper rule IDs to canonical ADR 0005 IDs. | Existing rule docs remain discoverable; canonical IDs are stable for new consumers. | `taudit explain` and rules index tests/docs. |
| A12 | P0 | Rules | Add `later_secret_materialized_after_path_mutation` as the shared timing predicate for helper-resolution rules. | High-confidence helper-PATH rules require earlier mutable resolution, later authority materialization, PATH/ambient helper execution, and authority transport to the helper. PATH mutation alone never fires. | Unit tests for PATH-only, reversed order, same-step materialization, and valid later-helper handoff. |
| A13 | P1 | Rules | Add `gha_setup_node_cache_helper_path_handoff`. | Flags `actions/setup-node` cache modes only when earlier mutable helper resolution exists and cache-path helper calls (`npm`, `pnpm`, `yarn`) run with later relevant authority or package registry context in scope. | Fixtures for cache disabled, cache enabled without prior PATH mutation, and cache enabled after prior PATH mutation. |
| A14 | P1 | Rules | Add `gha_setup_python_cache_helper_path_handoff`. | Flags `actions/setup-python` cache modes only when earlier mutable helper resolution exists and `pip`/`poetry` helper calls run with later private index, package, or cloud authority context in scope. | Fixtures for pip cache, poetry cache, no-authority downgrade, and prior PATH mutation ordering. |
| A15 | P1 | Rules | Add `gha_setup_python_pip_install_authority_env`. | Flags `actions/setup-python` `pip-install` mode only when private index tokens, package credentials, or cloud credentials are in inherited env; broad ambient env alone is not enough for high severity. | Fixtures for public install, private index token, cloud credential env, and no prior helper mutation. |
| A16 | P1 | Rules | Add `gha_docker_setup_qemu_privileged_docker_helper`. | Flags `docker/setup-qemu-action` only when paired with prior Docker auth, private image authority, or registry credential context; records privileged Docker helper execution separately from generic Docker usage. | Fixtures for QEMU alone, QEMU after docker login, private image context, and no prior helper mutation. |
| A17 | P2 | Rules | Add `gha_tool_installer_then_shell_helper_authority` as an advisory classifier. | Flags installer-followed-by-use patterns for Helm, kubectl, cosign, and similar tools when later shell commands carry deploy/signing authority; labels default output as workflow misconfiguration or hardening unless action-owned helper boundary evidence exists. | Fixtures for installer-only, installer plus deploy authority, cosign signing authority, and label downgrade behavior. |
| A18 | P2 | Corpus mining | Add workflow-shell authority concentration classifiers. | Detects shell patterns such as `docker login` -> `docker push`, `npm`/`pnpm publish`, `twine upload`, `terraform apply` -> `terraform output`, `helm registry login` -> `helm push`, `kubectl apply -f http(s)://...`, `cosign sign|attest`, and `gh release`; labels them as corpus/source leads, not disclosure candidates. | Corpus fixtures with JSON labels showing `WORKFLOW_MISCONFIGURATION` or `HARDENING_RECOMMENDATION`, not `PRODUCT_ACTION_CANDIDATE`. |
| A19 | P2 | Evidence tiers | Add explicit evidence-tier output for helper and shell authority classifiers. | Findings distinguish corpus signal, source lead, runner-faithful witness, hosted witness, and suppressed expected behavior; disclosure routing remains feature-gated internal output only. | Snapshot tests proving default customer output omits disclosure score, CVE language, canary details, and witness next-action fields. |

## Candidate rule intake

Current normalization lives in [`2026-05-05-algol-rule-intake-index.md`](2026-05-05-algol-rule-intake-index.md). Next grouping after the already-landed helper/cache/workflow-shell rules is:

- queued classifier rules with customer-safe output;
- catalog/source-anchor work needed before rule implementation;
- internal-only witness, disclosure, CVE, and red-team work behind feature gates.

Corpus signal/noise gating for these rules lives in
[`2026-05-05-algol-rule-corpus-signal-gate.md`](2026-05-05-algol-rule-corpus-signal-gate.md).

| Candidate | Backlog item | Default label | Evidence tier | Notes |
|-----------|--------------|---------------|---------------|-------|
| `later_secret_materialized_after_path_mutation` | A12 | Product-action candidate when tied to action catalog; hardening otherwise | Source lead or better | Shared predicate, not a standalone noisy PATH rule. |
| `gha_setup_node_cache_helper_path_handoff` | A13 | Product-action candidate after catalog/source anchor | Source lead | Cache helper calls must be tied to later authority or registry context. |
| `gha_setup_python_cache_helper_path_handoff` | A14 | Product-action candidate after catalog/source anchor | Source lead | Require private index/package/cloud authority context for strong signal. |
| `gha_setup_python_pip_install_authority_env` | A15 | Hardening recommendation by default | Corpus signal/source lead | High severity only with credential-bearing inherited env. |
| `gha_docker_setup_qemu_privileged_docker_helper` | A16 | Product-action candidate or workflow misconfiguration depending on source edge | Source lead | Registry/private-image authority is the differentiator. |
| `gha_tool_installer_then_shell_helper_authority` | A17 | Workflow misconfiguration/hardening | Corpus signal | Not disclosure-grade without action-owned helper boundary evidence. |
| Workflow-shell authority concentration rules | A18 | Workflow misconfiguration/hardening | Corpus signal | Useful for candidate mining and ranking, not CVE-grade by default. |

## Initial scoring expectations

| Candidate | Expected technical score | Internal disclosure score | Notes |
|-----------|--------------------------|---------------------------|-------|
| Firebase hosting deploy | High | High | Generated credential file passed to bare `npx`; hosted witness should elevate internal triage. |
| Azure login | High | Medium/high | `az` receives service-principal authority; caller-provided credential caveat remains. |
| Cloudflare Wrangler | High | Medium/high | Package-manager helper design caveat, but deploy secret transport is strong. |
| Docker login | High | Medium | Stdin registry password, but often caller-provided and expected wrapper behavior. |
| ECR login | High | High | Action-minted registry password is stronger than direct input forwarding. |
| setup-gcloud `skip_install` | Medium/high | Low/medium | Explicit ambient helper mode should downgrade disclosure priority. |

## Non-goals

- Do not run hosted witnesses inside taudit.
- Do not clone action source on every scan.
- Do not warn on PATH mutation alone.
- Do not merge post-cleanup rules into helper-resolution authority rules.
- Do not call unproven candidates CVEs.
- Do not expose disclosure scoring, CVE workflow hints, canary values, or private witness artifacts in default downstream/customer output.
