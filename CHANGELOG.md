# Changelog

All notable changes to this project will be documented in this file.

## v0.9.2 — 2026-04-26

> Patch release focused on correctness, integration readiness, and operator
> workflow. Ships 8 merged bundles since v0.9.1: parser/data-integrity fixes,
> security hardening, SOC outputs, major propagation performance gains,
> stability/provenance improvements, blue-team positive invariants,
> suppressions, and baseline-driven adoption.

### Added — Baselines feature (`.taudit/baselines/`)

- **Per-pipeline baselines** keyed by content hash at `.taudit/baselines/<hash>.json`.
- **`taudit baseline {init, accept, diff, review}`** command group for establishing and maintaining accepted finding state.
- **`scan` + `verify` baseline-aware by default** with diff-shaped output and the critical-always-fails contract.

### Added — Suppressions feature (`.taudit-suppressions.yml`)

- **Per-finding waivers with audit trail** via `.taudit-suppressions.yml`.
- **`taudit suppressions {list, add, review}`** command group.
- **Finding model expansion** with six operator fields including grouping, time-to-fix context, compensating controls, and suppression metadata.

### Added — Blue-team defensive signal

- **5 positive invariants** from corpus defense work.
- **4 compensating-control suppressions** tied to platform and repository guardrail metadata.

### Added — SOC and ecosystem integrations

- **`tauditplatform` CloudEvents extension** for downstream routing/attribution.
- **`scan --dedupe-against`** for incremental SIEM ingest workflows.
- **`schemas/finding.v1.json`** standalone finding schema for external validators.
- **SARIF partial fingerprints** published under `partialFingerprints["taudit/v1"]`.

### Changed — Stability and provenance

- **`FindingSource` provenance** now distinguishes built-in vs custom-rule findings.
- **Fingerprint v2** now includes all canonical components deterministically.
- **New composition rule**: `secret_via_env_gate_to_untrusted_consumer`.

### Fixed — Bug bundle and security hardening

- **GHA parser regression fixed** (EnvSpec edge case impacting 206 files).
- **ADO parser regression fixed** (37-file regression set).
- **JSON output integrity**: `rule_id` now populated and output ordering stabilized for byte-deterministic JSON.
- **`detect_platform()` now path-aware** with mismatch warning behavior.
- **Pin validation hardened**: rejects all-zero SHA and truncated digest forms.
- **`--invariants-dir` hardening**: rejects unsafe symlink traversal by default.
- **Cross-platform completeness guard**: parsers mark `Partial` when zero step nodes are produced.

### Performance

- **Propagation engine rewrite** reduced dense-case scan latency from ~1.08 s to ~15.3 ms (~70x in benchmark scenario).
- **Authority propagation clustering** reduced large hit sets (example: 6,565 to 1,145 findings).
- **`unpinned_action` severity tiering** improves signal quality by trust zone.

### Release delta summary (v0.9.1..v0.9.2)

- 37 commits grouped into 8 merge bundles.
- 41 files changed, 12,393 insertions(+), 1,985 deletions(-).
- Built-in invariants increased from 32 to 38.

### Known issues

- **Flaky test:** `verify_violating_fixture_exits_one` may fail in full-suite execution but passes on isolated re-run. Suspected shared temporary-directory coupling; tracked as a v0.9.3 follow-up.
- **Deferred rules batch:** the 21 council/redteam GHA+GitLab additive rules from deferred worktree `af68e4b6acd4e6bdd` are intentionally not included in v0.9.2.

## v0.9.1 — 2026-04-26

> Patch release. Same RC-for-v1.0 framing as v0.9.0. Adds 5 new authority
> invariants, hardens the finding-fingerprint mechanism, ships reference
> consumers + stack integration specs, expands the starter invariant
> library, adds a Criterion benchmark suite, and tightens CI hygiene.

### Added — 5 new authority invariants

- **`pr_trigger_with_floating_action_ref`** (Critical, Privilege+Supply Chain) — the conjunction of `pull_request_target` / `issue_comment` / `workflow_run` trigger AND a non-SHA-pinned action use. Compromised action default branch yields full repo write on the target. Fires 83× across vuejs/core, svelte, grafana, neovim, pytorch in our 960-file GHA corpus — most-impactful new rule. Neither `risky_trigger_with_authority` nor `unpinned_action` catches the intersection alone.
- **`runtime_script_fetched_from_floating_url`** (High, Injection) — `run:` block does `curl <url> | sh` / `wget … | bash` / `bash <(curl …)` where the URL points to a mutable branch ref.
- **`untrusted_api_response_to_env_sink`** (High, Injection) — workflow captures external API value (`gh api`, `curl api.github.com`) into `$GITHUB_ENV`/`$GITHUB_OUTPUT`/`$GITHUB_PATH`. Poisoned API field injects environment variables into every subsequent step.
- **`pr_build_pushes_image_with_floating_credentials`** (High, Supply Chain) — PR-triggered workflow uses non-SHA-pinned container-registry login action holding registry creds.
- **`template_repo_ref_is_feature_branch`** (High, Supply Chain, ADO-only) — `resources.repositories[]` pinned to a feature/topic/dev branch (anything outside main/master/release/hotfix). Strictly stronger signal than `template_extends_unpinned_branch`; co-fires.
- **`terraform_output_via_setvariable_shell_expansion`** (High, Injection, ADO) — two-step ADO chain: inline script captures `terraform output`, emits `##vso[task.setvariable]`, then a subsequent step expands `$(X)` in shell-expansion position. The setvariable hop launders attacker-controlled remote-backend Terraform state through pipeline-variable space.

### Added — Authority Invariant DSL extensions

- **Multi-document YAML loading** in `crates/taudit-core/src/custom_rules.rs` — multiple invariants per file via standard `---` separators.
- **`graph_metadata:` predicate** — match against graph-level metadata (`META_TRIGGER`, `META_PERMISSIONS`, etc.) so invariants can express "in PR context AND with broad identity" cleanly. Closes the v1.0-blocker DSL gap flagged by the strategic ratification council.
- **`standalone:` predicate** — match a single node's shape without requiring a propagation path (e.g. "any Image without `has_digest: true`"). Image nodes are now valid sinks.
- All grammar additions are backward-compatible. `cmd_invariants_list` updated to use the multi-doc loader (drive-by fix discovered by starter library expansion).

### Added — Stable finding fingerprint surface

- **Fingerprint computation moved to `taudit-core`** (`compute_fingerprint(&Finding, &AuthorityGraph) -> String`). Replaces the previous `std::hash::DefaultHasher` (which Rust explicitly does not stabilize across compiler versions — latent v1.0 stability bug).
- **SHA-256 truncated to 16 hex chars.** Canonical input: `v1\x1frule={id}\x1ffile={path}\x1fcategory={snake}\x1fnodes={root_authority OR sorted_unique_node_names}`.
- **Surfaces in all three output formats:** SARIF `partialFingerprints[<key>]`, JSON `findings[].fingerprint`, CloudEvents `tauditfindingfingerprint` extension attribute. Schema bumps in `contracts/schemas/taudit-report.schema.json` and `contracts/schemas/taudit-cloudevent-finding-v1.schema.json`.
- **Per-hop findings against the same authority collapse to one fingerprint** — one secret + four hops = one suppression key. Implements the blue team's "cluster authority_propagation" recommendation as a side effect.
- 8 new tests including cross-format parity (SARIF/JSON/CloudEvents fingerprints byte-identical for the same finding).

### Added — Reference consumers (`examples/consumers/`)

- **Python** (`blast_radius.py`, 98 lines, stdlib only) — ranks Secret nodes by transitive blast radius.
- **Go** (`main.go`, 133 lines, stdlib only) — finds OIDC identities reaching ThirdParty steps (cross-trust OIDC propagation).
- **TypeScript** (`find-cycles.ts`, 137 lines, Deno stdlib) — Tarjan SCC for authority cycle detection.
- Closes the strategic ratification council's "schema needs a reference consumer or it's a liability" critique. The v1 graph schema now has 3 second users.

### Added — Stack integration specs (`docs/integrations/`)

- **`tsign-consumer.md`** — proposed in-toto predicate `https://taudit.dev/attestations/authority-graph/v0.1` for sibling project tsign to attest authority graphs.
- **`axiom-consumer.md`** — proposed cross-repo decision schema `decision_schema_version: "0.1.0"` (allow/block/flag_for_review with attestation chain).
- **`index.md`** — overview of the 3-layer stack (taudit graph → tsign attest → axiom enforce).

### Added — Starter invariant library expansion (`invariants/starter/`)

- 7 new invariant files demonstrating every v0.9.0 DSL feature (`graph_metadata:`, `standalone:`, `not:`, typed metadata, multi-value lists, multi-doc YAML).
- `bundled-strict-policy.yml` shows multi-doc syntax (3 invariants in one file).
- Updated README with feature-coverage table and a "Choosing your first invariant" guide keyed to org type.
- 15 custom + 32 built-in = 47 invariants when starter library is loaded.

### Added — Criterion benchmark suite (`crates/*/benches/`)

- Bench files for propagation engine, rule evaluation, custom-rule DSL, and per-platform parsers.
- v0.9 baseline captured in `docs/perf-baseline.md`.
- **Headline finding:** propagation BFS is `O(V+E)` at sparse edge density (real-workflow case) but degrades toward `O(V·E)` at dense-5x — n=100→10,000 jumps 289 µs to 1.08 s (~3,700× for 100× nodes). Documented as a v1.0 hardening candidate (potential DoS vector via crafted dense graphs).

### Added — CI hardening

- `.github/workflows/security.yml` — cargo-deny on PR/push + Monday cron + hard-fail self-scan via `taudit scan --severity-threshold high`.
- `.github/workflows/quality.yml` — self-scan now uses release binary, emits SARIF artifact, gates on `taudit verify` against `invariants/starter/` and `invariants/policies/example-enterprise-ado.yml`.
- `.github/workflows/release.yml` — CycloneDX 1.5 SBOM generation alongside existing SPDX 2.3, both attached to release.
- `deny.toml` tightened: wildcards `deny`, unknown-git `deny`, allow-registry pinned to crates.io, closed SPDX list.
- `docs/release-trust.md` — minisign signed-release recipe documented as future work; placeholder `release/taudit.pub` scaffolded.

### Added — Self-hosting scan (`docs/self-hosting-scan.md`)

- Initial scan of tsafe shows the ROADMAP "zero findings" gate not yet met: 90 findings (20 critical), all 20 criticals concentrated in `release-plz.yml` from unpinned `release-plz/action@v0.5`, `actions/checkout@v4`, `dtolnay/rust-toolchain@stable` receiving `CARGO_REGISTRY_TOKEN` + `GITHUB_TOKEN`. Inconsistent with every other tsafe workflow which already uses SHA pins. Single-file fix would close the gate.
- runtime-isolation harness not present on the development machine; gate undetermined.

### Fixed

- **GHA parser tolerates `env: ${{ matrix }}`** — template-as-map at job/step env level no longer crashes; promotes graph to `Partial` instead.
- **ADO parser tolerates root-level parameter conditional templates** — `parameters: ... - ${{ if eq(parameters.X, true) }}: - job: ...` no longer fails the scan; promotes to `Partial`.

### Known v0.9.x → v1.0.0 backlog

Surfaced during this release cycle by fuzzing, corpus rerun, red-team round 2, and self-hosting scan:

1. **Parser regressions** — 205 GHA + 37 ADO-diverse files newly fail to parse on main vs v0.9.0 baseline (likely `EnvSpec` enum change). Net improvement on ADO main corpus (parser failures dropped 1 → 0).
2. **`scan --format json` non-determinism** (fuzz B1) — same input, different node ordering across runs. Fingerprints are stable; raw graph isn't.
3. **`detect_platform()` is content-only, never inspects path** (fuzz B2) — security-adjacent; stray `on:` in `.gitlab-ci.yml` flips parse to GHA, dropping GitLab job.
4. **Pin validation is structural, not semantic** (fuzz B3) — `actions/setup-python@<40-zeros>` accepted as pinned.
5. **`rule_id: null` in JSON output** (self-hosting scan) — text format shows correct categories; JSON consumers can't filter by rule.
6. **SARIF fingerprint collision class** (red team R2 #2) — two genuinely different `authority_propagation` findings sharing a secret name produce identical fingerprints. (The new SHA-256 fingerprint replaces unstable DefaultHasher but doesn't fully eliminate this collision class.)
7. **Trust-zone laundering via `$GITHUB_ENV`** (red team R2 #3) — secret written to env gate by first-party step + read by untrusted action = no `authority_propagation` finding. Composition gap between two correct rules.
8. **Custom invariant injection** (red team R2 #1) — no provenance annotation distinguishing built-in vs custom rule findings.
9. **Symlink traversal in `--invariants-dir`** (red team R2 #4) — symlinks followed without warning.
10. **Cross-platform silent clean** (red team R2 #5) — file with `jobs:` (GHA) wrapping ADO content auto-detects as GHA, returns 0 findings + `completeness: complete`.
11. **Dense-graph BFS perf cliff** (bench) — potential DoS vector via crafted graphs.

These will be addressed in v0.9.x patches and inform the v1.0 promotion decision when the scheduled 2026-05-10 agent runs.

## v0.9.0 — 2026-04-26 (release candidate for v1.0)

> v0.9.0 is the v1.0 release candidate. The CLI contract, graph schema, and
> invariant DSL are intended to be stable, but we're holding the v1.0 stamp
> until the full corpus + early-customer feedback validates them. Breaking
> changes between v0.9.x and v1.0.0 are possible if we find a defect.

> **Tagline:** *CI/CD is an untyped authority system. taudit makes it explicit, inspectable, and enforceable.*

### Breaking changes

- **`taudit scan` is now informational.** It always exits `0` unless a
  structural error occurs (file not found, parse failure → exit `2`).
  Findings are reported but never fail the process. Migration: move any
  pipeline gate that depended on `scan`'s non-zero exit to `taudit verify
  --policy <policy.yml>`, which is the new policy-driven enforcement
  entrypoint with deterministic exit codes (`0` clean, `1` violation,
  `2` structural error).
- **`--rules-dir` is deprecated** in favor of `--invariants-dir`. The
  old flag still works as an alias and emits a one-shot stderr
  deprecation warning. The alias is slated for removal in a future
  major.
- **No rule ID renames.** A v1 rule-ID sweep concluded all 26 IDs lock
  as-is — customer suppressions and SARIF baselines remain valid.

### New features

- **`taudit verify --policy <path>`** — policy-driven enforcement
  entrypoint. Runs only the user-supplied invariants in `--policy`
  unless `--include-builtin` is set. Deterministic exit codes (0/1/2),
  optional `--severity-threshold`, text/json output.
- **`taudit graph` command** — emits the authority graph as a
  first-class artifact in JSON or Graphviz DOT format. Backed by
  [`schemas/authority-graph.v1.json`](schemas/authority-graph.v1.json)
  (`schema_version: "1.0.0"`).
- **`taudit invariants list`** — prints every loaded invariant
  (built-in + custom) with id, severity, and source.
- **`--invariants-dir` flag** — canonical name for loading custom
  invariant YAML files.
- **Starter invariant library** at [`invariants/starter/`](invariants/starter/)
  with five copy-and-edit examples (`no-broad-identity-to-untrusted`,
  `no-third-party-step-with-identity`, `no-untrusted-image-with-secret`,
  `no-untrusted-with-prod-secret`, `prefer-oidc-over-static-secrets`).
- **CLI startup framing** — `taudit --help` now leads with the v1.0
  positioning line and points at `taudit verify --help` /
  `docs/positioning.md`.

### New rules — 10 ADO-only authority invariants

- **`template_extends_unpinned_branch`** (High, Supply Chain) — flags
  `resources.repositories[]` aliases that resolve to a default branch
  or `refs/heads/<branch>` (mutable) when consumed via `extends:`,
  `template: x@alias`, or `checkout: alias`.
- **`vm_remote_exec_via_pipeline_secret`** (High, Credentials) —
  pipeline step uses `Set-AzVMExtension` / `Invoke-AzVMRunCommand` /
  `az vm run-command` / `az vm extension set` with a pipeline secret
  or freshly-minted SAS in the executed command line.
- **`short_lived_sas_in_command_line`** (Medium, Credentials) — a
  SAS token minted in-pipeline is interpolated into
  `commandToExecute` / `scriptArguments` / `--arguments` / `-ArgumentList`
  rather than passed via env var or stdin.
- **`secret_to_inline_script_env_export`** (High, Credentials) — a
  pipeline secret is assigned to a shell variable inside an inline
  script (`export FOO=$(SECRET)`, `$X = "$(SECRET)"`), bypassing ADO's
  `$(SECRET)` log mask.
- **`secret_materialised_to_workspace_file`** (High, Credentials) — a
  pipeline secret is written to a workspace-relative file (`.tfvars`,
  `.env`, `.kubeconfig`, etc.) that persists for the rest of the job.
- **`keyvault_secret_to_plaintext`** (Medium, Credentials) — inline
  PowerShell pulls a Key Vault secret with `-AsPlainText` /
  `ConvertFrom-SecureString -AsPlainText` / `.SecretValueText`,
  bypassing variable-group masking.
- **`terraform_auto_approve_in_prod`** (Critical, Configuration) —
  `terraform apply -auto-approve` runs against a production-named
  service connection without an environment approval gate.
- **`add_spn_with_inline_script`** (High, Credentials) — `AzureCLI@2`
  task with `addSpnToEnvironment: true` plus an inline script —
  federated SPN material can be laundered into pipeline variables via
  `##vso[task.setvariable]`.
- **`parameter_interpolation_into_shell`** (Medium, Injection) — a
  free-form `type: string` pipeline parameter (no `values:` allowlist)
  is interpolated via `${{ parameters.X }}` directly into an inline
  shell or PowerShell script — shell-injection vector.

### DSL enhancements

- **Negation** (`not:`) on source / sink sub-matchers and inside metadata.
- **Typed metadata predicates**: `equals`, `not_equals`, `contains`
  (substring), `in` (any-of). Bare-string form preserved as `equals`
  for back-compat.
- **Multi-value `node_type` / `trust_zone`** — accepts either a single
  value or a list (any-of). Single-value form preserved.
- All grammar additions are backward-compatible with v0.4.x simple-form
  rule files. Unknown operator names produce a parse error so typos do
  not silently match nothing.

### Added (schema)

- `schemas/authority-graph.v1.json` now describes the `parameters` field
  on `AuthorityGraph` (`{param_type, has_values_allowlist}` per name).
- `PipelineSource` gains an optional `commit_sha` field (additive — CI
  integrations can populate this for reproducibility).
- Schema `description` notes that `$id` is a logical identifier
  (namespace, not a fetch endpoint).
- `docs/authority-graph.md` documents `META_JOB_NAME` (key `job_name`)
  as the only publicly stable node-metadata key.

### Strategic repositioning

- README, ROADMAP, and `docs/positioning.md` reframe taudit around
  authority invariants rather than rule-engine semantics.
- `docs/custom-rules.md` renamed to "Authority Invariants" framing
  (file kept as alias).

### Bug fixes (no prior release — bundled here)

- **GHA parser**: tolerates `env:` template expressions
  (`env: ${{ matrix }}`) instead of crashing — promotes to a Partial
  graph (commit `b5b33e2`).
- **ADO parser**: tolerates root-level parameter conditional templates
  (`- ${{ if eq(parameters.X, true) }}:`) — promotes to a Partial
  graph instead of failing the scan (commit `30fc274`). Now also
  catches the "invalid type: map" variant introduced by the rule-9
  parameter parsing.

### Migration guide

If you were depending on `taudit scan` exit code in CI:

1. Add a policy file under `invariants/` (or copy from `invariants/starter/`).
2. Replace `taudit scan <files>` (used as a gate) with `taudit verify
   --policy <path-or-dir> <files>`.
3. Optionally add `--include-builtin` to also count built-in invariant
   violations toward the gate.
4. Use `--severity-threshold critical|high|medium|low` to scope what
   counts as a failure.
5. The deprecated `--rules-dir` still works but logs a one-shot
   warning; switch to `--invariants-dir` at your convenience.

## v0.5.0 — 2026-04-26

### Added

- **GitLab CI parser** (`taudit-parse-gitlab`) — parses `.gitlab-ci.yml` files into the authority graph. Authority primitives modelled:
  - `CI_JOB_TOKEN` — implicit `Identity` node (always present, scope=broad), equivalent to ADO's `System.AccessToken`.
  - `secrets:` (Vault, AWS Secrets Manager, GCP, Azure) — each named secret emits a `Secret` node with `HasAccessTo` edge from the enclosing job.
  - `id_tokens:` — OIDC identity tokens emit `Identity` nodes tagged `oidc=true`, with audience label. Triggers `long_lived_credential` and `authority_propagation` rules.
  - `variables:` — variable names matching credential patterns (TOKEN, SECRET, PASSWORD, API_KEY, etc.) emit `Secret` nodes.
  - `image:` (global and per-job) — emits `Image` node with `UsesImage` edge. Untagged/undigest-pinned images have `TrustZone::Untrusted` (triggers `floating_image` rule).
  - `services:` — each service entry emits an `Image` node.
  - `environment:` — environment name recorded as step metadata.
  - `include:` — marks graph `Partial`.
  - `extends:` — marks graph `Partial` (job template inheritance not resolved).
  - `rules: if: $CI_PIPELINE_SOURCE == "merge_request_event"` — sets `META_TRIGGER = "merge_request"`.
  - `only: [merge_requests]` — sets `META_TRIGGER = "merge_request"`.
  - `META_JOB_NAME` stamped on all step nodes (enables `--job` subgraph filtering).

- **`--platform gitlab` flag** — forces GitLab CI parsing; auto-detect also recognises `.gitlab-ci.yml` files by YAML structure.

- **Auto-detect disambiguation** — `stages:` as a flat string list (GitLab) is now distinguished from `stages:` as a list of objects (ADO). Previously, any file with `stages:` was classified as ADO.

### Behavioral changes (upgrade notes)

- **Auto-detect change**: files containing `stages: [build, test, deploy]` (flat string list) were previously classified as ADO and likely failed to parse. They are now correctly identified as GitLab CI.
- **`make_parser` match is exhaustive**: library users who pattern-match on `Platform` will need to add a `Platform::GitLab` arm.

## v0.4.1 — 2026-04-26

### Changed

- **`taudit explain <rule>` now links to the rule documentation page** — output ends with `See: https://github.com/0ryant/taudit/blob/main/docs/rules/{id}.md`. Users running `taudit explain trigger_context_mismatch` will see a direct link to the full remediation guide with examples and context. No behavioral change to scanning.

## v0.4.0 — 2026-04-25

### Added

- **Custom YAML rule loading** — `taudit scan --rules-dir <path>` loads user-defined rules from a directory of YAML files at runtime. Each rule file specifies declarative `match` predicates on the propagation source node (node type, trust zone, metadata), sink node, and path (trust zones crossed). Matching rules produce `Finding` objects that appear in all output formats — terminal, JSON, CloudEvents JSONL, and SARIF. SARIF output dynamically registers custom rule IDs alongside the built-in rule catalog. Invalid rule files produce descriptive errors; the scanner never panics on bad input. This enables enterprise teams to add org-specific detection (e.g., "our production token must never reach an unpinned action") without recompiling. Rule format documentation in `docs/custom-rules.md`.

- **`taudit map --format dot`** — outputs the authority graph as Graphviz DOT syntax. Pipe to `dot -Tsvg -o map.svg` or `dot -Tpng -o map.png` for visual rendering. Node shapes encode `NodeKind` (Secret=box, Identity=diamond, Step=ellipse, Image=cylinder); node colors encode `TrustZone` (FirstParty=green, ThirdParty=yellow, Untrusted=red); edge labels encode `EdgeKind`. Combine with `--job` for focused subgraph diagrams.

- **`taudit map --job <name>`** — restricts the authority map to the subgraph reachable from a single job's steps (via BFS across all edge kinds). Pairs with `--format dot` to produce per-job authority diagrams in large mono-repo pipelines. Unknown job names produce a descriptive error listing all available job names.

- **`META_JOB_NAME` node metadata** — all `Step` nodes now carry a `job_name` metadata key set by both the GHA and ADO parsers. This enables `--job` filtering and is visible in `--verbose` scan output and JSON/SARIF reports.

### Behavioral changes (upgrade notes)

Upgrading from v0.3.x is safe for existing workflows:

- All existing `taudit scan` and `taudit map` invocations are unchanged — new flags are opt-in.
- **`taudit-report-sarif` library users:** `emit_multi` is replaced by `emit_multi_with_custom_rules`. Pass an empty slice for `custom_rules` to get identical behavior. This is a minor API break for direct library consumers; the CLI handles it transparently.

## v0.3.0 — 2026-04-25

### Added

- **Composite action inlining** — local composite actions (`uses: ./path/to/action`) are now parsed end-to-end. The GHA parser loads `action.yml` relative to the repository root, inlines each composite step as a proper `Step` node in the authority graph, and adds `DelegatesTo` edges from the calling step. Previously, local composite actions were classified as FirstParty but their sub-steps were hidden — any secrets or identities flowing through them were invisible to the graph. Pipelines using composite actions will see more complete finding coverage. When `action.yml` is missing or `using:` is not `composite`, the graph is marked `Partial` with a descriptive reason.

- **OIDC severity escalation** — OIDC cloud identities (`META_OIDC = "true"`, e.g. AWS `role-to-assume`, GCP workload identity federation, Azure federated credentials) propagating to any third-party sink are now **Critical**, regardless of whether the sink is SHA-pinned. Previously, an OIDC identity reaching a SHA-pinned third-party action was scored High. Cloud identity tokens carry direct blast radius to the cloud role — no further credential is needed — so SHA pinning does not bound the impact. Non-OIDC propagation to SHA-pinned actions remains High.

- **ADO environment approval boundaries** — Azure DevOps deployment jobs with an `environment:` key and required approvals now create an explicit propagation boundary in the graph. Findings that cross an environment-gated boundary are reduced one severity step (Critical→High, High→Medium, Medium→Low). Non-gated ADO jobs are unaffected.

### Behavioral changes (upgrade notes)

Upgrading from v0.2.x may change findings on existing pipelines:

1. **New findings** — pipelines using local composite actions will produce findings for previously hidden sub-steps.
2. **Severity increases** — OIDC-sourced propagation to SHA-pinned third-party actions is now Critical (was High). CI gates checking `--severity-threshold critical` will see new failures on unchanged pipeline YAML.
3. **Severity decreases** — ADO pipelines with environment approval gates will see some findings downgraded by one step.

## v0.2.7 — 2026-04-25

### Fixed

- **`taudit explain` missing rule** — `checkout_self_pr_exposure` was not registered in the SARIF rule catalog (`taudit-report-sarif::all_rules()`), so `taudit explain` listed 16 rules and `taudit explain checkout_self_pr_exposure` returned an error. Rule definition added with full description, severity (High), and tags.

## v0.2.6 — 2026-04-25

### Added

- **`--platform auto` (default)** — taudit now auto-detects each pipeline file's platform independently by sniffing top-level YAML structure: top-level `on:` key → GitHub Actions; `trigger:`, `pr:`, `stages:`, or `jobs:` (without `on:`) → Azure DevOps; fallback → GitHub Actions. Previously the default was `--platform github-actions`, silently producing 0 findings when scanning ADO repos without an explicit `--platform azure-devops` flag. Each file is detected independently, so mixed-platform directories work correctly.

- **`checkout_self_pr_exposure` rule** (High) — fires when a PR-triggered pipeline checks out the repository (`META_CHECKOUT_SELF = "true"` on a Step node when `META_TRIGGER = "pr"` or `"pull_request_target"`). Attacker-controlled code from a forked PR lands on the runner and is readable by all subsequent steps. Applies to both GHA (`pull_request_target`) and ADO (`pr:` trigger). This is the 17th rule in taudit's rule set.

- **Composite GitHub Action** (`.github/actions/taudit-scan/`) — drop-in `uses: ./.github/actions/taudit-scan` integration for any GitHub workflow. Inputs: `paths`, `platform` (default: `auto`), `severity-threshold`, `format`, `fail-on-findings`, `version`, `extra-args`. Output: `findings-count`.

- **PR authority diff workflow** (`.github/workflows/taudit-pr-diff.yml`) — triggers on pull requests that touch pipeline files (`.github/workflows/**`, `azure-pipelines*.yml`, `**/.pipelines/**`). Diffs the authority graph between base and head, posts a PR comment with the per-file diff, and scans the PR head for High/Critical findings as a non-blocking `::warning::` annotation.

- **taudit self-scan in CI** — `quality.yml` now runs `taudit scan .github/workflows/ --platform github-actions --severity-threshold high --quiet` on every push and PR, emitting a `::warning::` annotation if findings are found (non-blocking gate).

## v0.2.5 — 2026-04-25

### Changed

- **`taudit map` layout rewrite** — table now fits the terminal window without wrapping:
  - Zone column abbreviated: `FirstParty`→`1P`, `ThirdParty`→`3P`, `Untrusted`→`?` (saves 8+ chars per row)
  - Step names capped at 28 chars with `…`; authority column names capped at 18 chars
  - Authority columns paginate into labelled groups (`columns 1–4 of 12`) when the full table exceeds terminal width
  - Terminal width read from `$COLUMNS` env var (set by interactive shells); falls back to 120
  - Markers changed to `✓` (has access) and `·` (no access) for visual clarity

## v0.2.4 — 2026-04-25

### Added

- **SARIF fingerprint collapse** — `partialFingerprints.primaryLocationLineHash` now keys on `rule_id + "::" + root_authority_node_name` so GitHub Code Scanning groups all per-hop propagation findings from the same secret or identity into a single alert. Findings without a Secret/Identity node (e.g. `authority_cycle`, `floating_image`) fall back to the prior `rule_id + uri + message` hash.

- **`--omit-empty` flag** — in `--quiet` mode, files with zero findings are silently skipped. Previously every scanned file appeared in the output even when clean.

- **`--collapse-template-instances` flag** — groups findings sharing the same `(category, root authority node)` within a file into one summary finding. The highest severity is kept; the message becomes `"N occurrences of <category>: [node1, node2, ...]"`. On a 276-file ADO corpus this cuts raw output from 1 364 findings to 754 (45% reduction for pipelines that reference shared templates multiple times).

### Fixed

- **`--ignore-file` error message** — the serde_yaml error for a plain-text ignore file now shows the expected YAML format and directs users to `taudit explain` for rule IDs.

- **`untrusted_with_authority` ADO noise** — `System.AccessToken` is tagged `implicit: true` in the ADO parser. The rule downgrades to Info severity with a note explaining that this token is platform-injected and structurally available to all tasks by design. Explicit secrets remain Critical.

## v0.2.3 — 2026-04-25

### Added

- **3 new ADO PR-boundary rules** — all gate on `trigger=pr` context so they fire only when attacker-controlled code is involved, not on every pipeline:
  - `variable_group_in_pr_job` (Critical) — ADO variable group secrets are reachable from a PR-triggered job; malicious PR code can exfiltrate them via log output or network calls.
  - `self_hosted_pool_pr_hijack` (Critical) — PR-triggered job runs on a self-hosted agent and checks out the repository; attacker can inject malicious git hooks that persist on the shared runner and execute with full pipeline authority on subsequent runs.
  - `service_connection_scope_mismatch` (High) — broad-scope ADO service connection (subscription-wide Azure RBAC, no OIDC federation) is reachable from a PR-triggered job, enabling lateral movement into the Azure tenant.

- **Parser tagging for new rules:**
  - ADO: `pool.name` without `vmImage` → Image node tagged `self_hosted: true`; variable group secrets tagged `variable_group: true`; `checkout: self` steps tagged `checkout_self: true`; service connections tagged `service_connection: true`.
  - GHA: `runs-on: self-hosted` (string, sequence, or group mapping) → Image node tagged `self_hosted: true`; `actions/checkout` steps tagged `checkout_self: true` regardless of pin level (trigger context gates the rule, not the pin).

- **`taudit explain` subcommand** — `taudit explain` lists all 16 rules with severity. `taudit explain <rule>` shows the full description, tags, and remediation guidance. Unknown rule exits 2 with the valid ID list.

### Fixed

- **`cargo fmt`** — format gate now passes on all crates.

## v0.2.2 — 2026-04-25

### Fixed

- **Multi-document YAML** — pipeline files using `---` document separators now parse correctly. Both the GHA and ADO parsers use `serde_yaml::Deserializer` to read the first document cleanly; if additional documents are present the graph is marked partial with an explanatory gap note. Previously taudit errored out immediately on any `---`-separated file.
- **`cargo deny` Zlib license** — `foldhash v0.2.0` (transitive via `jsonschema → reqwest → hashbrown`) was rejected by the licence allowlist. `Zlib` added to `deny.toml`.
- **`rustls-webpki` security advisory** — updated `rustls-webpki` from `0.103.12` to `0.103.13` to resolve RUSTSEC-2026-0104 (reachable panic in CRL parsing, transitive via `reqwest`).

## v0.2.1 — 2026-04-25

### Fixed

- **SARIF output with multiple files** — scanning a directory or passing multiple paths with `--format sarif` previously emitted one complete SARIF document per file, concatenated end-to-end. Downstream consumers (`jq`, `sarif-tools`, VS Code SARIF Viewer, any `json.load`) failed with `JSONDecodeError: Extra data`. All findings are now aggregated into a single SARIF 2.1.0 document with one `runs[0]` entry, as the spec requires.

## v0.2.0 — 2026-04-25

### Added

- **Azure DevOps platform support** — `--platform azure-devops` parses ADO YAML pipelines (stages/jobs/steps, all three shapes). Detects System.AccessToken, service connections, variable groups, `$(VAR)` references, and template references.
- **`PersistsTo` edge** — new graph edge kind for credentials written to disk (e.g. `persistCredentials: true` on checkout steps).
- **`PersistedCredential` finding** — fires High severity when a checkout step writes credentials to `.git/config`, making the token available to all subsequent steps.
- **`-var` flag exposure detection** — secrets passed as Terraform `-var "key=$(SECRET)"` arguments are marked `cli_flag_exposed: true`. The `UntrustedWithAuthority` finding message and remediation now note the log exposure risk and recommend `TF_VAR_*` env vars instead.
- **Colored CI output** — ANSI color is now on by default. GitHub Actions and Azure DevOps log viewers render it from piped stdout. Disable with `--no-color` or `NO_COLOR` env var (any value).
- **Redesigned terminal reporter** — severity-keyed colors, per-file horizontal rule headers, `[partial]` tag on every finding from an incomplete graph, node-kind annotations on paths, clean-file suppression (counted in summary instead of noisy per-file output), and a run-level summary footer.
- **Graceful CI artifact paths** — runtime artifact paths (telemetry, receipts, logs) now resolve independently. If HOME/XDG is unset (minimal CI containers), artifacts are silently skipped instead of hard-failing before any scanning occurs.

### Changed

- `EgressBlindspot` and `MissingAuditTrail` finding categories are reserved for future API-enriched implementations and marked `#[doc(hidden)]`. They cannot be detected from pipeline YAML alone.

## v0.1.1

Patch release to refresh crates.io metadata and release surfaces.

Highlights:

- publish corrected repository and owner metadata for the canonical `0ryant/taudit` source
- carry the shared-envelope CloudEvents provenance and correlation work into the next published crate set
- keep workspace crate versions aligned for the next cargo publish

## v0.1.0

Initial public release of `taudit`.

Highlights:

- GitHub Actions authority-graph parsing
- authority propagation and privilege finding rules
- terminal, JSON, SARIF, and CloudEvents output modes
- CLI support for scan, map, diff, version, and CellOS spec emission
- JSON schemas and example reports for machine-readable integrations