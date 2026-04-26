# Changelog

All notable changes to this project will be documented in this file.

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