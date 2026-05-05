# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Detection delta (read first)

_(none yet — populate this paragraph when adding entries that change finding behaviour)_

### Fixed

### Changed

### Added

### Migration notes

_(populate if any consumer-visible field, schema, or contract changes; remove subsection if none)_

## v1.1.0-rc.3 — 2026-05-05 (release candidate)

> **Release candidate.** Supersedes `v1.1.0-rc.2`, which partially published
> lower-level crates before crates.io rejected `taudit-parse-bitbucket` for
> missing package metadata. `v1.1.0-rc.3` carries the same detection payload as
> `rc.2`, adds the missing Bitbucket parser crate description, and adds a CI
> release gate so publish metadata fails before any registry upload.

### Detection delta (read first)

No rule, parser, report, or schema behaviour change versus `v1.1.0-rc.2`.

### Fixed

- Added required crates.io metadata to `taudit-parse-bitbucket`.
- Added `scripts/check-crates-publish-metadata.py` and wired it into the
  release workflow before publish, preventing another partial publish caused by
  missing crates.io package metadata or incoherent release versions.

## v1.1.0-rc.2 — 2026-05-05 (release candidate)

> **Superseded release candidate.** `v1.1.0-rc.2` partially published
> `taudit-api@0.2.0`, `taudit-core@1.1.0-rc.2`, and
> `taudit-parse-ado@1.1.0-rc.2`, then failed before the top-level `taudit`
> crate was published. Use `v1.1.0-rc.3` instead. Stable consumers on v1.0.12 are
> unaffected per [ADR 0004](docs/adr/0004-prereleases-publish-to-crates-io.md).
> This is not promoted to `v1.1.0` stable because
> [`docs/RELEASE_GATES.md`](docs/RELEASE_GATES.md) sets the earliest stable date
> at 2026-05-16, subject to soak and dogfood gates.

### Detection delta (read first)

`v1.1.0-rc.2` is an additive parser/rule/reporting cut driven by the public YAML
corpus pass across GitHub Actions, Azure DevOps, GitLab CI, and Bitbucket
Pipelines. It **will flag more issues** than `v1.1.0-rc.1` on repositories that
use Bitbucket Pipelines, mutable remote scripts, Docker socket / privileged
container patterns, compromised action references, or OIDC identity in
untrusted contexts. It also adds publication-grade context fields to JSON and
SARIF so downstream reports can distinguish YAML-only evidence from runtime
preconditions and portal-side controls.

| Change | Direction | Affects |
|--------|-----------|---------|
| Bitbucket Pipelines parser added and wired into `taudit scan --platform bitbucket` plus auto-detection for `bitbucket-pipelines.yml` | **more findings** (coverage↑) | Bitbucket corpora and any mixed-CI estate using BB pipelines |
| Added/finalised rules for OIDC identity in untrusted context, known compromised action references, floating remote script execution, Docker socket exposure, and privileged CI containers | **more findings** (FN↓) | GHA/ADO/GitLab/BB pipelines with cloud identity, mutable supply-chain, or container escape primitives |
| ADO/GHA/GitLab parser recovery improvements from corpus failures | **fewer parser failures** | Public YAML with non-canonical but recoverable structure |
| JSON/SARIF findings now include `confidence_scope`, `runtime_preconditions`, `portal_control_dependency`, `authority_kinds`, `attacker_surface_kinds`, `template_resolution_strength`, and `cve_relationship` when known | **contract additive** | SIEM, Backstage, reporting, and case-study consumers |
| JSON report `summary.graph_risk_summary` added | **contract additive** | High-volume corpus reporting and executive rollups |

**Net FP/FN risk:** safer but noisier by design. New rules expose previously
missed authority and supply-chain primitives; the added metadata is intended to
make triage less noisy by showing which findings require runtime/platform
preconditions before exploitability is claimed.

### Added

- **Bitbucket Pipelines parser crate** (`taudit-parse-bitbucket`) plus CLI
  platform wiring and corpus harness support.
- **Publication context metadata** on findings: confidence scope, runtime
  preconditions, portal-control dependency, authority kinds, attacker-surface
  kinds, template-resolution strength, and CVE relationship.
- **Graph risk summary** in JSON reports for corpus-scale ranking.
- **Research harnesses and reports** under `scripts/research/` and
  `docs/research/` for public-corpus scanning and vulnerability/rule discovery.
- **AAA roadmap and semantic index** docs for the current repository state.

### Changed

- **`taudit-api` bumped to `0.2.0`** for additive wire-type fields. Downstream
  consumers pinned to `taudit-api = "0.1"` should review the new fields and move
  to `taudit-api = "0.2"` when ready.
- **JSON/SARIF snapshots updated** to pin the additive metadata contract.
- **CloudEvents platform schema** now admits Bitbucket platform spellings.
- **Release workflow semver gate is stable-only.** Prerelease tags still run
  fmt, clippy, tests, deny, audit, publish packaging, SBOM, binaries, and
  crates.io publish, but skip `cargo semver-checks` because the registry
  baseline compares prereleases against the latest stable line.

### Migration notes

- **No CLI flag removal.** Existing `scan`, `verify`, baseline, and sink flags
  remain compatible.
- **Output consumers should tolerate additive fields.** JSON, SARIF, and schema
  contracts gained optional metadata; strict consumers should refresh schemas.
- **Finding counts may increase.** Treat this as an RC re-baseline event for
  estates using Bitbucket, OIDC, Docker-in-Docker, floating script downloads, or
  mutable action references.

## v1.1.0-rc.1 — 2026-05-02 (release candidate)

> **Release candidate.** Published to crates.io under semver pre-release identifier `1.1.0-rc.1`. Opt-in via `taudit = "=1.1.0-rc.1"` or `cargo install taudit --version 1.1.0-rc.1`. Stable consumers on v1.0.12 are unaffected per [ADR 0004](docs/adr/0004-prereleases-publish-to-crates-io.md). Promotion to `v1.1.0` stable is gated by [`docs/RELEASE_GATES.md` §2.2](docs/RELEASE_GATES.md): ≥2 concurrent pilots × 14-day soak × zero new P0/P1 + ≥1 recorded buyer-side reference call.

### Detection delta (read first)

`v1.1.0-rc.1` is the first release candidate after the v1.1.0-beta cycle (.1, .2, .3) closed 2 P0s + ~20 P1s from the 10-agent deep audit. This RC adds **three additional fixes** identified by a structured council debate (transcript at `/tmp/taudit-deep-review/00-synthesis.md` and the post-beta.3 council exchange) as gating procurement-grade adoption. **No new finding-class additions vs `-beta.3`;** strict-superset stance vs v1.0.12 holds.

| Change | Direction | Affects |
|--------|-----------|---------|
| ADO `condition:` and `dependsOn:` now modelled; conditional steps marked `Partial`/`Expression` and stamped with `META_CONDITION` (AND-joined chain across stage/job/step) and `META_DEPENDS_ON` (non-default only) | **fewer findings** (FP↓) | ADO pipelines using `condition: eq(variables['Build.SourceBranch'], 'refs/heads/main')` and similar gating expressions — typical enterprise ADO estates have these on 30–40% of jobs |
| ADO conditional-gate compensating control: a Critical `untrusted_with_authority` finding on a step under `condition:` now downgrades to High via the `with_compensating_control` builder, recording `original_severity` for audit trail | **conservative downgrade** | Same population as above |
| Terminal sink strips C0/C1 control characters + Unicode bidi/joiner steering codepoints from attacker-controllable strings (`finding.message`, `node.name`, `graph.source.file`, gap reasons, custom-rule fields) | **closes ANSI escape injection class** | All terminal-rendered output; was a P2 security blocker per Agent 9 |
| SARIF sink Markdown-escapes `result.message.text` and custom-rule descriptors (`name`, `shortDescription.text`, `fullDescription.text`); built-in `RULE_DEFS` descriptors NOT escaped (author-controlled, intentional Markdown); rule `id` NOT escaped (charset gate enforces snake/kebab/digit) | **closes Markdown / link injection class** in GitHub Code Scanning UI rendering | All SARIF consumers; was a P2 security blocker |
| `cross_sink_contract.rs` and `output_injection_corpus.rs` regression tests **in CI** assert byte-equal fingerprints across JSON / SARIF / CloudEvents under hostile input AND no control bytes / unescaped Markdown delimiters in attacker-controllable rendering paths | **trust-artifact integrity** | Downstream consumers (tsign, Backstage plugins, SIEMs) that re-render taudit's output |

**No fingerprint format change vs `-beta.3`** — fingerprints remain 32-hex (128-bit). Sanitisation deliberately runs AT the render boundary, not at ingest, so fingerprint canonical input is unaffected. Existing baselines from `-beta.3` remain valid.

### Fixed

#### RC blocker A — ADO `condition:` and `dependsOn:` modelling

Previously, ADO stage/job/step `condition:` was unmodelled — `condition: eq(variables['Build.SourceBranch'], 'refs/heads/main')` jobs got authority edges as if they always ran on every PR build, generating false-positive findings on the most common gating pattern in enterprise ADO estates. `crates/taudit-parse-ado/src/lib.rs` now extracts `condition:` and `dependsOn:` on the typed model (`AdoStage` / `AdoJob` / `AdoStep`); marks the graph `Partial` with `GapKind::Expression` whenever a non-empty `condition:` is encountered (gap reason cites the conditional text); stamps `META_CONDITION` on resulting Step nodes (AND-joined chain across stage/job/step); stamps `META_DEPENDS_ON` only when explicitly non-default (ADO's default chain is "depends on previous job in declaration order" — only the explicit override is captured). A new compensating-control arm in `apply_compensating_controls` reads `META_CONDITION` and downgrades severity by one tier on the firing step, routing through the public `Finding::with_compensating_control` builder so `extras.original_severity` and `extras.compensating_controls` survive the downgrade.

#### RC blocker B — Output-channel injection sanitisation

The deep-audit security review (Agent 9) identified two attack classes where adversary-controlled YAML or custom-rule YAML could plant payloads in fields the renderers interpret rather than display: (a) **ANSI escapes in terminal output** — `colored::ColoredString` only wraps with SGR sequences and does not sanitise inner bytes, so a payload `\x1b[2J\x1b[H\x1b[1;32m✓ no findings\x1b[0m` planted in a node name impersonates the success banner; (b) **Markdown / HTML injection in SARIF `result.message.text`** — GitHub Code Scanning UI renders Markdown links inside that field, so a payload `[Click here to remediate](https://attacker.example/?steal=1)` plants a phishing link inside an "authentic" taudit alert.

Two render-boundary primitives, hand-rolled (no new dependencies), `Cow`-returning zero-alloc on clean input:

- `taudit_report_terminal::strip_control_chars(&str) -> Cow<'_, str>` strips ASCII C0 (0x00..=0x1F except `\n`/`\t`), DEL (0x7F), C1 (0x80..=0x9F), Unicode bidi/joiner steering codepoints (U+200B–200F, U+202A–202E, U+2066–2069, U+FEFF). Applied at every terminal call site that renders attacker-controllable strings.
- `taudit_report_sarif::escape_markdown(&str) -> Cow<'_, str>` escapes the exploitable set: `\ [ ] ( ) < > * ` !`. Deliberately omits `_`, `~`, `{}`, `#`, `+`, `-`, `|` to avoid noising up legitimate identifiers like `AWS_KEY`, `my-custom-rule`, `v1.2-beta`.

`crates/taudit-cli/tests/output_injection_corpus.rs` is the new regression test running in CI (per `docs/RELEASE_GATES.md` §2.1). Four tests — one per attack class (raw-shipping JSON, SARIF Markdown escape, terminal control-byte strip, fingerprint stability under hostile input). Plus `cross_sink_contract.rs` extended to assert all three sinks produce byte-equal fingerprints when the input is hostile.

Trust-artifact angle: tsign signs taudit's output. If an attacker controls rendered bytes, the signature attests to "this YAML produced this graph" — not "this graph is safe to display." Sanitisation closes that chain-of-custody hole.

#### RC blocker C — `taudit-api` wire-types crate extracted at v0.1.0

New `crates/taudit-api/` crate at version `0.1.0` owns every Rust type that appears in taudit's emitted JSON / SARIF / CloudEvents output. 76 public items: 11 enums (`Severity`, `FindingCategory`, `Recommendation`, `FindingSource`, `FixEffort`, `NodeKind`, `EdgeKind`, `TrustZone`, `AuthorityCompleteness`, `IdentityScope`, `GapKind`); 9 structs (`Finding`, `FindingExtras`, `Node`, `Edge`, `PipelineSource`, `ParamSpec`, `AuthorityEdgeSummary`, `PropagationPath`); 2 type aliases (`NodeId`, `EdgeId`); 54 constants (`AUTHORITY_EDGE_SUMMARY_FIELD_MAX` + 53 `META_*` keys); 2 `#[doc(hidden)]` helpers (`downgrade_severity`, `serialize_string_map_sorted`).

Dependency direction: `taudit-core` → `taudit-api` → `{serde, serde_json}`. `taudit-api` is the leaf — zero internal deps.

Backward compatibility: `taudit-core` `pub use`-re-exports every type that moved. `taudit_core::finding::Finding` and `taudit_core::graph::NodeKind` continue to compile unchanged for all in-tree sinks, parsers, rules, tests, and any out-of-tree consumer that pinned `taudit-core`. Confirmed by 715/715 tests passing and zero snapshot churn.

Stability promise (see `crates/taudit-api/src/lib.rs` crate-root docstring): at `0.x` additive minor bumps may add new variants/fields; consumers should pin a minor (`taudit-api = "0.1"`) and review on each upgrade. At `1.0` the promise lifts — only a `2.0` major may break compatibility. `cargo semver-checks check-release` (already in `release.yml`) gates ABI changes.

Crate-root `#![deny(missing_docs)]` enforces docstring discipline on every public name. `cargo doc -p taudit-api --no-deps` validates the lint at build time.

Downstream tooling guidance (now that the contract is real): tsign, axiom, custom SIEM integrations, Backstage plugins, and any external consumer should depend on `taudit-api` directly rather than `taudit-core`. `taudit-core` is workspace-internal and may break between minors per the API stability policy ([memory: `project_api_stability_policy.md`](#)); `taudit-api` is the public contract.

### Added

- **`docs/RELEASE_GATES.md`** — pre-committed promotion criteria for beta → rc and rc → stable cuts, plus calendar-anchored milestones for tsign integration GA (Q1 2027) and axiom enforcement integration GA (Q3 2027). Direct outcome of the council debate at `/tmp/taudit-deep-review/00-synthesis.md`. Codifies §2.1 hard gates (fmt, clippy, test, schema-generator `--check`, `cargo semver-checks`, CHANGELOG detection-delta paragraph), §2.2 promotion gates (the 2 × 14-day × 0 P0/P1 + recorded reference call rule), §3 calendar anchors ("version-as-promise rots; quarters anchor"), and §4 three-lens framework (engineering / customer / adversary).
- **`crates/taudit-api/`** — new leaf crate at v0.1.0; see RC blocker C above.
- **`crates/taudit-cli/tests/output_injection_corpus.rs`** — regression test in CI for ANSI / Markdown / Unicode-RTL injection; see RC blocker B above.

### Migration notes

- **Downstream Rust consumers should migrate to `taudit-api` for stable wire types.** `taudit-core` re-exports keep existing imports compiling; new code should import from `taudit-api`. Add `taudit-api = "0.1"` to `Cargo.toml` and pin a minor.
- **No fingerprint format change.** Existing `-beta.3` baselines remain valid; no re-baseline required for this RC. (The fingerprint format change happened in `-beta.3` — 16-hex → 32-hex / 64-bit → 128-bit. If you skipped `-beta.3` entirely and are upgrading directly from v1.0.12, see the `-beta.3` migration note.)
- **ADO `condition:` modelling will change Partial/Complete classifications** for any pipeline using `condition:`. Workflows previously reported `Complete` may now report `Partial` with an Expression gap. The compensating control downgrades severity for the conditional-gate case but does not eliminate the finding — operators on heavily-conditional ADO pipelines may want to combine with `--ignore-partial` per `docs/baselines.md`.
- **No CLI flag changes; no schema URI changes; no schema dialect changes.**

## v1.1.0-beta.3 — 2026-05-02 (prerelease)

> **Prerelease.** Published to crates.io under semver pre-release identifier `1.1.0-beta.3`. Opt-in via `taudit = "=1.1.0-beta.3"` or `cargo install taudit --version 1.1.0-beta.3`. Stable consumers on v1.0.12 are unaffected per [ADR 0004](docs/adr/0004-prereleases-publish-to-crates-io.md).

### Detection delta (read first)

This is a substantial cut driven by a 10-agent comprehensive deep audit (`/tmp/taudit-deep-review/00-synthesis.md`). It closes 2 P0s and ~20 P1s, including a P1 security finding in the suppression contract.

| Change | Direction | Affects |
|--------|-----------|---------|
| GHA secret extraction now scans only inside `${{ … }}` template spans (no longer matches literal `secrets.X` substrings in comments / shell paths) | **fewer findings** (FP↓) | Workflows where comments or shell paths contain `secrets.<token>` literals |
| GHA `${{secrets.X}}` (no spaces) now recognised | **more findings** (FN↓) | Every workflow using the canonical terse form — previously **silently missed every secret edge** |
| GHA concatenated multi-secret values now extract all secrets, not just first | **more findings** (FN↓) | Workflows using values like `"${{ secrets.A }}-${{ secrets.B }}"` |
| GHA reusable-workflow `secrets:` map form now propagates HasAccessTo edges | **more findings** (FN↓) | Workflows calling reusable workflows with explicit `secrets: { K: ${{ secrets.X }} }` |
| GitLab `$CI_COMMIT_REF_PROTECTED == "false"` no longer counted as protected-only | **more findings** (FN↓) | GitLab pipelines with negation-form deploy gates that previously silenced `gitlab_deploy_job_missing_protected_branch_only` |
| Schema-validation contract: 4 schemas now enumerate all 63 `FindingCategory` variants (was 10–39); CI fails on Rust↔schema drift | **no detection delta** but **53 of 63 categories now schema-valid** | Any consumer with strict JSON-schema validation |
| `pipeline_identity_material_hash` and `compute_fingerprint` now normalise path separators to `/` | **no detection delta** but **fingerprints stable across Windows ↔ Linux** | Cross-platform CI matrices |
| **Fingerprint widened from 64 bits to 128 bits (16 hex → 32 hex)** | **breaking for fingerprint consumers** | All `.taudit-suppressions.yml` and per-finding baseline entries — see Migration notes |
| 8 previously-empty `nodes_involved` rules now carry stable anchors | **no detection delta** but **per-rule findings no longer collide on fingerprint** | SIEM dedup pipelines on `unpinned_include_remote_or_branch_ref`, `template_extends_unpinned_branch`, `sensitive_value_in_job_output`, `no_workflow_level_permissions_block`, `pull_request_workflow_inconsistent_fork_check`, `template_repo_ref_is_feature_branch` |

**Net FP/FN risk:** mixed but *strictly safer*. Fewer false positives on benign GHA workflows; fewer false negatives on the canonical terse-template form, multi-secret values, reusable-workflow callees, and GitLab negation-form deploy gates. **A real workflow scanned on v1.0.12 should produce a strict superset of true findings on v1.1.0-beta.3 — no genuine issue is now silently dropped.**

### Fixed

#### Closed P0 — schema↔Rust enum drift

- **Category enum drift in 4 schemas** (`contracts/schemas/taudit-report.schema.json`, `contracts/schemas/taudit-cloudevent-finding-v1.schema.json`, `schemas/finding.v1.json`, plus the auto-generated `authority-invariant-v1.schema.json`) — they enumerated 10/39/63 of `FindingCategory`'s 63 variants. `additionalProperties: false` made findings emitted by 53 of 63 rules byte-valid but schema-invalid. Schema-validation tests were blind because every test fired `UnpinnedAction` or `AuthorityPropagation`. Extended `scripts/generate-authority-invariant-schema.py` to stamp all four schemas; the existing `--check` CI step now fails the build on any future drift. Property test `every_finding_category_variant_validates_against_report_schema` (and the parallel CloudEvents test) iterates all 63 variants. ([Agent 10](docs/adr/) Findings 2 + 3.)

#### Closed P1 — GHA parser correctness (5 fixes)

- **`run:` script extractor matched literal `secrets.X` substrings** outside `${{ … }}` template spans → phantom Secret nodes named `json`, `conf` from comments and shell paths. New `iter_secret_refs(s)` helper walks template spans only.
- **`is_secret_reference` required exactly one space** → `${{secrets.X}}` (the canonical terse form, no spaces) silently missed every secret edge. The new helper is whitespace-tolerant.
- **`extract_secret_name` found only the first `secrets.X`** per env/with value → concatenated multi-secret values lost every secret after the first. Iterator-based callers loop over every match.
- **Reusable workflow `secrets:` map form silently dropped** — only the literal `inherit` string was inspected. Mapping form `secrets: { CHILD: ${{ secrets.PARENT }} }` now propagates `HasAccessTo` edges.
- **Reusable-workflow synthetic step skipped workflow.env entirely** — workflow-level env IS in scope for the caller's evaluation of `secrets:` and `with:` (job.env is not). Now applied.

#### Closed P1 — GHA HashMap iteration (2 fixes missed by v1.1.0-beta.1)

- `META_JOB_OUTPUTS` writer iterated `job.outputs: HashMap` unsorted. Now sorted by key.
- `Permissions::Map` `Display` impl iterated `HashMap` unsorted. Type changed to `BTreeMap<String, String>`.

#### Closed P1 — GitLab parser correctness (1 + 5 P2)

- **`$CI_COMMIT_REF_PROTECTED` substring match accepted the negation** (`== "false"`) → silenced `gitlab_deploy_job_missing_protected_branch_only` on the exact deploy-on-feature-branch jobs the rule was meant to catch. New `check_truthy_comparison` helper parses to operator level. Same fix class on `$CI_COMMIT_TAG` and the MR-trigger detector.
- `id_tokens.aud` list form (multi-cloud broker) collapsed to `aud=unknown`; now stamps `META_OIDC_AUDIENCES` with the comma-joined list.
- `is_credential_name` boundary-checked: `CERTAIN_FLAG`, `TOKENIZER_VERSION`, `UNCERTAIN`, `CERTIFICATE_PATH` no longer create phantom Secret nodes.
- `needs.artifacts: false` now honoured (was ignored, so dotenv-flow rule reported flows GitLab won't actually create).
- Determinism convention adopted: GitLab parser now sorts mapping iteration matching the established GHA + ADO `// determinism: sort by key` pattern.

#### Closed P1 — Fingerprint contract holes

- **Path-separator normalisation in fingerprint canonical input.** `compute_fingerprint` now normalises `\` → `/` in `graph.source.file` before hashing. Windows scan + Linux baseline now produce identical fingerprints for the same logical finding. Same fix in `Baseline::from_findings`'s `pipeline_path`.
- **🔒 Fingerprint widened from 64 bits to 128 bits.** Closes a P1 security finding: birthday collision against a public `.taudit-suppressions.yml` was ~2³² trials = single-digit hours on a laptop. The 128-bit truncation moves the bound to 2⁶⁴, computationally infeasible. **Existing 16-hex baselines need re-baselining once.** Three golden fingerprints are pinned in `finding.rs` so any future algorithm change requires a deliberate update + CHANGELOG entry.
- **DRY refactor:** `extract_custom_rule_id` and `category_rule_id` were duplicated in `finding.rs`, `baselines.rs`, and `taudit-report-sarif`. Local copies deleted; `finding::rule_id_for` is now the single source of truth. `category_rule_id` is an explicit `match` returning `&'static str` (no serde indirection — a future `#[serde(tag)]` change can no longer silently turn every rule_id into `"unknown"`). `extract_custom_rule_id` tightened to `^[a-z][a-z0-9_]*$` so emphasis phrases like `[high blast-radius]` no longer mis-attribute built-in findings.

#### Closed P1 — `verify` exit code + CLI round-trip

- **`verify` SARIF render error now preserves exit 1** when policy violations exist (was returning exit 2, clobbering the merge-gate signal). Documented in a comment: "policy violation outranks render error."
- **`taudit emit-spec --platform gitlab`** round-trip fixed — `Platform::as_str()` now returns `"gitlab"` matching the clap value name (was `"gitlab-ci"` which clap rejected when the spec was replayed).
- **`taudit completions zsh | head` no longer panics on SIGPIPE** — the single missed `SilenceBrokenPipe` site from the v1.0.5/v1.0.7 EPIPE hardening.

#### Closed P1 — CloudEvents `tauditruleid` extension

- CloudEvents previously emitted only `type` for rule shape; the `[id]` prefix in custom-rule messages was ignored. Now a `tauditruleid` extension attribute (lowercase, CloudEvents 1.0 §3.1) is populated from `rule_id_for(finding)`. **JSON, SARIF, and CloudEvents now agree on the rule id for every finding** — verified by the new `cross_sink_contract` integration test.

#### Closed P1 — Custom-rule loader hardening

- `load_rules_dir` now actually recursive (was documented "recursive" but used non-recursive `read_dir`). Subdirectory rules previously loaded as zero invariants with no diagnostic.
- In-tree symlinks now deduplicated by canonical target (was loading the same rule twice — bug enshrined in tests; test rewritten).
- Custom-rule `id` validated at deserialise time: `^[A-Za-z_][A-Za-z0-9_-]{0,63}$`. YAML with `id: "foo] [bar"` now errors with a clear message.

#### Closed P1 — propagation summary `GapKind` taxonomy

- `AuthorityPropagationSummaryDocument` now carries `completeness_gap_kinds` and a derived `worst_gap_kind: Option<GapKind>`. Schema bumped 1.0.0 → 1.1.0 (additive, non-breaking; const constraint loosened to `^1\.\d+\.\d+$` pattern). Severity ordering follows `GapKind::worst_gap_kind`'s existing impl: Opaque > Structural > Expression.

### Changed

- **Reserved categories sealed against custom YAML.** `EgressBlindspot` and `MissingAuditTrail` are `#[doc(hidden)]` and reserved for future runtime-enrichment detection. Custom YAML attempting to emit them now errors at deserialise time via `#[serde(skip_deserializing)]`. Built-in code that constructs these variants in Rust still serialises correctly.
- **`taudit-core` API stability policy.** The cross-sink helpers (`compute_fingerprint`, `compute_finding_group_id`, `rule_id_for`, `downgrade_severity`) stay `pub` for inter-crate visibility but are now `#[doc(hidden)]` with a module-level docstring stating: "taudit-core is a workspace-internal library, NOT a stable public API. External consumers should consume the JSON / SARIF / CloudEvents output contracts." See ADR 0001 (graph as product) and ADR 0004. `cargo semver-checks check-release` is now a CI gate so even hidden-but-public symbols can't accidentally break between minor versions.
- **Determinism guards extended.** `META_JOB_OUTPUTS` and `Permissions::Map` (GHA), plus all four mapping-iteration sites in the GitLab parser, now follow the explicit sort-by-key convention. New byte-determinism regression tests on SARIF, CloudEvents stable bits, and Terminal output (the JSON sink had this since v0.9.1; the other three were unguarded against the same HashMap-iteration class).
- **Out-of-range `NodeId` in `nodes_involved`** now emits `<missing:N>` sentinel rather than silently eliding (could previously cause two distinct findings to collapse onto one fingerprint).

### Added

- **Cross-sink contract test** (`crates/taudit-cli/tests/cross_sink_contract.rs`) asserts JSON, SARIF, and CloudEvents emit byte-identical fingerprints AND rule ids for the same finding, including custom-rule cases. Pins the contract documented in `docs/finding-fingerprint.md`.
- **Property test** iterating every `FindingCategory` variant against the published JSON Schema. Replaces the previous coverage gap where only `UnpinnedAction` / `AuthorityPropagation` were ever validated.
- **Three golden fingerprint pins** in `finding.rs` to lock the v3 algorithm output: any future change forces a deliberate update + CHANGELOG entry.
- **`cargo semver-checks check-release`** in `release.yml` (between `cargo test` and `cargo deny`) — enforces the API stability policy.
- **Documentation refreshed** end-to-end: schema URI namespace canonicalised across all docs (4 stale references the audit didn't initially catch were also found and fixed); USERGUIDE / verify.md / man page version pins refreshed; `docs/baselines.md` gains a "Migration: v1.1.0-beta.1 baseline hash break" subsection; ROADMAP "Visual Summary" footer (which had drifted out of sync with the charter table) deleted; ADR 0002 status bumped from Proposed to Accepted (every phase is shipped in-tree).

### Migration notes

- **Re-baseline once after upgrading.** Fingerprints widened from 16 hex to 32 hex. Existing `.taudit/baselines/<hash>.json` files keep working at the file-discovery layer (`pipeline_content_hash` is unchanged), but per-finding entries inside them no longer match. Run `taudit baseline init <pipeline-files>` once after upgrading. Suppressions in `.taudit-suppressions.yml` need their `fingerprint:` field updated from 16-hex to the new 32-hex form — re-emit them via `taudit verify --emit-suppressions` (or hand-update from a fresh scan).
- **Schema URI consistency.** Every taudit schema `$id` is now under `https://taudit.dev/schemas/...`. The previous mixed namespace (4 schemas under `github.com/0ryant/taudit/...`) is gone. Consumers that fetched schemas by `$id` need to update.
- **`schema_version` field flips from `"v1"` to `"1.0.0"`** in the JSON report (this happened in v1.1.0-beta.2; mentioned again here because the doc-refresh in this cut updated stale README/USERGUIDE references).
- **Reserved categories sealed.** Any custom YAML emitting `category: egress_blindspot` or `category: missing_audit_trail` now errors at load time. These were always documented as reserved (`#[doc(hidden)]`) but the gate wasn't serde-aware until now.
- **No CLI flag changes that affect existing scripts.** The `Platform::as_str()` round-trip fix is internal; if a script was hand-parsing taudit's emitted CellOS spec and consuming `--platform gitlab-ci`, it now sees `--platform gitlab` (which clap accepts cleanly).

## v1.1.0-beta.2 — 2026-05-02 (prerelease)

> **Prerelease.** Published to crates.io under semver pre-release identifier `1.1.0-beta.2`. Same opt-in semantics as `-beta.1`: `taudit = "=1.1.0-beta.2"` or `cargo install taudit --version 1.1.0-beta.2`. Stable consumers on v1.0.12 are unaffected. See [ADR 0004](docs/adr/0004-prereleases-publish-to-crates-io.md).

### Detection delta (read first)

**No detection changes in this release.** This is a pure schema-contract canonicalisation cut — every change is to schema-side metadata (URIs, version strings, JSON Schema dialect). Findings, fingerprints, baselines, and graph content are byte-identical to `v1.1.0-beta.1` on every fixture.

### Changed (schema contract — no detection delta)

- **Schema URI namespace canonicalised to `taudit.dev`** ([`schemas/`](schemas/), [`crates/taudit-report-json/src/lib.rs`](crates/taudit-report-json/src/lib.rs), [`crates/taudit-core/src/summary.rs`](crates/taudit-core/src/summary.rs)) — four schemas previously used `$id` under `github.com/0ryant/taudit` while four others used `taudit.dev`. A consumer indexing schemas by `$id` saw two vendor namespaces for the same product. Every schema `$id` and matching Rust `*_SCHEMA_URI` constant now points to `https://taudit.dev/schemas/...`. SARIF `TOOL_URI` and `RULES_BASE_URI` remain on github.com — those are documentation links, not schema `$id`s.
- **JSON report `schema_version` format `"v1"` → `"1.0.0"`** ([`crates/taudit-report-json/src/lib.rs`](crates/taudit-report-json/src/lib.rs), [`contracts/schemas/taudit-report.schema.json`](contracts/schemas/taudit-report.schema.json), example fixtures) — the standalone graph schema was already on semver `"1.0.0"`; the report's prefixed `"v1"` couldn't express the additive 1.x.y / breaking 2.0.0 contract that ROADMAP promises. Future additive changes will bump the const to `1.1.0` (etc) by editing the const + a CHANGELOG entry. JSON sink output's `schema_version` field changes from `"v1"` to `"1.0.0"` accordingly — consumers that key on the literal `"v1"` need to update.
- **JSON Schema dialect migrated draft-07 → 2020-12** ([`schemas/authority-graph.v1.json`](schemas/authority-graph.v1.json), [`schemas/baseline.v1.json`](schemas/baseline.v1.json), [`schemas/authority-propagation-summary.v1.json`](schemas/authority-propagation-summary.v1.json)) — three schemas were on draft-07 while the other five were on 2020-12. Validators that pin one dialect (older Python jsonschema, Go gojsonschema; vs modern ajv strict, Rust jsonschema crate) couldn't consume the contract uniformly. All eight schemas now speak draft 2020-12 (`$schema` URL + `definitions` → `$defs` + `#/definitions/X` → `#/$defs/X`). Pure dialect-only migration; the features used (type, const, required, additionalProperties, enum, properties, items, $ref, format, pattern, minimum, description, union types) are syntactically and semantically identical between the two dialects.

### Migration notes

- **`schema_version: "v1"` → `"1.0.0"`.** Consumers that filter or branch on the literal string `"v1"` need to update. `"1.0.0"` is the pre-existing format used by every other taudit schema; this cut closes the inconsistency.
- **`$id` host change.** Schemas that resolve `$id` for caching / fetching (most validators just use it as an identifier, but some do fetch) now report `taudit.dev`. The URLs are still logical identifiers — they may not resolve over HTTP, as the schema description prose has always stated.
- **Dialect change in three schemas.** Validators auto-detect dialect from `$schema`, so most consumers see no impact. If you cache compiled schemas keyed by dialect, invalidate that cache for `authority-graph.v1.json`, `baseline.v1.json`, `authority-propagation-summary.v1.json`.
- **No CLI flag changes, no rule changes, no fingerprint changes, no baseline format changes.** A consumer who was on `v1.1.0-beta.1` and re-baselined for that release is on the same baseline contract for `-beta.2`.

## v1.1.0-beta.1 — 2026-05-01 (prerelease)

> **Prerelease.** Published to crates.io under semver pre-release identifier `1.1.0-beta.1`. Cargo's resolver does not pick this up for `taudit = "1"` / `"1.0"` / `"1.1"` consumers or for `cargo install taudit` (no `--version`) — opt-in via `taudit = "=1.1.0-beta.1"` in `Cargo.toml` or `cargo install taudit --version 1.1.0-beta.1`. Stable consumers on v1.0.12 are unaffected. See [ADR 0004](docs/adr/0004-prereleases-publish-to-crates-io.md) and [`docs/release-strategy.md`](docs/release-strategy.md) §4.

### Detection delta (read first)

| Change | Direction | Affects |
|--------|-----------|---------|
| GHA `env:` shadowing now modelled correctly — step-level literal env values **shadow** workflow/job-level secret references for that step | **fewer findings** (FP↓) | `pull_request_target` workflows where a secret is bound at workflow/job scope and a specific step shadows the binding with a literal |
| GHA composite-action inlining (`uses: ./local-action`) **removed**; references now mark the graph `Partial` with a Structural gap | **graph-completeness contract change** + **fewer findings** on inlined sub-steps | Any workflow with local composite actions — graphs flip `Complete` → `Partial`; inlined sub-step findings no longer fire (surface-level findings on the calling step still fire) |
| ADO parser HashMap iteration now sorted at four call sites | **deterministic** — no detection delta in steady state | Same YAML now produces same NodeIds and edge order across runs; baselines stable |
| `pipeline_identity_material_hash` canonical string no longer includes raw `NodeId` | **breaking for baseline consumers** | Existing `.taudit/baselines/<hash>.json` files will not match — one-time re-baseline required (`taudit baseline init`) |

**Net FP/FN risk:** lower-FP (env shadowing fix removes phantom edges; composite-action removal removes inferred-from-disk inlining). No new false negatives — the composite-action inlining was over-promising rather than under-reporting; structural gaps surface honestly via the new `Partial` marker.

**Should you adopt this prerelease?** Yes if (a) you run baselines on real ADO pipelines and have hit non-deterministic suppression breakage, or (b) you maintain `pull_request_target` workflows where step.env shadows a workflow-level secret. The composite-action change reduces graph richness for workflows using local actions; if you depended on inlined sub-step findings, evaluate impact on a representative pipeline before adopting.

### Fixed

- **Baselines: `pipeline_identity_material_hash` no longer leaks `NodeId`** ([`crates/taudit-core/src/baselines.rs`](crates/taudit-core/src/baselines.rs)) — `NodeId` is a `usize` insertion-order index; baking it into the canonical material hash made any benign parser change (e.g. capturing one extra Image node) silently invalidate every existing field baseline via `identity_material_matches`. Names + trust zones alone are sufficient to detect dependency-shape drift, which is what this hash is contracted to detect. Adds regression test `identity_material_hash_is_stable_across_nodeid_shifts`. **Breaking for baseline consumers — re-baseline once after upgrade.**
- **ADO parser: HashMap iteration determinism** ([`crates/taudit-parse-ado/src/lib.rs`](crates/taudit-parse-ado/src/lib.rs)) — `step.env`, `step.inputs`, service-connection scan, and `extract_task_inline_script` previously iterated `HashMap`s in random order. Each value flowed through `extract_dollar_paren_secrets` → `find_or_create_secret` → `graph.add_node`, so per-process random iteration leaked into NodeId allocation order and edge-append order, then into `pipeline_identity_material_hash` via the JSON sink (already byte-deterministic on the report side, but the underlying NodeIds differed). Now sorted by key at all four sites, mirroring the established pattern in `taudit-parse-gha`. Adds regression test `ado_hashmap_iteration_is_deterministic_across_runs` (9× parse, asserts byte-identical NodeId + edge order).
- **GHA parser: `env:` shadowing modelled correctly** ([`crates/taudit-parse-gha/src/lib.rs`](crates/taudit-parse-gha/src/lib.rs)) — three independent passes over `workflow.env` / `job.env` / `step.env` replaced with one merged effective-env pass (workflow ⊕ job ⊕ step, step wins). When a step-level env literal shadows a workflow- or job-level secret reference (the common defence-in-depth pattern on `pull_request_target` workflows), the phantom outer-scope `HasAccessTo` edge no longer fires. Adds regression tests `step_env_literal_shadows_workflow_level_secret` and `step_env_secret_shadows_workflow_level_secret`.

### Changed

- **GHA parser: composite-action inlining removed (Option B1 per audit)** ([`crates/taudit-parse-gha/src/lib.rs`](crates/taudit-parse-gha/src/lib.rs)) — `try_inline_composite_action` (~215 LOC) and `resolve_local_action_path` (~24 LOC) walked the filesystem from `pipeline_file`'s parent up to 6 ancestors looking for an `action.yml` to inline. Same input bytes produced different graphs depending on CWD, absolute-vs-relative `pipeline_file`, and whether the YAML had been copied to a sandbox without the surrounding repo. The on-disk walking is removed entirely; `uses: ./local-action` now marks the graph `Partial` with a `GapKind::Structural` gap (`"composite action not resolved (local action — taudit does not read filesystem)"`). Adds regression tests `composite_action_reference_marks_graph_partial_without_inlining`, `composite_action_secrets_not_captured_after_partial_marking`, `composite_action_resolution_does_not_depend_on_cwd`. **Behaviour change for any workflow with local composite actions — see Detection delta table above.**
- **Release harness: prerelease tags publish to crates.io** ([`.github/workflows/release.yml`](.github/workflows/release.yml), [ADR 0004](docs/adr/0004-prereleases-publish-to-crates-io.md), [`docs/release-strategy.md`](docs/release-strategy.md) §4) — workflow trigger widened to match both `v[0-9]+.[0-9]+.[0-9]+` and `v[0-9]+.[0-9]+.[0-9]+-*`; `gh release create` now passes `--prerelease` for tags containing a hyphen. Stable-lane safety is provided by Cargo's resolver-side prerelease-skip rule, not by withholding the artifact. The earlier "`cargo publish` runs only for stable tags" framing in §4 is superseded.

### Added

- **Ecosystem standard (taudit)** — root **[`standardise-ecosystem.md`](standardise-ecosystem.md)** is the binding checklist; **[`scripts/tool-versions.env`](scripts/tool-versions.env)** + **[`scripts/install-governance-tools.sh`](scripts/install-governance-tools.sh)** pin **gitleaks 8.30.1**, **trivy 0.70.0**, **checkov 3.2.497**, **zizmor 1.24.1** (Linux x86_64). **[`.github/workflows/governance.yml`](.github/workflows/governance.yml)** adds the normative **`governance`** job; **[`.github/workflows/scheduled-fuzz.yml`](.github/workflows/scheduled-fuzz.yml)** runs parser fuzz on **Tuesdays**; **[`release-plz.toml`](release-plz.toml)** + **[`.github/workflows/release-plz.yml`](.github/workflows/release-plz.yml)** (`workflow_dispatch`). **[`rust-toolchain.toml`](rust-toolchain.toml)** (**1.88.0**), **[`.github/CODEOWNERS`](.github/CODEOWNERS)**, **[`.clippy.toml`](.clippy.toml)**, **[`rustfmt.toml`](rustfmt.toml)**, **[`.yamllint`](.yamllint)** + **[`scripts/install-ci-linters.sh`](scripts/install-ci-linters.sh)** (**actionlint** + **yamllint**), **[`.zizmor.yml`](.zizmor.yml)**, **[`scripts/ecosystem-governance-integrations.sh`](scripts/ecosystem-governance-integrations.sh)** (tsafe / CellOS **skip-with-reason** stubs). **`quality-gate.sh ci-governance`** runs **zizmor** (advisory exit), linters, ecosystem script, then **taudit**.
- **FinOps smoke (Terraform + optional Infracost)** — **[`infra/finops-smoke/`](infra/finops-smoke/)** with committed **`.terraform.lock.hcl`**, and **[`.github/workflows/finops.yml`](.github/workflows/finops.yml)** (`terraform fmt` / `validate`; **Infracost** when **`INFRACOST_API_KEY`** is set). Documented in **[`docs/integrations/ci-mirrors.md`](docs/integrations/ci-mirrors.md)** (*FinOps* section) and **[`infra/finops-smoke/README.md`](infra/finops-smoke/README.md)**.
- **ADO stack-integration sketch** — optional **[`azure-pipelines.stack-integration.yml`](azure-pipelines.stack-integration.yml)** (manual trigger) and **[`docs/integrations/ci-mirrors.md`](docs/integrations/ci-mirrors.md)** section for **tsafe / CellOS** parity with [`.github/workflows/stack-integration.yml`](.github/workflows/stack-integration.yml); **[`docs/integrations/index.md`](docs/integrations/index.md)** cross-link.
- **ADR 0004** — [Prereleases publish to crates.io, gated by Cargo's resolver](docs/adr/0004-prereleases-publish-to-crates-io.md). Establishes the policy used by this prerelease cut.

### Changed (CI / docs)

- **Ecosystem CI layout** — [`.github/workflows/quality.yml`](.github/workflows/quality.yml) **`quality`** job matches **fmt → clippy → test → deny → audit** (then invariants / insta / contracts / build / SARIF); **governance** tooling runs in **[`governance.yml`](.github/workflows/governance.yml)** on GitHub and stays in **ADO / GitLab** quality via **`install-governance-tools.sh`**. **Fuzz** removed from per-push **`quality`** / **ADO**; use **[`scheduled-fuzz.yml`](.github/workflows/scheduled-fuzz.yml)** (**Tuesday**) instead. **Mutation** cron moved to **Monday** ([`mutation-coverage.yml`](.github/workflows/mutation-coverage.yml)). **MSRV** **[`Cargo.toml`](Cargo.toml)** `workspace.package.rust-version` → **1.88**. [**`taudit-pr-diff.yml`**](.github/workflows/taudit-pr-diff.yml) **SHA-pins** actions + **shellcheck** SC2129; [**`release.yml`**](.github/workflows/release.yml) **`macos-15-intel`**; [**`stack-integration.yml`**](.github/workflows/stack-integration.yml) / [**`mutation-coverage.yml`**](.github/workflows/mutation-coverage.yml) YAML hygiene for **yamllint** / **shellcheck**.
- **CI mirrors** — [`azure-pipelines.yml`](azure-pipelines.yml) (Azure DevOps), [`.gitlab-ci.yml`](.gitlab-ci.yml) (GitLab CI), [`bitbucket-pipelines.yml`](bitbucket-pipelines.yml) (Bitbucket Pipelines, Rust subset until a parser exists); guide in [`docs/integrations/ci-mirrors.md`](docs/integrations/ci-mirrors.md).
- **CI** — `cargo-mutants` removed from the blocking [`quality.yml`](.github/workflows/quality.yml) job (cancellation could still fail the run); added [`mutation-coverage.yml`](.github/workflows/mutation-coverage.yml) (weekly schedule + `workflow_dispatch`) with artifact upload. `quality.yml` now uses **concurrency** with `cancel-in-progress` so superseded runs release runners quickly.
- **Crate metadata** — `homepage` and `documentation` (GitHub) on all publishable crates; refreshed `description` fields to emphasize CI/CD authority graph analysis, propagation, and trust-boundary differentiation from linters/scanners/policy runtimes.
- **Docs** — README, USERGUIDE, `docs/positioning.md`, and `man/taudit.1` aligned with that positioning; `CONTRIBUTING.md` and new **`docs/release-strategy.md`** document **stable vs edge** lanes, **crates.io publish gates**, **semver for detection**, **changelog discipline**, and weekly stable shipping as a **ceiling** (not a quota).

### Migration notes

- **Re-baseline once.** If you use `.taudit/baselines/<hash>.json` field baselines, run `taudit baseline init` once after upgrading to v1.1.0-beta.1. The pre-existing baseline files will silently fail-open (suppressions disabled) until re-baselined; you'll see a `warning: failed to apply baseline` line in `taudit verify` output if this happens.
- **Composite-action workflows.** Workflows with `uses: ./local-action` now report `Partial` with a Structural gap. `taudit verify` exit code is unchanged for these workflows unless you have a policy that gates on `AuthorityCompleteness::Complete` — review your policy bundle if so.
- **No CLI flag changes, no schema changes.** Schema versions are unchanged at this release.

## v1.0.12 — 2026-04-29

### Fixed

- **BUG-1 (complete fix): CRLF normalisation at the read boundary** — Previous fix normalised only inside `compute_pipeline_hash`. On Windows with `git core.autocrlf=true`, `git add`/`checkout` silently converts LF → CRLF in the working tree; because the same CRLF content also reaches the parser and the `content_for_baseline` capture, `sha256` still diverged. `normalise_line_endings()` now runs immediately after every `read_to_string` on a pipeline file (scan loop, verify loop, baseline init loop, `parse_content`) so both the parser and the hash always see LF regardless of platform or git configuration.

## v1.0.11 — 2026-04-29

### Added

- **`GapKind` typed taxonomy** — partial graphs now record why they're partial
  with one of three typed levels:
  - `expression` — a template or matrix expression hides a value; graph
    structure is intact
  - `structural` — an unresolvable component (composite action, reusable
    workflow, `extends:`, `include:`) breaks the authority chain
  - `opaque` — the graph cannot be built at all (zero steps, unknown platform)

  Terminal output shows severity-keyed headers (`error: ⛔` / `note: ⚠` /
  `note: ·`) and per-gap kind labels (`[opaque]` / `[structural]` /
  `[expression]`). JSON and CloudEvents outputs carry `{"kind", "reason"}`
  gap objects. CLI `--help` and man page include a `COMPLETENESS LEVELS`
  reference. See `docs/authority-graph.md` for the full schema.

- **`taudit scan --verbose` / `-v`** — per-finding `[partial]` inline tags are
  now suppressed by default (header warning and run summary remain always-on).
  `--verbose` restores inline tags. `opaque` gaps always emit `[partial:opaque]`
  inline regardless of verbosity. See `docs/policies/cookbook-partial-graphs.md`
  Pattern D and Pattern E.

## v1.0.10 — 2026-04-29

### Fixed

- **BUG-2 (complete fix):** `baseline init` now sets all three required waiver fields for Critical findings: `severity_override`, `reason_waived` ("Accepted at baseline init — review before expiry"), and `expires_at`. Previously only `expires_at` was set, but `is_valid_critical_waiver` requires all three to suppress a Critical finding.

## v1.0.9 — 2026-04-29

### Fixed

- **BUG-1 (High): Baseline hash breaks silently on Windows CRLF** — `compute_pipeline_hash` now normalises `\r\n → \n` before hashing. Baselines created on Linux/Mac now match on Windows with `git core.autocrlf=true`; `0 pre-existing suppressed` no longer appears on unchanged files.
- **BUG-2 (Medium): `baseline init` doesn't suppress CRITICAL findings** — `Baseline::from_findings` now auto-sets `expires_at = now + 90 days` for CRITICAL findings on init. Running `taudit baseline init` bulk-accepts all current findings including CRITICAL ones without requiring 144 per-finding `baseline accept` calls.
- **BUG-3 (Medium): Plain config variables flagged CRITICAL** — When a pipeline declares ADO variable groups (opaque without API access), `$(VAR)` references in scripts no longer create new Secret nodes unless the variable was explicitly declared `isSecret: true`. The variable group's own Secret node is sufficient to model group access.
- **BUG-4 (Low): `##vso[task.setvariable]` integer count flagged as secret exfiltration** — The ADO parser now stamps `META_ENV_GATE_WRITES_SECRET_VALUE` only when the setvariable VALUE contains a `$(ref)` expression. The `self_mutating_pipeline` rule skips ADO setvariable steps that write plain literals or integer counters (no secret-value marker).
- **BUG-5 (Low): `--policy .taudit/policy` hard-fails with `--include-builtin`** — If the policy directory doesn't exist and `--include-builtin` is set, `verify` now treats it as zero custom rules rather than exiting with code 2.
- **BUG-6 (Medium): Variable-group `[partial]` findings can't be bulk-suppressed** — `taudit verify` gains `--ignore-partial`: when set, findings whose `nodes_involved` include a variable-group Secret are suppressed, enabling CI gating on ADO pipelines without API access to resolve variable groups.

### Added

- **`taudit verify`** — Text and JSON output include per-pipeline **authority graph modeling**: counts of `complete` / `partial` / `unknown` graphs, optional per-file gap lines in text, and a **`pipelines`** array in JSON (`path`, `completeness`, `completeness_gaps`). ADR [0003](docs/adr/0003-strategic-spine-adoption-phased.md) Phase 2.

### Documentation

- **[docs/golden-paths.md](docs/golden-paths.md)** — Path H (graph → scan → verify); stdout-only note for **`taudit graph`**; links to partial-graph cookbook and ADR 0003.
- **[docs/examples/ci-gate-taudit-verify.yml](docs/examples/ci-gate-taudit-verify.yml)** — Example GitHub Actions job (pinned install, verify, SARIF upload).
- **[docs/policies/cookbook-partial-graphs.md](docs/policies/cookbook-partial-graphs.md)** — Patterns for gating on `completeness` outside custom invariants.
- **[docs/research/BACKLOG-parser-depth-adr0003.md](docs/research/BACKLOG-parser-depth-adr0003.md)** — Parser triage backlog (ADR 0003 Phase 4.1).
- **[docs/positioning.md](docs/positioning.md)**, **[README.md](README.md)**, **[docs/integrations/index.md](docs/integrations/index.md)** — actionlint complementary; tsafe / CellOS pointers; optional future linter ingestion called out as not shipped.
- **[docs/adr/0003-strategic-spine-adoption-phased.md](docs/adr/0003-strategic-spine-adoption-phased.md)** — Implementation status table.
- **`tests/fixtures/verify-golden-noop-policy.yml`** — Unsatisfiable invariant for **`scripts/golden-paths.sh`** verify smoke.
- **[man/taudit.1](man/taudit.1)** — `taudit graph` writes stdout only (no `-o`).

## v1.0.8 — 2026-04-27

### Added

- **`taudit graph --format summary` (ADR 0002 Phase 3)** — Bounded propagation rollup JSON over boundary-crossing paths (same BFS / dense-graph guard as `scan`); schema [`schemas/authority-propagation-summary.v1.json`](schemas/authority-propagation-summary.v1.json); core builder in [`taudit_core::summary`](crates/taudit-core/src/summary.rs). **`--job`** and **`--rich-labels`** are rejected for this format (full graph only; labels N/A).
- **Graph JSON — `authority_summary` on edges (ADR 0002 Phase 2)** — On **`has_access_to`** edges to **identity** nodes, exports include an optional **`authority_summary`** (`trust_zone`, `identity_scope`, truncated **`permissions_summary`**) stamped from existing node metadata. Schema: [`schemas/authority-graph.v1.json`](schemas/authority-graph.v1.json); scan report schema updated in lockstep. Parsers call [`AuthorityGraph::stamp_edge_authority_summaries`](crates/taudit-core/src/graph.rs) automatically after parse.
- **`--rich-labels`** — On **`taudit graph`** and **`taudit map`** with **`--format dot`** or **`--format mermaid`**, embed trust zone and selected node metadata (identity scope, permissions summary) in diagram labels; default labels unchanged; JSON export unchanged. **`taudit map --format mermaid`** uses the same renderer as **`taudit graph --format mermaid`**. See ADR [0002](docs/adr/0002-authority-signal-roadmap-phased.md) Phase 1 and [docs/research/PHASE1-lanes.md](docs/research/PHASE1-lanes.md).
- **CLI error hints** — User-facing `hint:` lines for common failures (missing `--policy`, output files, suppressions, dense-graph override, remediate paths, etc.) via [`error_hints.rs`](crates/taudit-cli/src/error_hints.rs).
- **Corpus CLI integration test** — [`corpus_cli_suite.rs`](crates/taudit-cli/tests/corpus_cli_suite.rs) runs `taudit scan` and `taudit graph` (json + summary) on every committed YAML under `tests/fixtures/`, parser `fuzz/corpus/`, and `.github/workflows/`. Run with `just corpus-suite`. Optional root `corpus/` stress pass: `TAUDIT_TEST_LOCAL_CORPUS=1`.
- **`tests/common`**: [`workspace_root()`](crates/taudit-cli/tests/common/mod.rs) for integration tests.

### Fixed

- **`.gitignore`** — Ignore repo-root **`security.svg`** and **`verify.sarif.json`** when produced by ad-hoc demos (`docs/golden-paths.md` uses `/tmp` for SVG examples instead).
- **Dense graph guard** — One coherent error (source file + hint) instead of duplicate `eprintln!` + `main` error lines.
- **`scripts/quality-gate.sh`** and **`just self-test`** — Use `cargo run -p taudit` (package name is `taudit`, not `taudit-cli`).

### Documentation

- **[docs/ROADMAP.md](docs/ROADMAP.md)** — v1.0 charter table aligned with shipped **`verify`**, **`graph`** (json/dot/mermaid/**summary**), and versioned schemas; opening “current state” paragraph refreshed.
- **[docs/golden-paths.md](docs/golden-paths.md)** — Blessed copy-paste CLI flows on committed fixtures; **[docs/media/README.md](docs/media/README.md)** — policy for generated SVGs vs terminal screenshots; **[docs/research/2026-04-27-council-docs-golden-paths-screenshots.md](docs/research/2026-04-27-council-docs-golden-paths-screenshots.md)** — Quick Council synthesis (executable docs, insta/corpus layering, text over pixels). **`just golden-paths`** + **`scripts/golden-paths.sh`** smoke those paths (includes **mermaid** + **`explain`**); **quality** workflow runs the same script after release build; **`scripts/quality-gate.sh`** **pre-push** / **quality-gate** stages run the smoke after **`cargo test`**.
- **[docs/corpus-research.md](docs/corpus-research.md)** — Documents the automated corpus CLI suite and `TAUDIT_TEST_LOCAL_CORPUS`.
- **[USERGUIDE.md](USERGUIDE.md)** — **`taudit graph --format summary`** (propagation rollup), **`--job`** vs full-graph for json/summary/scan, and anchor to **docs/authority-graph.md**.
- **[docs/adr/0002-authority-signal-roadmap-phased.md](docs/adr/0002-authority-signal-roadmap-phased.md)** — Phase **1** **Shipped (in-tree)** line (parity with phases 2–3).
- **[man/taudit.1](man/taudit.1)** — `map --format mermaid`, **`--format summary`**, **`--rich-labels`**, and diagram-vs-JSON/summary notes aligned with **USERGUIDE** / **docs/authority-graph.md**.

## v1.0.7 — 2026-04-27

### Fixed

- **Broken pipe (EPIPE) on stdout** — All high-volume commands now treat a closed pipeline (e.g. `| head -c 1`) as a clean exit **0**, consistent with `taudit graph` since v1.0.5. Covers **`scan`** (all formats to stdout), **`map`** (text, dot, mermaid), **`verify`**, **`diff`**, **`explain`**, **`invariants`**, **`suppressions`**, **`baseline`**, **`version` / `update`**, **`emit-spec`**, and **`remediate`**. Implementation: [`SilenceBrokenPipe`](crates/taudit-cli/src/stdio_epipe.rs) for streaming writers, [`try_write_stdout`](crates/taudit-cli/src/stdio_epipe.rs) / `try_println!` for buffered lines; integration tests in [`crates/taudit-cli/tests/broken_pipe.rs`](crates/taudit-cli/tests/broken_pipe.rs).

## v1.0.6 — 2026-04-27

### Added

- **`taudit graph --format mermaid`** — emits a **Mermaid** `flowchart LR` diagram (same node/edge model and `--job` filtering as `--format dot`). Use in READMEs and wikis without installing Graphviz; JSON remains the canonical interchange. See [ADR 0001](docs/adr/0001-graph-native-exports-and-leverage.md) and [product research](docs/research/2026-04-27-graph-as-product-research.md).

### Documentation

- **[docs/adr/](docs/adr/)** — ADR 0001 (graph-native exports and leverage) and index.

## v1.0.5 — 2026-04-27

### Fixed

- **`taudit graph`**: writing DOT/JSON to a **broken pipe** (e.g. `| dot` when Graphviz is not installed) no longer panics; exits **0** like other Unix text tools.
- **USERGUIDE** — Graphviz: note that `dot` is external; `brew` / `apt` install examples; `taudit graph --format dot` in the same section as `map --format dot`.

## v1.0.4 — 2026-04-27

> Documentation release: corpus methodology, licensing guidance, and install example version pins.

### Added

- **`docs/corpus-research.md`** — Guidance for large-directory scans (JSON vs SARIF aggregation, fingerprint path semantics, partial graphs), **citing upstream workflows** (not public domain; prefer links and short excerpts; attribution), and **degenerate** mirrors (e.g. comment-only files that yield an empty graph).
- **README** — Link to corpus research doc from Support.
- **USERGUIDE** — New §11 linking to `docs/corpus-research.md`; example `taudit` / `cargo install` version strings updated to **1.0.4**.
- **docs/verify.md** — Example `cargo install` pins updated to **1.0.4**.

## v1.0.3 — 2026-04-27

> Clarify `over_privileged_identity` for ADO service connections.

### Fixed

- **`over_privileged_identity` now distinguishes service connections from pipeline tokens** — previously both showed `permissions: ''` in the message, making service connection findings look identical to the Bug 2 token finding. Service connections now emit a distinct message explaining that scope is ADO-portal-configured (not YAML-controlled), with a recommendation pointing to Project Settings → Service Connections → Security or workload identity federation (OIDC).

### Added

- E2E regression test: `over_privileged_identity_does_not_fire_when_permissions_contents_none` — chains the ADO parser into the rule to catch any future regression in the full parse→rule pipeline.

## v1.0.2 — 2026-04-26

> Bug-fix release: ADO trigger detection hardening, permissions parsing, and finding dedup ordering.

### Fixed

- **`pr: none` / `pr: ~` / `pr: false` now correctly suppress PR-specific rules** — ADO PR trigger detection previously used string enumeration that missed serde_yaml 0.9's representation of `~` and boolean `false`. Detection now requires `is_mapping() || is_sequence()`, suppressing `variable_group_in_pr_job`, `trigger_context_mismatch`, and `checkout_self_pr_exposure` on schedule-only pipelines.
- **`permissions: read` (scalar) now constrains `System.AccessToken`** — `ado_permissions_are_broad()` previously treated scalar `read` as broad scope; only `"write"` is now broad.
- **`permissions: contents: read` (map form) now constrains the token**.
- **Finding deduplication now runs before compensating controls** — dedup keyed on `message` previously ran after CC modified messages, allowing BFS-duplicate findings to survive. Reversed order ensures clean dedup before any message mutation.

### Tests

- 9 new regression tests covering all PR trigger opt-out forms, permissions scalar variants, and dedup ordering.

## v1.0.1 — 2026-04-26

> Competitive parity release: snapshot regression suite, multi-OS CI, GitHub Artifact Attestations on release assets, and parser fuzz harnesses.

### Highlights

- **76 cargo-insta snapshots**: Per-finding regression snapshots across GHA, ADO, and GitLab parsers. Any change to rule IDs, severities, fingerprints, or message copy fails CI explicitly. Gate: `cargo insta test --unreferenced reject`.
- **Multi-OS CI matrix**: `cargo test --workspace` now passes on ubuntu, macos, and windows on every PR (`test-matrix` job with `fail-fast: false`).
- **Build provenance (GitHub Artifact Attestations):** Release archives and SBOM files are attested with [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance) in `.github/workflows/release.yml`. Verify with **`gh attestation verify <path> --repo 0ryant/taudit`** (see [docs/release-trust.md](docs/release-trust.md#verifying-build-attestations-github)). *Errata (2026-04): earlier text referenced `slsa-github-generator` / `slsa-verifier`; that generator path was not adopted.*
- **Parser fuzz harnesses**: Three `cargo-fuzz` targets (`parse_gha`, `parse_ado`, `parse_gitlab`) with 10 corpus seed files. CI smoke-runs each for 10 s on push to main.
- **cargo-mutants gate**: Informational mutation coverage report for `taudit-core` runs on every push to main.
- **572 tests**: 76 new snapshot assertions on top of the v1.0.0 baseline.

## v1.0.0 — 2026-04-26

> Stable release. CLI contract, graph schema, and invariant DSL are now stable. 61 built-in rules across GitHub Actions, Azure DevOps, and GitLab CI. 540 tests.

### Highlights

- **CLI contract stable**: `scan`, `verify`, `map`, `explain`, `baseline`, `suppressions`, `invariants`, `remediate`, `update` — all subcommands stable as of this release.
- **61 built-in rules**: 20 new authority/injection/supply-chain rules landed in v0.9.3 (see below); this release freezes the rule schema.
- **`taudit update`**: Background version check against crates.io on every command; `taudit update` subcommand for explicit check. Respects `TAUDIT_NO_UPDATE_CHECK` and `CI` env vars.
- **`taudit remediate --unstable`**: Write-path remediation (`apply`, `rollback`) gated behind `--unstable` opt-in. Read-only ops (`suggest`, `diff`, `list-backups`) are stable.
- **BUG-2 fix**: `artifact_boundary_crossing` no longer fires for upload→download within the same CI job.
- **BUG-3 fix**: Artifact node TrustZone now inherits the producing step's zone (not always FirstParty).
- **THREAT_MODEL.md**: 12 threats documented across HTTP (version check), YAML deserialization, and `remediate apply` write-path.
- **SBOM on release**: SPDX + CycloneDX SBOMs generated and attached to every GitHub release.

### Pre-release review

Pre-v1.0.0 code review (28 ISC criteria) completed. All criteria satisfied or acknowledged as non-blocking advisory gaps. 540 tests, 0 failed.

## v0.9.4 — 2026-04-26

> Patch release: GHA parser now emits Artifact nodes (Produces/Consumes edges) enabling `artifact_boundary_crossing` to fire from real scans; `.gitignore` hardened for `.taudit/baselines/`; B7/B8/B3/G1/G2/G3 fixes from v0.9.3 validated against 1,636-file corpus.

### Added

- **GHA parser — Artifact graph edges**: `actions/upload-artifact` steps now create `Artifact` nodes with `Produces` edges; `actions/download-artifact` and `dawidd6/action-download-artifact` steps create `Consumes` edges. Same artifact name within a workflow reuses the same node. This makes `artifact_boundary_crossing` fire from real scans (previously rule was unit-tested only against hand-built graphs).
- **3 new parser tests**: `upload_artifact_creates_produces_edge`, `download_artifact_creates_consumes_edge`, `upload_download_same_name_share_artifact_node`.

### Fixed

- **`.gitignore`**: Added `.taudit/baselines/` exclusion (scanner-generated per-file state was untracked). `.taudit/backups/` was already excluded; now both generated sub-directories are covered with an explanatory comment.

### Validation

- Corpus scan (1,636 files — 960 GHA, 412 ADO, 264 GitLab): `artifact_boundary_crossing` verified fires on crafted positive/negative test YAMLs; 0 corpus fires (no SHA-pinned download after unpinned upload with auth in the wild).
- Workspace tests: **530 passed, 0 failed**.

## v0.9.3 — 2026-04-26

> Patch release that merges deferred additive rule work from `worktree-agent-af68e4b6acd4e6bdd` using a safe 3-way patch apply onto post-v0.9.2 main. Keeps v0.9.2 release contents/versions/docs intact while landing the council/red-team GHA+GitLab expansion.

### Added — 20 new built-in authority invariants (deferred worktree batch)

- **GHA authority/injection rules:** `risky_trigger_with_authority`, `sensitive_value_in_job_output`, `manual_dispatch_input_to_url_or_command`, `secrets_inherit_overscoped_passthrough`, `unsafe_pr_artifact_in_workflow_run_consumer`, `script_injection_via_untrusted_context`, `interactive_debug_action_in_authority_workflow`, `pr_specific_cache_key_in_default_branch_consumer`, `gh_cli_with_default_token_escalating`.
- **GitLab authority/supply-chain rules:** `ci_job_token_to_external_api`, `id_token_audience_overscoped`, `untrusted_ci_var_in_shell_interpolation`, `unpinned_include_remote_or_branch_ref`, `dind_service_grants_host_authority`, `security_job_silently_skipped`, `child_pipeline_trigger_inherits_authority`, `cache_key_crosses_trust_boundary`, `pat_embedded_in_git_remote_url`, `ci_token_triggers_downstream_with_variable_passthrough`, `dotenv_artifact_flows_to_privileged_deployment`.

### Added — remediation workflow (`taudit remediate`)

- **New command group:** `taudit remediate {suggest,diff,apply,rollback,list-backups}`.
- **Conservative v1 transform policy:** low-risk/high-confidence rewrites by default.
- **First-class rollback workspace:** backups, snapshots, forward/reverse patches, and manifests under `.taudit/backups/<backup-id>/`.
- **Auto-restore on failed validation:** `apply` runs parse checks + `taudit verify --policy ...` and restores originals on failure.
- **Hash-protected rollback:** `rollback` verifies current-file hash against recorded post-apply hash unless `--force` is set.

### Changed

- **Built-in invariant corpus** increased from **38** to **58**.
- **Rule docs/index** expanded for the newly added rules under `docs/rules/`.
- **Rule plumbing surfaces updated additively**: `FindingCategory` variants, parser metadata stamping, SARIF rule definitions, and CloudEvents category mapping.

### Validation

- Workspace tests: **494 passed, 0 failed**.
- `cargo fmt --all` clean.
- `cargo clippy --workspace --all-targets -- -D warnings` clean.

### Notes

- v0.9.2 versioning/CHANGELOG/ROADMAP content was intentionally preserved during merge conflict resolution (per release-trap constraints).
- The known flaky test from v0.9.2 (`verify_violating_fixture_exits_one`) was not observed in this merge validation run.

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
