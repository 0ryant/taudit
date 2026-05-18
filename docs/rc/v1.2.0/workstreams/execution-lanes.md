# Execution Lanes

## Goal

Run the `v1.2.0-rc.1` direction as disjoint, reviewable work that preserves the release contract: parser, graph, output, schema, and CLI changes must be explicit, tested, and changelog-visible before any RC tag. This brief is the lane control surface for six initial agents and any follow-up agents. It applies the existing phased-lane pattern from `docs/jobs-phased-lanes.md`, the v1 contract goals in `docs/ROADMAP.md`, the local/CI gates in `justfile` and `.github/workflows/quality.yml`, and the tag/publish flow in `.github/workflows/release.yml`, `docs/release-operations.md`, and `docs/RELEASE_GATES.md`.

## Parallel Lanes

| Lane | Owner | Write scope | Read scope | Exit evidence |
| --- | --- | --- | --- | --- |
| L1 - Release coordination | Agent 1 or maintainer | `CHANGELOG.md`, `docs/rc/v1.2.0/**`, release runbook deltas only when needed | `.github/workflows/release.yml`, `.github/workflows/release-plz.yml`, `release-plz.toml`, `docs/release-strategy.md`, `docs/release-operations.md`, `docs/RELEASE_GATES.md` | RC blockers, tag/version checklist, and release-note requirements are written before code lanes merge. |
| L2 - API and contracts | Agent 2 | `crates/taudit-api/`, `contracts/schemas/`, `schemas/`, contract fixtures/examples | `Cargo.toml`, `crates/taudit-report-json/`, `crates/taudit-sink-cloudevents/`, `docs/ROADMAP.md` | Public type/schema changes are additive or semver-called out, with schema drift checks and contract tests named. |
| L3 - Parser parity | Agent 3 | exactly one parser crate per PR: `crates/taudit-parse-gha/`, `crates/taudit-parse-ado/`, `crates/taudit-parse-gitlab/`, or `crates/taudit-parse-bitbucket/`; matching parser fixtures/tests | `docs/jobs-phased-lanes.md`, `docs/ROADMAP.md`, parser-specific rule docs | Parser completeness changes include explicit `AuthorityCompleteness`/gap behavior and snapshots where output changes. |
| L4 - Core graph and rules | Agent 4 | `crates/taudit-core/`, rule docs under `docs/rules/`, rule fixtures/tests | `schemas/authority-graph.v1.json`, `schemas/exploit-graph.v1.json`, `docs/authority-graph.md`, `docs/ROADMAP.md` | Rule/graph semantics are isolated from parser rewrites and include focused regression tests. |
| L5 - CLI, reports, and sinks | Agent 5 | `crates/taudit-cli/`, `crates/taudit-report-*`, `crates/taudit-sink-cloudevents/`, CLI/report snapshots | `docs/golden-paths.md`, `docs/verify.md`, `docs/baselines.md`, `.github/workflows/quality.yml` | CLI flags, exit codes, report fields, SARIF, JSON, terminal, and CloudEvents deltas are tested and changelog-ready. |
| L6 - Docs and operator evidence | Agent 6 | `docs/**`, `README.md`, `USERGUIDE.md`, `packaging/**`, `release/**`; no Rust | `docs/jobs-phased-lanes.md`, `docs/ROADMAP.md`, `docs/RELEASE_GATES.md`, `docs/release-trust.md` | Operator-facing docs match merged behavior and do not document unmerged code as shipped. |

Follow-up agents inherit the same model: pick one lane, declare the exact owned paths, and do not widen scope without reassigning ownership in `docs/rc/v1.2.0/**`.

## Ownership / Conflict Rules

- One writer per high-churn path at a time. Treat `crates/taudit-cli/src/main.rs`, `crates/taudit-core/src/rules.rs`, `crates/taudit-core/src/graph.rs`, `crates/taudit-sink-cloudevents/src/lib.rs`, `contracts/schemas/`, `schemas/`, `CHANGELOG.md`, and `.github/workflows/release.yml` as serialized unless L1 records an explicit handoff.
- Parser lanes are crate-disjoint. Do not combine ADO, GitLab, GHA, or Bitbucket parser changes in one PR unless the change is a shared API migration owned by L2 and reviewed by L3.
- Docs-only work must not touch `crates/**/*.rs`, `Cargo.toml`, or `Cargo.lock`. Code lanes may update their required docs, but broad docs polish belongs to L6.
- Contract and output lanes must coordinate before changing JSON/SARIF/CloudEvents field names, schema versions, fingerprints, suppression keys, or exit-code semantics. `docs/release-strategy.md` treats detection semantics and public outputs as release-contract surface.
- Do not run repo-wide formatters that rewrite files outside the lane. `cargo fmt --all` is allowed as a verification/fix command only when Rust code is in scope and the resulting diff is inspected for ownership.
- Do not overwrite untracked or unrelated work. Start and finish with `git status --short`; if another worker has touched a path, rebase/merge deliberately instead of editing through it.
- Release automation edits are single-owner. `justfile`, `.github/workflows/quality.yml`, `.github/workflows/release.yml`, `scripts/release_harness.py`, and `docs/release-operations.md` should not be edited by feature lanes without L1 review.

## Merge Order

1. L1 lands the RC control docs first: workstream briefs, blockers, version/tag assumptions, and changelog discipline.
2. L2 lands API/schema foundations before consumers. This prevents report, sink, parser, and docs lanes from racing on public contract names.
3. L3 and L4 land next, preferably one parser or one core concern per PR. If L4 changes graph APIs used by parsers, land L4 before parser PRs that depend on it.
4. L5 lands after the data shape is stable. Reporters, sinks, CLI flags, snapshots, and golden paths should reflect merged parser/core behavior, not predicted behavior.
5. L6 lands docs after behavior is merged, except for neutral planning docs under `docs/rc/v1.2.0/**`.
6. Final RC release prep lands last: changelog detection delta, release notes, version bumps, release harness checks, and tag readiness per `docs/release-operations.md` and `.github/workflows/release.yml`.

If two PRs are both green but conflict on a serialized path, merge the lower-level contract/data PR first: API/schema -> parser/core -> CLI/output -> docs/release.

## Verification Matrix

| Change type | Required local commands | CI/release mirror |
| --- | --- | --- |
| Docs-only planning under `docs/rc/v1.2.0/**` | `git diff --check` and manual link/path review | `.github/workflows/quality.yml` ignores docs-only changes, so reviewer inspection is the gate. |
| Any Rust code | `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace` or `just check` | Quality workflow runs fmt, clippy, workspace tests, deny, audit, contract tests, self-scan, and golden paths in `.github/workflows/quality.yml`. |
| Contract/schema/API | Rust gates plus `python3 scripts/generate-authority-invariant-schema.py --check` when invariant schema can drift; `cargo test -p taudit-report-json`; `cargo test -p taudit-sink-cloudevents`; `just contracts` | Quality workflow validates invariant schema drift, starter YAML, report JSON, and CloudEvents contracts. |
| CLI/output/snapshots | Rust gates plus `cargo insta test --workspace --unreferenced reject` when snapshots change; `just golden-paths` when `docs/golden-paths.md`, CLI output, or examples change | Quality workflow runs snapshot review and `scripts/golden-paths.sh` after building `taudit`. |
| Parser behavior | Rust gates plus parser-focused package tests and affected CLI integration tests under `crates/taudit-cli/tests/` | Test matrix in `.github/workflows/quality.yml` runs `cargo test --workspace`; push builds add macOS and Windows coverage. |
| Release candidate prep | `just release-check v1.2.0-rc.1`; `just release-notes v1.2.0-rc.1`; optionally `just release-standardize v1.2.0-rc.1` after the tag exists | `.github/workflows/release.yml` runs quality, release harness check, release creation, SBOMs, multi-target binaries, attestations, and crates.io publish for `v*.*.*-*` tags. |
| Stable promotion after RC | All RC prep plus soak/corpus/fuzz/dogfood gates from `docs/RELEASE_GATES.md` | Stable tags additionally run `cargo semver-checks check-release` in `.github/workflows/release.yml`. |

## Review Checklist

- The PR states its lane, owned paths, and any intentionally read-only paths.
- `git status --short` before merge shows no unrelated path drift from other workers.
- Public contract impact is classified: none, additive, breaking, detection delta, or output delta.
- `CHANGELOG.md` has a detection delta entry for rule, parser, graph, report, schema, fingerprint, suppression, or CLI behavior changes.
- Tests cover the behavior at the lowest useful layer: parser unit, core rule, report/sink contract, CLI integration, snapshot, or golden path.
- Docs cite behavior that has already merged, or explicitly mark it as RC plan/pending.
- Release-facing changes preserve prerelease semantics from `docs/release-strategy.md`: prerelease tags publish, stable resolvers skip them, and stable promotion re-enables semver checks.
- Reviewer confirms no serialized hotspot was edited without the lane owner or maintainer acknowledging the handoff.

## Risks / Non-Goals

- Risk: contract drift between `taudit-api`, schemas, JSON/SARIF/CloudEvents, and docs. Mitigation: land L2 before L5/L6 and run contract tests.
- Risk: parser/core merge fights around graph shape and completeness. Mitigation: one parser crate per PR, one core graph/rule concern per PR, and merge API/core dependencies first.
- Risk: docs claim RC behavior before it exists. Mitigation: L6 may write planning docs early but operator docs update only after code merges.
- Risk: release automation changes mask feature risk. Mitigation: release workflow/harness edits are L1-owned and reviewed separately from behavior changes.
- Risk: CI cost slows agents into skipping checks. Mitigation: use focused tests during development, but require the verification matrix before merge or tag.
- Non-goal: this brief does not define the product scope of `v1.2.0-rc.1`; it defines execution discipline for whatever scope L1 records.
- Non-goal: this brief does not authorize runtime writes, publishing, tagging, or committing. It is a docs-only lane plan.
