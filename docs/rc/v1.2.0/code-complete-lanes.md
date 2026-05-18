# v1.2.0 Code-Complete Lanes

This is the execution backlog for `v1.2.0-rc.1: Authority Evidence Platform`.
It turns the RC charter, workstream briefs, and council pass into lane-owned
subtasks that multiple agents can execute without clobbering each other.

This document is intentionally stricter than a roadmap. A lane is not complete
because it has a plan, a local demo, or a plausible implementation. It is
complete when its acceptance gates pass and its release-facing claims are backed
by evidence.

## Scope Boundary

Code complete for this RC means:

- public contract boundaries are decided and tested;
- ordered authority evidence is implemented or explicitly deferred without
  overclaiming;
- parser completeness is measured against a real-input corpus;
- output identity, evidence, suppressions, and exit semantics are cross-sink
  conformance-gated;
- release, provenance, and marketplace claims are backed by receipts;
- the changelog and release gates can honestly describe the shipped payload.

Post-RC ecosystem work is tracked because this direction unlocks it, but it does
not block `v1.2.0-rc.1` unless L1 promotes it into the RC payload.

## Lane Rules

- One writer owns a high-churn path at a time.
- API/schema names merge before parser/core/report consumers.
- Parser work is one provider per PR unless the change is an L2 shared API
  migration.
- Release automation is L1-owned and serialized.
- Docs may describe pending RC plans only under `docs/rc/v1.2.0/**`; operator
  docs describe merged behavior only.
- Generated files, lockfiles, broad formatters, and workflow changes require an
  explicit owner and join gate.
- Every subagent must report changed paths, verification run, residual risk, and
  the next dependency it unblocks.

## ADR Run

| ADR | Decision | Blocking role |
| --- | --- | --- |
| [0009](../../adr/0009-v1-2-release-contract-and-semver-map.md) | v1.2 RC release contract and SemVer map | RC tag blocker |
| [0010](../../adr/0010-public-contract-boundary-and-api-readiness.md) | Public contract boundary and `taudit-api` readiness | Contract blocker |
| [0011](../../adr/0011-ordered-authority-evidence-model.md) | Ordered authority evidence model | Detection blocker |
| [0012](../../adr/0012-public-output-identity-contract.md) | Public output identity contract | Output blocker |
| [0013](../../adr/0013-evidence-rendering-and-output-ceiling.md) | Evidence rendering and customer-safe output ceiling | Output blocker |
| [0014](../../adr/0014-parser-completeness-and-platform-promise.md) | Parser completeness and platform promise | Parser/docs blocker |
| [0015](../../adr/0015-real-input-corpus-provenance-and-runner.md) | Real-input corpus provenance and runner | Corpus blocker |
| [0016](../../adr/0016-external-resolution-and-enrichment-boundary.md) | External resolution and ADO enrichment boundary | Parser/enrichment blocker |
| [0017](../../adr/0017-current-output-profile-and-contract-examples.md) | Current output profile and contract examples | Contract blocker |
| [0018](../../adr/0018-suppression-baseline-and-exit-code-semantics.md) | Suppression, baseline, and exit-code semantics | CLI gate blocker |
| [0019](../../adr/0019-reporter-sink-sanitization-boundary.md) | Reporter and sink sanitization boundary | Output safety blocker |
| [0020](../../adr/0020-output-conformance-harness-and-rc-gate.md) | Output conformance harness and RC gate | Release blocker |
| [0021](../../adr/0021-operator-proof-receipt-contract.md) | Operator proof receipt contract | Adoption claim blocker |
| [0022](../../adr/0022-adoption-doc-version-and-link-policy.md) | Adoption doc version and link policy | Docs claim blocker |
| [0023](../../adr/0023-ecosystem-evidence-envelope-and-stack-contracts.md) | Ecosystem evidence envelope and stack contracts | Post-RC unlock |
| [0024](../../adr/0024-external-diagnostic-intake-boundary.md) | External diagnostic intake boundary | Post-RC unlock |

## Next Action Sets

The first safe parallel wave is documentation and contract shaping. It does not
write Rust behavior yet.

| Set | Parallel lanes | Join gate |
| --- | --- | --- |
| NAS-1 | L1 release map, L2 public boundary matrix, L3 parser matrix, L6 adoption proof audit | ADRs 0009, 0010, 0014, 0021, and 0022 have concrete checklists and no contradictory docs |
| NAS-2 | L2 schema/current-profile design, L4 ordered evidence model design, L5 identity/output test design | field names frozen enough for code lanes |
| NAS-3 | L3 corpus runner, one parser provider PR, L4 core event builder, L5 conformance harness skeleton | all write scopes disjoint |
| NAS-4 | L5 report/sink projection, L6 operator docs, L1 changelog and version map | behavior merged before operator docs claim it |

## L1: Release Coordination

Owned paths: `CHANGELOG.md`, root `Cargo.toml`, `crates/*/Cargo.toml`,
`Cargo.lock`, `scripts/release_harness.py`, `scripts/check-crates-publish-metadata.py`,
`tests/test_release_harness.py`, `.github/workflows/release.yml`,
`docs/RELEASE_GATES.md`, `docs/release-*`.

| ID | Subtask | Depends on | Acceptance gate |
| --- | --- | --- | --- |
| L1-01 | Add `CHANGELOG.md` `## v1.2.0-rc.1` with `Detection delta (read first)` and migration notes | behavior delta known | changelog names finding count, FP/FN, schema, CLI, output, fingerprint, suppression, and crate-version impact |
| L1-02 | Decide crate version map for CLI, `taudit-api`, and implementation crates | L2-01, L2-02 | map is in changelog and release notes |
| L1-03 | Bump CLI to `1.2.0-rc.1` and update lockfile if needed | L1-02 | release harness and metadata checker pass |
| L1-04 | If API or implementation crates change, bump each semver line intentionally | L1-02 | publish metadata checker passes and release notes explain bump |
| L1-05 | Add release harness tests for prerelease existing-release normalization and `--latest=false` | none | `pytest tests/test_release_harness.py` |
| L1-06 | Wire conformance harness from ADR 0020 into release gate | L2/L5 harness skeleton | local recipe and CI path both exist |
| L1-07 | Refresh `docs/RELEASE_GATES.md` to distinguish RC tag gates from stable promotion gates | ADR 0009 | no stale `1.1.0-rc.1` current-cycle language remains |
| L1-08 | After tag workflow, record release asset, checksum, SBOM, attestation, crates.io, and docs.rs receipts | tag workflow complete | proof receipts under `docs/proof/v1.2.0-rc.1/` |

## L2: API, Schemas, Contracts

Owned paths: `crates/taudit-api/**`, `schemas/**`, `contracts/schemas/**`,
`contracts/examples/**`, `examples/consumers/**`, schema generators, contract
docs.

| ID | Subtask | Depends on | Acceptance gate |
| --- | --- | --- | --- |
| L2-01 | Publish public boundary matrix for API, graph JSON, scan JSON, SARIF, CloudEvents, exploit graph, baselines, suppressions, and exit codes | ADR 0010 | matrix linked from RC docs and release docs |
| L2-02 | Decide `taudit-api` readiness: stay `0.4.1`, bump prerelease minor, or promote later | L2-01 | release notes name the decision |
| L2-03 | Define public ordered evidence wire fields from ADR 0011 | ADR 0011 | schemas and API docs use same field names |
| L2-04 | Define public output identity fields from ADR 0012 | ADR 0012 | `rule_id`, `fingerprint`, `suppression_key`, and `finding_group_id` are described once |
| L2-05 | Define public versus internal evidence projection from ADR 0013 | ADR 0013 | output ceiling matrix exists |
| L2-06 | Repair graph/report schema drift, including standalone graph fields versus embedded report graph fields | L2-01 | fixtures validate both standalone graph JSON and report JSON |
| L2-07 | Add current-output profile checks separate from compatibility schema validation | ADR 0017 | examples fail if promised current fields disappear |
| L2-08 | Refresh contract examples from real fixtures | L2-03 to L2-07 | examples validate schemas and current profile |
| L2-09 | Add schema/source drift controls across Rust API enums, finding schema, report schema, CloudEvents schema, and invariant schema | L2 field decisions | generator/check target fails on drift |
| L2-10 | Build reference consumer harness for Python, TypeScript, or Go consumers | L2-01 | consumers ignore unknown metadata and honor completeness gaps |
| L2-11 | Validate exploit graph JSON for empty, positive, downgrade-suppressed, and observed-evidence-disabled cases | L4 exploit work | schema validation in conformance harness |
| L2-12 | Document semver rules for graph `1.x`, report schema, CloudEvents, and `taudit-api` | L2-02 | changelog and contract docs agree |

## L3: Parser Completeness And Corpus

Owned paths: one parser crate per PR under `crates/taudit-parse-*`, provider
fixtures, fuzz corpora, `docs/parser-feature-matrix.md`, corpus manifest and
runner, corpus reports.

| ID | Subtask | Depends on | Acceptance gate |
| --- | --- | --- | --- |
| L3-01 | Write parser feature matrix for GHA, ADO, GitLab, and Bitbucket | ADR 0014 | each row has construct, support state, gap kind, fixture, corpus sample, intended release state |
| L3-02 | Decide corpus storage path versus manifest fetch cache, accounting for ignored `/corpus/` | ADR 0015 | tracked manifest or tracked fixture path exists |
| L3-03 | Implement corpus manifest schema and runner | L3-02 | runner scans with timeout and emits histograms |
| L3-04 | Populate initial corpus: at least 100 public GHA, ADO, and GitLab files plus named Bitbucket tranche | L3-03 | manifest has URL, commit/digest, license/use basis, expected parser, expected gaps |
| L3-05 | GHA parser lane: service containers, private registry creds, volumes/options, fork/event expression gates, reusable/local action boundary | L3-01 | focused tests, corpus samples, no untyped partials |
| L3-06 | ADO parser lane: templates, resources, service connections, secure files, pools, conditions, duplicate fields, variable groups | L3-01, ADR 0016 | parser tests plus mock enrichment tests |
| L3-07 | GitLab parser lane: include, extends, default, hidden jobs, inherit, protected refs, scoped variables, child pipelines | L3-01 | deterministic local cases modelled; dynamic cases typed partial |
| L3-08 | Bitbucket parser lane: caches, clone options, deployments, secured variables, pipes, services, parallel/stage semantics | L3-01 | broad fixtures, fuzz target, tranche report |
| L3-09 | ADO enrichment secret-safety lane: PAT masking and live-state reproducibility metadata | ADR 0016 | PAT absent from logs, reports, snapshots, and baseline metadata |
| L3-10 | Corpus report integration into release evidence | L3-03 to L3-08 | report validates JSON and counts complete/partial/unknown/failure/gap kinds |
| L3-11 | Parser docs truth pass | L3-01 to L3-10 | README, USERGUIDE, ROADMAP, and RC docs do not overclaim |
| L3-12 | Provider-focused verification pass | provider PRs | `cargo test -p taudit-parse-gha`, `-p taudit-parse-ado`, `-p taudit-parse-gitlab`, `-p taudit-parse-bitbucket` |

## L4: Core Graph, Evidence, Rules

Owned paths: `crates/taudit-core/**`, core fixtures, rule docs tied to the
specific rule lane, exploit path projection.

| ID | Subtask | Depends on | Acceptance gate |
| --- | --- | --- | --- |
| L4-01 | Add shared authority event builder with ordered evidence events | L2-03, parser stamps | tests cover positive, reversed, same-step, cross-job, missing-materialization cases |
| L4-02 | Promote helper resolution, authority transport, and authority origin to shared schema/API-backed values | L2-03 | no string-only matching for public evidence fields |
| L4-03 | Add action intelligence catalog schema, validation, and source anchors | L4-02 | catalog entries validate and have source or witness-status explanation |
| L4-04 | Seed catalog entries for Firebase, Azure, Cloudflare, Docker, npm, ECR, setup-gcloud, GoReleaser, Codecov, and Teleport | L4-03 | fixtures cover each entry or mark deferred |
| L4-05 | Rewrite helper authority rules around ordered evidence predicate | L4-01 to L4-04 | rules do not fire on PATH mutation alone |
| L4-06 | Add transport-specific rules for argv, stdin, env, credential/config file path, workspace file, and OIDC request env | L4-05 | unit tests for each transport |
| L4-07 | Add downgrade/suppression matrix for absolute path, toolcache, action-owned path, explicit ambient mode, and caller-provided-only forwarding | L4-05 | negative tests prove downgrade/suppress cases |
| L4-08 | Make exploit-path projection consume shared evidence and catalog facts | L4-01 to L4-07 | deterministic JSON and schema validation |
| L4-09 | Keep observed sink semantics disabled unless explicit evidence input exists | L4-08 | tests prove static shape never invents observed sink |
| L4-10 | Add rule ID migration or aliasing for any canonical helper-rule rename | L4-05 | backcompat tests for old IDs where needed |
| L4-11 | Add property tests for graph invariants and cross-platform gap arrays | L2 schemas | endpoints valid, gap arrays parallel, identity stable under CRLF/path separator |
| L4-12 | Add performance guard for event index and propagation hot paths | L4-01 | bench or perf smoke records regression baseline |

## L5: CLI, Reports, Sinks, Output Identity

Owned paths: `crates/taudit-cli/**`, `crates/taudit-report-*`,
`crates/taudit-sink-cloudevents/**`, cross-sink tests, CLI snapshots.

| ID | Subtask | Depends on | Acceptance gate |
| --- | --- | --- | --- |
| L5-01 | Extend cross-sink identity tests from `rule_id` and `fingerprint` to `suppression_key` and `finding_group_id` | L2-04 | `cargo test -p taudit --test cross_sink_contract` |
| L5-02 | Add evidence parity checks across JSON, SARIF, CloudEvents, and terminal verbose mode | L2-03, L2-05 | fixture proves required public evidence appears consistently |
| L5-03 | Map every public finding extra to SARIF properties or document non-projection | L2-05 | SARIF snapshots and docs agree |
| L5-04 | Map every public finding extra to CloudEvents data or extensions | L2-05 | CloudEvents schema and examples validate |
| L5-05 | Add terminal verbose identity/evidence/suppression rendering | L2-04, L2-05 | terminal snapshots remain sanitized and readable |
| L5-06 | Fix CloudEvents documentation drift for fingerprint, platform token, event type, and Bitbucket token behavior | L2-04 | schema descriptions and tests agree |
| L5-07 | Implement suppression/baseline/exit-code matrix tests | ADR 0018 | table-driven CLI tests cover scan/verify/baseline/threshold/waiver modes |
| L5-08 | Preserve suppression metadata across sinks even when human output hides or downgrades a finding | L5-07 | cross-sink tests prove metadata survives |
| L5-09 | Add hostile rendering corpus cases for control bytes, markdown, SARIF text, path separators, CRLF, and long fields | ADR 0019 | identity stable while renderers apply sink boundary |
| L5-10 | Add optional witness-spec or observed-evidence CLI only behind explicit feature gate if shipped | L4 observed semantics | default CLI omits internal fields and rejects accidental exposure |
| L5-11 | Add conformance harness command for ADR 0020 | L2/L4/L5 test pieces | local command validates all output contracts |
| L5-12 | Refresh snapshots and golden paths only after behavior stabilizes | L5-01 to L5-11 | `cargo insta test --workspace --unreferenced reject` when snapshots change |

## L6: Docs, Operator Evidence, Adoption Proof

Owned paths: `docs/**`, `README.md`, `USERGUIDE.md`, `TODOS.md`,
`docs/proof/v1.2.0-rc.1/**`, integration docs, media/proof assets. No Rust.

| ID | Subtask | Depends on | Acceptance gate |
| --- | --- | --- | --- |
| L6-01 | Audit docs for stable, RC, and planned labels | ADR 0022 | no unpublished surface is described as live |
| L6-02 | Refresh README, USERGUIDE, golden paths, adoption docs, and integration docs for current stable versus RC examples | L6-01 | version/link audit passes |
| L6-03 | Reconcile VS Code publication contradictions | ADR 0021 | one bounded statement plus receipt or planned label |
| L6-04 | Update `TODOS.md` marketplace action state from implementation checklist to proof-gated readiness | ADR 0021 | action claims require receipts |
| L6-05 | Create proof ledger directory and receipt template under `docs/proof/v1.2.0-rc.1/` | ADR 0021 | template contains required receipt fields |
| L6-06 | GitHub Action proof pack: hosted SHA smoke, immutable tag, moving `v1`, release, Marketplace receipt | external repo ready | receipt recorded before docs claim live Marketplace action |
| L6-07 | Azure DevOps proof pack: hosted `Taudit@1` smoke, output variables, artifacts, version alignment | task package ready | receipt recorded before docs claim task ready |
| L6-08 | VS Code proof pack: package checksum, install smoke, command smoke, publish/readback if in RC | publisher ready | receipt or planned label |
| L6-09 | Marketplace media pack from real surfaces only | L6-06 to L6-08 | screenshots/media link to receipts and contain no secrets |
| L6-10 | Operator docs for parser matrix and corpus report | L3 reports | docs cite measured support and typed gaps |
| L6-11 | Operator docs for evidence rendering and output ceiling | L5 outputs | no CVE/disclosure/witness overclaim |
| L6-12 | Final release note/doc drift audit | all behavior lanes | README, USERGUIDE, docs, changelog, RC docs agree |

## QA And Resilience Gates

Owned paths vary by lane. QA is a join function, not a free-floating rewrite
license.

| ID | Subtask | Depends on | Acceptance gate |
| --- | --- | --- | --- |
| QA-01 | Workspace formatting | any Rust changes | `cargo fmt --all -- --check` |
| QA-02 | Workspace lint | any Rust changes | `cargo clippy --workspace --all-targets -- -D warnings` |
| QA-03 | Workspace tests | any code changes | `cargo test --workspace` |
| QA-04 | Contract tests | L2/L5 changes | report JSON, CloudEvents, SARIF, cross-sink, exploit graph tests pass |
| QA-05 | Corpus gate | L3 changes | runner validates schema and emits corpus histograms |
| QA-06 | Snapshot/golden paths | CLI/output/docs examples | `cargo insta test --workspace --unreferenced reject` and `just golden-paths` when applicable |
| QA-07 | Security/supply-chain gates | release prep | `cargo deny`, `cargo audit`, SBOM workflow, attestation checks |
| QA-08 | Release readiness | final RC | release harness, publish metadata, conformance harness, changelog, proof receipts |

## Post-RC Unlock Lanes

These are unlocked by the Authority Evidence Platform direction. They are not
RC blockers unless L1 explicitly promotes them.

| ID | Subtask | Owner | Gate |
| --- | --- | --- | --- |
| X-01 | Ecosystem evidence envelope v1 | L5 plus stack owners | schema validates and taudit responsibilities remain producer-only |
| X-02 | `tsign` authority graph predicate contract | stack integration lane | signed graph claims specify canonicalization and partial-graph stance |
| X-03 | `axiom` decision contract and override attestations | stack integration lane | taudit output consumed without making taudit the orchestrator |
| X-04 | `tsafe` remediation and runtime containment receipt contract | stack integration lane | no runtime writes from taudit |
| X-05 | External diagnostic SARIF intake | integration lane | advisory-only context cannot create authority edges |
| X-06 | JetStream or NATS publish adapter | output lane | optional adapter preserves identity and evidence contracts |
| X-07 | TUI/watch mode | product UX lane | does not change graph semantics or output contracts |
| X-08 | Stack smoke across taudit, tsign, axiom, and tsafe | stack integration lane | receipts distinguish each project owner |

## Final Code-Complete Gate

`v1.2.0-rc.1` is code complete only when:

- every blocker ADR from 0009 through 0022 has its acceptance gates satisfied or
  its scoped deferral is recorded in the changelog;
- L1 through L6 blocker subtasks are complete;
- QA-01 through QA-08 are complete for the changed surface;
- no operator-facing doc claims behavior without a receipt or merged code;
- release harness and publish metadata accept `v1.2.0-rc.1`;
- the conformance harness passes;
- the changelog says exactly what changed and what did not.

Stable `v1.2.0` remains a separate promotion step. It requires the latest RC to
clear soak, corpus, fuzz, contract, and release-trust gates without semantic
payload changes that would require another RC.
