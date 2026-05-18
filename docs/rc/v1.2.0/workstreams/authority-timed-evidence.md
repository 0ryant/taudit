# Authority-Timed Evidence

## Goal

Make v1.2.0-rc.1 the release candidate where helper-resolution authority findings are backed by ordered, typed evidence instead of broad PATH lint. The workstream should connect authority events, helper-resolution edges, exploit-path graph output, report copy, and internal witness handoff into one customer-safe contract: "earlier mutable runner state can influence a later authority-bearing helper invocation" only when the ordered evidence supports that path.

## Why This Takes taudit Skyward

taudit's strategic category is authority modelling for CI/CD, not generic pipeline scanning (`docs/ROADMAP.md`). Authority-timed evidence turns that positioning into a sharper product claim: taudit can explain not just that authority exists, but when it becomes reachable, how it crosses helper-resolution boundaries, and what evidence supports or limits the claim.

This is the difference between noisy security lint and a graph-native authority system:

- The canonical authority graph stays the source model (`crates/taudit-core/src/graph.rs`, `docs/authority-graph.md`).
- The exploit-path view remains a derived projection over that model, not a second truth source (`docs/adr/0006-exploit-path-view-and-ruleset.md`).
- Customer output stays useful and restrained: authority classification, confidence, evidence strength, remediation, and hardening labels without default CVE, disclosure, witness-canary, or exploit overclaiming (`docs/adr/0005-authority-edge-classifier-and-witness-handoff.md`, `CHANGELOG.md`).

## Current Evidence

- ADR 0005 accepts taudit as the authority-edge classifier and prioritizer, with witness execution delegated to a separate harness. It requires ordered evidence: `PathMutation.step_index < SecretMaterialized.step_index <= HelperExecution.step_index`, explicit helper resolution, authority transport, authority origin, witness status, same-job caveat text, and feature-gated disclosure/CVE output (`docs/adr/0005-authority-edge-classifier-and-witness-handoff.md`).
- ADR 0006 accepts a separate `exploit_path` rule/view scope. The exploit view is a deterministic projection over the canonical graph plus catalog facts, with `rule_id`, `umbrella_rule_id`, `rule_scope`, `mutable_channel`, `helper`, `helper_resolution`, `authority_transport`, and `authority_origin` as stable consumer fields (`docs/adr/0006-exploit-path-view-and-ruleset.md`).
- Phase 5 is already the owning implementation plan: 5A for timing and metadata schema, 5B for ordered rules and downgrades, 5C for gated witness spec and scoring, 5E for exploit-path scope and graph parity, and 5W for customer-safe copy (`docs/jobs-phased-lanes.md`).
- The current exploit-path implementation already exports the core contract and pattern facts, filters to GitHub Actions, requires a prior same-job mutable writer, requires authority materialization, suppresses downgrade helper resolutions, and emits static/inferred edges without observed sinks unless evidence exists (`crates/taudit-core/src/exploit_path.rs`).
- The core graph remains the mutable engine and stable authority model; nodes, edges, trust zones, completeness, and identity authority summaries live in the graph contract rather than report-only prose (`crates/taudit-core/src/graph.rs`, `schemas/authority-graph.v1.json`).
- The exploit graph schema states that the projection does not prove exploitability without explicit witness evidence and requires path summary counts plus per-path rule/helper/transport/origin fields (`schemas/exploit-graph.v1.json`).
- v1.1.0 already shipped `taudit graph --view exploit` with internal-gated disclosure scoring, CVE workflow metadata, witness specs, and canary details absent from default customer output; v1.1.5 has no rule/parser/graph/report/schema behavior change, and `Unreleased` has no detection delta yet (`CHANGELOG.md`).

## Deliverables

- Authority event model: add or finalize typed events for prior mutable state, later authority materialization, helper resolution, helper receiving authority, and optional observed witness sink. Events must carry stable ordering coordinates such as job identity and step index or graph-node source id, and must avoid ad hoc strings where enums already exist or should exist (`docs/adr/0005-authority-edge-classifier-and-witness-handoff.md`, `crates/taudit-core/src/graph.rs`).
- Ordered evidence contract: rules must prove the sequence "prior mutable channel -> later authority materialization -> helper resolution -> authority transport" before emitting helper-authority findings. A PATH write alone, package-manager use alone, or known action name alone is not enough (`docs/adr/0005-authority-edge-classifier-and-witness-handoff.md`, `docs/rules/later_secret_materialized_after_path_mutation.md`).
- Exploit-path graph contract: keep `taudit graph --view exploit --format json|dot|mermaid|summary` deterministic and schema-backed. Public JSON must preserve `rule_scope: exploit_path`, rule IDs, helper resolution, transport, origin, confidence, and `authority_bearing`; observed edges require explicit witness evidence (`schemas/exploit-graph.v1.json`, `docs/authority-graph.md`, `crates/taudit-core/src/exploit_path.rs`).
- Helper-resolution authority edges: normalize the ADR 0005 family across existing rule IDs, docs, schemas, and explain output. Transport-specific findings should distinguish argv, stdin, env, credential/config file path, workspace file, and OIDC request env. Origin should distinguish caller-provided secret, action input secret, GitHub token, OIDC capability, action-minted cloud/registry credentials, generated credential files, and derived secret payloads (`docs/adr/0005-authority-edge-classifier-and-witness-handoff.md`, `schemas/finding.v1.json`, `contracts/schemas/taudit-report.schema.json`).
- FP control: downgrade or suppress absolute-path, trusted toolcache, action-owned install path, user-supplied absolute path, and explicit ambient-mode helper resolution unless another authority-confusion edge remains. Unknown resolution should be confidence-limited, not silently promoted (`docs/adr/0005-authority-edge-classifier-and-witness-handoff.md`, `crates/taudit-core/src/exploit_path.rs`, `docs/rules/gha_toolcache_absolute_path_downgrade.md`).
- FN control: grow catalog-backed and source-anchored coverage for known helper-delegating actions without creating candidate-specific detections. Candidate packs should become fixtures/evidence inputs that validate stable patterns, not one-off rules (`docs/adr/0006-exploit-path-view-and-ruleset.md`, `docs/jobs-phased-lanes.md`).
- Default-output guardrails: public scan, SARIF, CloudEvents, graph, and report output must not claim CVEs, exploitability, hosted-witness proof, disclosure routing, private anchors, or canary observations unless explicit internal gates and explicit evidence are present (`docs/adr/0005-authority-edge-classifier-and-witness-handoff.md`, `docs/adr/0006-exploit-path-view-and-ruleset.md`, `CHANGELOG.md`).

## Acceptance Criteria

- A helper-resolution authority finding cannot emit unless the model contains ordered evidence for prior mutable state, later authority materialization, helper resolution, and authority transport in the same relevant execution scope.
- The exploit-path JSON validates against `schemas/exploit-graph.v1.json` and preserves deterministic fields: `rule_id`, `umbrella_rule_id`, `rule_scope`, `mutable_channel`, `helper`, `helper_resolution`, `authority_transport`, `authority_origin`, node IDs, edge confidence, and `authority_bearing`.
- Default report/SARIF/CloudEvents/graph output contains customer-safe language only: no CVE claim, no disclosure score, no witness-spec next action, no canary value, no private hosted-run artifact, and no "observed" sink without explicit witness evidence.
- Transport-specific rules and docs explain what authority reached the helper and how: argv, stdin, env, credential/config file path, workspace file, or OIDC request env.
- Downgrade/suppression fixtures cover trusted helper resolution modes and prove the rule does not fire on generic PATH mutation, generic npm/docker/az/gcloud use, action-owned absolute helper paths, or explicit mode choices without authority transport.
- Positive fixtures cover at least one path for each high-signal transport class and one action-minted or generated-credential origin, with same-job caveat text present where applicable.
- The same workflow input, parser metadata, catalog version, and feature flags produce the same exploit-path output on repeated runs.
- `CHANGELOG.md` has a detection delta entry before rc.1 if this work changes rule behavior, schemas, report fields, or default output.

## Risks / Non-Goals

- Non-goal: taudit does not execute hosted-runner proofs or become the witness harness (`docs/adr/0005-authority-edge-classifier-and-witness-handoff.md`).
- Non-goal: taudit does not claim CVEs by default, and internal disclosure scoring must not leak into customer output (`docs/adr/0005-authority-edge-classifier-and-witness-handoff.md`, `docs/adr/0006-exploit-path-view-and-ruleset.md`).
- Non-goal: the exploit-path projection does not replace the canonical authority graph or change `AuthorityGraph` into a disclosure artifact (`docs/authority-graph.md`, `crates/taudit-core/src/graph.rs`).
- Risk: over-broad matching turns the feature into PATH lint. Control it with mandatory timing, authority transport, helper resolution, and downgrade evidence.
- Risk: under-modelled action catalog entries hide real helper authority paths. Control it with source anchors, fixtures, catalog versioning, and explicit `witness_status`/evidence-strength fields.
- Risk: same-job objections can be misread. Keep the caveat explicit: the finding is about earlier helper-resolution mutation before later deploy/publish/sign authority is materialized, not about claiming isolation between arbitrary same-job steps.
- Risk: observed/inferred language can drift. Treat static/source, inferred, and observed as separate evidence strengths, and require explicit witness input before `observed_path_count` or `ObservedSink` becomes non-zero.

## Suggested Verification

- Run targeted Rust tests for exploit-path construction and graph export after schema/rule changes: `cargo test -p taudit-core exploit_path`.
- Run the workspace gates before rc.1: `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- Validate exploit graph JSON fixtures against `schemas/exploit-graph.v1.json`, including empty-path, positive-path, downgraded/suppressed-path, and explicit-witness cases.
- Snapshot default text, SARIF, CloudEvents, and JSON output for positive helper-authority findings and verify absence of `CVE`, `disclosure_score`, witness-spec routing, canary values, and private run anchors unless an internal gate is enabled.
- Run `just golden-paths` when graph/report/docs snapshots change, because `docs/ROADMAP.md` treats golden paths as blessed demo commands.
- Review `CHANGELOG.md` before rc.1 and add a detection delta if any finding behavior, schema, or default output changes.
