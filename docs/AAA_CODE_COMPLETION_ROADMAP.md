# taudit AAA code-completion roadmap

Status basis: local repository inspection on 2026-05-04. This document treats
"full AAA" as the version a platform/security team can adopt as a standard CI/CD
authority tool without private caveats: stable contract, trustworthy outputs,
three-platform confidence, real-input proof, and low-noise enterprise operation.

## Current observed state

- Workspace is Rust, 10 crates, CLI package version `1.1.0-rc.1`.
- Product thesis is graph-first: CI/CD authority is parsed into typed nodes,
  trust zones, edges, propagation paths, and findings.
- Public contract surface exists: `taudit-api`, JSON schemas, SARIF,
  CloudEvents, graph export, baseline and suppression formats.
- Three parsers exist: GitHub Actions, Azure DevOps, GitLab CI.
- Built-in rule catalogue is large: docs list 61 built-in rules and the core
  rules module wires the catalogue through `run_all_rules`.
- Verification infrastructure is serious: fmt, clippy, workspace tests, schema
  drift checks, snapshots, deny, audit, golden paths, release build, self-scan,
  scheduled fuzz workflow, mutation workflow, and release gates.
- The repository still contains contradictory/stale planning copy. `docs/ROADMAP.md`
  says the old AAA gate is closed, but the same repo has open gates for stable
  promotion, public corpus population, parser completeness, seam/correlation
  work, ADO enrichment, and signed release follow-ups.

## AAA definition for this repo

AAA is complete when these gates are all true:

CHK-A1: Stable public contract is safe to consume.
Evidence: `taudit-api`, schemas, JSON/SARIF/CloudEvents parity tests, semver
checks, changelog migration notes.

CHK-A2: Real-input confidence exists.
Evidence: curated public corpus of at least 100 pipeline files across GHA, ADO,
and GitLab; scan outputs schema-validate; no crashes/hangs; dogfood report
committed for the release.

CHK-A3: Parser partiality is honest and reduced on mainstream constructs.
Evidence: supported constructs parse to `AuthorityCompleteness::Complete`; known
unresolved constructs emit typed `GapKind` entries; no silent under-modeling.

CHK-A4: Output channels are trustworthy.
Evidence: no terminal/SARIF/CloudEvents injection class, stable fingerprints,
cross-sink rule id/fingerprint agreement, no path/line-ending nondeterminism.

CHK-A5: Enterprise adoption path is low-noise.
Evidence: baselines, suppressions, custom invariants, ADO variable-group
handling strategy, policy gate docs, migration docs.

CHK-A6: Release/promotion gate is cleared.
Evidence: `docs/RELEASE_GATES.md` hard gates pass, 14-day soak conditions are
satisfied, public-corpus and fuzz windows are clean, changelog is release-ready.

## Critical contradictions to resolve first

1. `CHANGELOG.md` rc.1 text says stable promotion requires ">=2 concurrent
   pilots ... recorded buyer-side reference call"; `docs/RELEASE_GATES.md`
   replaced that with maintainer-side real-input gates. Update changelog or
   release notes before stable promotion.
2. `docs/ROADMAP.md` still has stale claims about composite action parsing and
   "AAA gate closed", while `CHANGELOG.md` says local composite-action inlining
   was deliberately removed and now marks Structural partiality.
3. `docs/rules/index.md` says "All other rules fire on both GitHub Actions and
   Azure DevOps", but the same table includes GitLab-only and platform-specific
   rows. Fix the footer to avoid misleading operators.
4. `docs/dogfood-corpus.md` is a stub. `docs/RELEASE_GATES.md` makes this a
   stable-promotion blocker.
5. `docs/ROADMAP.md` Done gate says fuzzing/property tests/benchmarks remain
   open, while current workflows and crate benches show some of this exists.
   Reconcile "exists" vs "gates stable promotion" vs "full Done".

## Phase 0: planning truth repair

Goal: make the roadmap, gates, changelog, and docs agree before coding more.

Tasks:

- Update `docs/ROADMAP.md` to distinguish historical AAA v0.3.0 from current
  full-AAA/stable `1.1.x` gate.
- Update `CHANGELOG.md` rc.1 promotion wording to match `docs/RELEASE_GATES.md`.
- Update `docs/rules/index.md` platform footer.
- Mark which `docs/gaps-implementation-prompt.md` gaps are shipped, moved to
  scheduled workflows, or still open.
- Add a small `docs/audit-tracker.md` if release-gate P0/P1 tracking needs a
  permanent home instead of `/tmp/taudit-deep-review/00-synthesis.md`.

Exit criteria:

- No public doc claims a gate is closed while another live doc says it blocks
  stable promotion.
- Changelog, release gates, and roadmap define the same promotion path.

## Phase 1: stable-promotion gate closure

Goal: get from `1.1.0-rc.1` to stable without weakening the release gate.

Tasks:

- Populate `docs/dogfood-corpus.md` and `corpus/dogfood/` with at least 100
  pinned public CI files across GHA, ADO, and GitLab.
- Add the corpus runner described in `docs/dogfood-corpus.md`; validate JSON
  against `contracts/schemas/taudit-report.schema.json`.
- Commit `docs/dogfood/v1.1.0.md` with self-scan results for this repo and at
  least two sibling CI estates if available.
- Confirm scheduled fuzz ran cleanly across the soak window, or document why
  the stable cut is blocked.
- Run release-gate commands: fmt, clippy, workspace tests, schema generator
  `--check`, semver checks, deny, audit, snapshots, golden paths.
- Confirm no new P0/P1 public-contract findings during the soak.

Exit criteria:

- `docs/RELEASE_GATES.md` section 2.2 is satisfied with committed evidence.
- Stable release notes no longer contain stale pilot/reference-call language.

## Phase 2: parser completeness and honest partiality

Goal: reduce Partial graphs on mainstream pipelines while preserving explicit
gap evidence.

GHA:

- Keep local composite action behavior honest: if taudit does not read the
  filesystem, do not claim `Complete`; if reintroducing inlining, make it
  deterministic from an explicit repo root and document it.
- Add limited expression evaluation only for bounded, high-signal expressions
  such as `github.event_name`, fork checks, and obvious branch gates. Preserve
  `GapKind::Expression` fallback.
- Improve reusable workflow authority modeling where caller-provided secrets
  are statically present; keep remote fetch out of scope unless explicitly
  designed.

ADO:

- Finish static parity around template constructs, resources, service
  connections, variable groups, conditions, `dependsOn`, deployment jobs, and
  environment gates.
- Implement optional ADO variable-group enrichment from `TODOS.md` if enterprise
  noise reduction is required for AAA adoption: `--ado-org`, `--ado-project`,
  `--ado-pat`, read-only scope, no logging, graceful fallback.

GitLab:

- Continue `include:` and `extends:` treatment: either resolve deterministic
  local forms or mark Structural partiality with stable reasons.
- Model protected branch/tag rules where statically visible.
- Improve variable scope handling for environment/group/project variables
  without pretending unavailable GitLab API state is known.

Exit criteria:

- Each parser has a supported-feature matrix.
- Every unsupported mainstream construct has a typed gap and fixture.
- Public corpus shows partiality rates and top gap causes by platform.

## Phase 3: rule and invariant contract polish

Goal: make built-in and custom rules feel like a stable authority-invariant
language, not a pile of detections.

Tasks:

- Confirm every `FindingCategory` has schema coverage, docs, tests, and stable
  rule id mapping.
- Reconcile reserved categories (`egress_blindspot`, `missing_audit_trail`) with
  docs: either implement built-ins or explicitly document reserved status.
- Ensure `taudit explain`, `docs/rules/index.md`, SARIF rule metadata, and JSON
  `rule_id` agree byte-for-byte.
- Expand custom invariant examples for real enterprise policies, including
  partial-graph stance.
- Keep `--rules-dir` as alias but make `--invariants-dir` canonical in docs.

Exit criteria:

- Rule catalogue count, docs, schemas, CLI explain, and emitted ids all agree.
- A downstream policy author can write and validate an invariant without reading
  Rust source.

## Phase 4: output, correlation, and downstream trust

Goal: make output artifacts safe for tsign, axiom, SIEM, Backstage, and CI gates.

Tasks:

- Finish seam-shaped CloudEvents fields from `docs/jobs-phased-lanes.md` Phase 2:
  stable subject URNs, pipeline id, scan run id, rules version, provenance parent
  readiness.
- Keep `TAUDIT_CORRELATION_ID` behavior documented and tested.
- Validate CloudEvents schema examples under `contracts/examples/`.
- Confirm JSON/SARIF/CloudEvents carry identical fingerprints, rule ids, and
  group ids for built-in and custom findings.
- Publish a concise downstream-consumer guide for `taudit-api` vs JSON schemas.

Exit criteria:

- Downstream consumers can correlate findings across formats without
  re-deriving ids.
- Output channels stay render-safe under attacker-controlled YAML/custom-rule
  strings.

## Phase 5: enterprise/noise hardening

Goal: make adoption on large existing estates practical.

Tasks:

- Complete or deliberately defer ADO `--ado-pat` enrichment.
- Strengthen suppression and baseline docs around critical waivers, expiry, and
  partial-graph behavior.
- Add public examples for "new findings only" PR gates, starter invariants, and
  strict vs advisory modes.
- Ensure dense-graph guard, propagation summary, and map/graph UX are documented
  for monorepos.

Exit criteria:

- A large org can adopt taudit without first fixing every historical finding.
- Known-noise controls are auditable and time-bounded.

## Phase 6: performance and resilience

Goal: keep the graph product fast and safe at corpus scale.

Tasks:

- Keep adjacency-based propagation as the default engine; add benchmarks to
  watch regression on large graphs.
- Run parser fuzz targets in scheduled CI and document how crashers are triaged.
- Decide whether mutation testing remains weekly/advisory or becomes a hard
  quality gate.
- Add property tests for graph invariants: edge endpoints valid, gap arrays
  stay parallel, fingerprints stable under path separator and CRLF variation,
  sink outputs preserve cross-format identity.

Exit criteria:

- Public corpus, fuzz smoke, property tests, and benches provide regression
  evidence for full-AAA stability.

## Recommended execution order

1. Phase 0 documentation truth repair.
2. Phase 1 stable-promotion gate closure.
3. Phase 2 parser completeness by corpus top gap causes.
4. Phase 4 output/correlation work if tsign/axiom integration is next.
5. Phase 5 ADO enrichment if enterprise ADO noise is blocking adoption.
6. Phase 3 rule catalogue polish in parallel with parser work where write sets
   do not overlap.
7. Phase 6 resilience as a continuing gate, not a one-time feature.

## Residual risk

- I did not run the full test suite for this roadmap artifact; evidence is from
  file inspection, not execution.
- Some docs are historical and intentionally retained. Treat this roadmap as the
  current synthesized plan, not proof that every older checklist is wrong.
- Public-corpus and soak-window status cannot be proven from the local repo
  alone; those require CI/history evidence.
