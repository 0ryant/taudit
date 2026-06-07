# AXIOM Record: v1.2 RC ADR And Lane Planning

## Problem

The v1.2 RC direction needed an exhaustive ADR and subtask plan that multiple
agents can execute without overlapping ownership or overclaiming release
readiness.

## Goal

Create durable repo artifacts that enumerate the ADR decisions and laneable
subtasks required to take `v1.2.0-rc.1: Authority Evidence Platform` to code
complete.

## Constraints

- Preserve existing untracked local state.
- Do not write runtime roots.
- Treat Cortex and subagent outputs as candidate evidence until reconciled with
  repository files.
- Keep operator-facing claims bounded by evidence.

## Criteria

- CHK-1: New ADRs cover release, contracts, evidence, parser/corpus, output,
  proof, adoption, and post-RC unlock boundaries.
- CHK-2: A master lane backlog names owned paths, dependencies, acceptance
  gates, and final code-complete criteria.
- CHK-3: Index documents link the new artifacts.
- CHK-4: Verification checks run after edits.

## Lanes

- Council L1: contract/API/schema read-only gap pass.
- Council L2: authority-timed evidence/core rules read-only gap pass.
- Council L3: parser completeness/corpus read-only gap pass.
- Council L4: CLI/report/sink/output identity read-only gap pass.
- Council L5: release/adoption/marketplace/provenance read-only gap pass.
- Council L6: strategic unlocks read-only gap pass.

## Decisions

- DEC-1: Add ADRs 0009 through 0024 rather than overloading the six RC
  workstream briefs.
- DEC-2: Make `docs/rc/v1.2.0/code-complete-lanes.md` the dispatch backlog for
  follow-up parallel implementation.
- DEC-3: Separate RC blockers from post-RC ecosystem unlocks.

## Evidence

- FILE(`docs/rc/v1.2.0/charter.md`) selected `Authority Evidence Platform`.
- FILE(`docs/rc/v1.2.0/workstreams/*.md`) provided initial six workstreams.
- TOOL(`spawn_agent`, result=six read-only council lanes returned gap lists).
- FILE(`docs/adr/0009-v1-2-release-contract-and-semver-map.md`) through
  FILE(`docs/adr/0024-external-diagnostic-intake-boundary.md`) record ADRs.
- FILE(`docs/rc/v1.2.0/code-complete-lanes.md`) records the lane backlog.

## Verification

- CMD(`git diff --check`, exit=0) reported no whitespace errors for tracked
  changes.
- CMD(`rg placeholder scan`, exit=1) found no placeholder patterns in the new
  ADR and lane artifacts.
- CMD(`PowerShell ASCII scan`, exit=0) found no non-ASCII characters in the new
  ADR and lane artifacts.
- CMD(`PowerShell markdown link check`, exit=0) found no missing local links in
  the new ADR and lane artifacts.

## Learning

For taudit v1.2, the critical path is not more isolated rules. It is making
authority evidence, output identity, parser completeness, and operator proof
share one contract and one release gate.

## Session: 2026-06-01 Competitive Report Fixes

### Goal

Update the Azure DevOps Marketplace package candidate, turn the arXiv benchmark
gap into executable tasking, and implement conservative fixes from the
competitive report without exceeding the ADR 0005/0006 evidence ceiling.

### Constraints

- AXIOM is an authority/evidence layer, not another coding agent.
- Market-leading, release-ready, production-ready, fastest, broadest, and
  externally benchmarked claims require current proof gates.
- Subagent outputs are candidate evidence until reconciled in the main tree.
- Live Marketplace publishing remains operator-owned.

### Criteria

- CHK-1: Source-local Azure DevOps extension manifests and docs target the
  latest observed taudit release.
- CHK-2: arXiv path records inclusion, reproduction, and independent-submission
  gates without claiming acceptance.
- CHK-3: Report remediation work is implemented in code and tests, not only
  docs.
- CHK-4: Competitive and public-facing docs carry evidence ceilings for
  unsupported stronger claims.
- CHK-5: Verification commands run after the final edits.

### Lanes

- ADO-MARKETPLACE: source-local Azure DevOps package/doc update.
- ARXIV: read-only benchmark inclusion and reproduction plan.
- REPORT-FIXES: remediation and claim-ceiling implementation, reconciled by the
  primary agent after overlapping lane drift.

### Evidence

- FILE(`integrations/azure-devops-extension/vss-extension.json`) now records
  extension `0.1.10`.
- FILE(`integrations/azure-devops-extension/Taudit/task.json`) now records
  task patch `1.0.6` and default `taudit` `1.1.5`.
- FILE(`docs/research/2026-06-01-arxiv-benchmark-inclusion-plan.md`) records
  the arXiv benchmark route and stop conditions.
- FILE(`crates/taudit-cli/src/remediate.rs`) implements patchable versus
  review-only remediation suggestions.
- FILE(`docs/positioning.md`) and
  FILE(`docs/research/2026-06-01-competitive-scorecard.md`) record the claim
  ceiling.

### Verification

- CMD(`npm run preflight`, exit=0) packaged and smoked
  `dist/algol.taudit-azure-pipelines-0.1.10.vsix`.
- CMD(`cargo test -p taudit --test remediate_contract`, exit=0) passed 10
  remediation contract tests.
- CMD(`cargo test -p taudit remediate`, exit=0) passed 11 targeted remediation
  unit tests.
- CMD(`cargo fmt --all -- --check`, exit=0) passed.
- CMD(`git diff --check`, exit=0) passed with line-ending warnings only.
- SEARCH(`Visual Studio Marketplace extensionquery`, result=live
  `Algol.taudit-azure-pipelines` still reports `0.1.9`).
- SEARCH(`crates.io api taudit`, result=latest stable crate `1.1.5`).

### Residual Risk

- Live Azure DevOps Marketplace is still `0.1.9`; source-local `0.1.10` is a
  publish candidate until operator upload and live smoke are recorded.
- `npm audit --omit=dev` in the task runtime reports 2 moderate advisories via
  `azure-pipelines-task-lib` -> `uuid`, with no available upstream fix while
  `azure-pipelines-task-lib` is at latest observed `5.2.10`.
- taudit is not in the arXiv benchmark and has no external FP/FN or runtime
  benchmark receipt yet.
