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
