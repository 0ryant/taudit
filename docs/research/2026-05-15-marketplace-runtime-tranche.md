# 2026-05-15 Marketplace Runtime Tranche

## Goal
Drive the remaining taudit marketplace/runtime work in parallel: republish readiness, live Azure proof, proof media planning, and dogfood/self-audit guidance.

## Lanes
- Lane A: Publish/live-page QA
- Lane B: Visual proof media
- Lane C: Real Azure runtime proof
- Lane D: Dogfood/self-audit patterns
- Lane E: Read-only marketplace review

## Task Count
14 concrete tasks remain across 5 lanes.

## Task inventory

### Lane A — Publish and live-page QA
1. Republish the VS Code extension with the latest listing copy.
2. Republish the Azure DevOps extension with the latest overview and trust copy.
3. Verify live marketplace pages render the updated text, links, and icon correctly.

### Lane B — Proof media
4. Capture a VS Code `Verify Workspace` screenshot.
5. Capture an authority graph screenshot/render.
6. Capture an exploit graph screenshot/render.
7. Record a short GIF: initialize policy -> verify -> inspect output.

### Lane C — Azure runtime proof
8. Add `Taudit@1` to one real Azure pipeline.
9. Run it successfully end to end.
10. Verify outputs and artifacts: `taudit.outcome`, `taudit.reportPath`, graph/report artifact behavior.

### Lane D — Dogfood/self-audit guidance
11. Add one explicit doc example for keeping taudit self-findings visible but non-blocking via policy, baseline, or suppressions.
12. Add one concrete pipeline snippet for Azure DevOps or GitHub dogfood lanes.

### Lane E — Final conversion polish
13. Review the live rendered listings after republish and tighten hero/short-description copy if needed.
14. Add screenshot or GIF references into marketplace-facing docs/listings where supported.

## Tranche 1 assignments
- Worker 1 (Zeno): Azure DevOps live-proof checklist and smoke-lane review
- Worker 2 (Avicenna): Marketplace media shot list and capture plan
- Worker 3 (Linnaeus): Dogfood/self-audit non-blocking patterns
- Reviewer (Averroes): Remaining marketplace-conversion/trust review

## Critical path
1. Republish marketplace surfaces
2. Run one real Azure pipeline with Taudit@1
3. Add proof media to listings/docs

## Integration rules
- One writer per file per tranche.
- Agent outputs are claimed evidence until reviewed locally.
- Publish and real Azure runtime proof stay on the critical path.
