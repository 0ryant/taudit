# ADR 0008: Synthesize research into maintained artifacts, not scratch files

- **Status:** Accepted
- **Date:** 2026-05-13
- **Context:** [README.md](../../README.md), [docs/rules/index.md](../rules/index.md), [ADR 0007](0007-standardize-release-harness.md).

## Context

Timestamped scratch research files were useful during the v1.1 release cleanup,
but they surfaced two recurring failure modes:

1. durable signals lived in one-off `RESEARCH-*.md` notes instead of maintained
   policy or product documentation, and
2. public docs carried hand-maintained exact counts that drifted from the live
   product surface.

Those notes were helpful as private working material. They are not good public
contracts. They age quickly, duplicate maintained docs, and invite the repo to
accumulate historical critiques without folding the conclusions back into the
documents or tooling that actually govern the product.

## Decision

1. **Scratch research files do not live in the public repository root.**
   Timestamped `RESEARCH-*.md` notes, council scratchpads, and similar working
   artifacts are temporary inputs, not public-facing deliverables.

2. **Durable signals from research must be synthesized into maintained
   artifacts.**
   Acceptable targets are ADRs, release policy docs, maintained product docs,
   tests, or tooling changes.

3. **Public quantitative claims must be mechanically derived or phrased without
   exact counts.**
   README and rule-catalogue surfaces should point users at live commands such
   as `taudit explain` instead of hard-coding counts that can drift.

4. **The synthesized artifact is the record.**
   Once the signal has been carried into ADRs/docs/tooling, delete the scratch
   research note rather than keeping both.

## Consequences

### Positive

- The public repo keeps stable policy and product docs instead of accumulating
  timestamped scratch analysis.
- Release and product decisions are easier to audit because the durable record
  lives where maintainers already look.
- Public-facing docs stop depending on manually-updated exact counts.

### Negative

- Some intermediate rationale disappears once the synthesis is done.
- Maintainers have to do one extra pass to distill findings into policy or docs
  before deleting scratch notes.

### Follow-up

- When a future research note finds a policy gap, encode the fix in an ADR or
  maintained doc first, then remove the scratch note.
