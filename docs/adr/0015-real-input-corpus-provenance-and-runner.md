# ADR 0015: Real-input corpus provenance and runner

- **Status:** Accepted
- **Date:** 2026-05-18
- **Context:** [parser completeness workstream](../rc/v1.2.0/workstreams/parser-completeness-corpus.md), [RELEASE_GATES.md](../RELEASE_GATES.md), [dogfood-corpus.md](../dogfood-corpus.md).

## Context

The RC needs measured parser truth. The current checkout has corpus-related
tests and research scripts, but the public real-input corpus described by the
docs is not present as a release-gated artifact, and `/corpus/` is ignored.

## Decision

The real-input corpus is a manifest-plus-runner product surface.

The manifest records:

- provider platform;
- upstream URL;
- immutable commit or artifact digest;
- license or use basis;
- local fixture path or fetch method;
- expected parser;
- expected completeness state;
- expected gap kinds;
- timeout class;
- notes on secrets and redaction.

The runner must scan the pinned corpus with `taudit scan --format json
--no-color`, validate scan JSON against the report schema, and emit complete,
partial, unknown, failure, and gap-kind histograms.

The initial RC corpus target is at least 100 public files across GitHub Actions,
Azure DevOps, and GitLab CI, plus a named Bitbucket tranche. Stable promotion may
raise the count but must not lower provenance requirements.

## Lane Ownership

- **L3 corpus** owns manifest, fetcher or checked-in fixture policy, runner, and
  parser-specific expectations.
- **L2 contracts** owns schema validation.
- **L6 docs/operator evidence** owns public corpus report.
- **L1 release coordination** owns release-gate wiring.

## Acceptance Gates

- corpus storage path is tracked or the fetcher writes into an ignored cache
  from a tracked manifest
- runner has timeouts and fails on panic, hang, schema-invalid JSON, and
  untyped parser failure
- report includes platform histograms and top gap causes
- release notes link the corpus report used for the tag

## Consequences

Completeness becomes measurable. Parser PRs can be prioritized by real top gap
causes instead of anecdote.
