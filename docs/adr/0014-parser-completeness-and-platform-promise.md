# ADR 0014: Parser completeness and platform promise

- **Status:** Accepted
- **Date:** 2026-05-18
- **Context:** [parser completeness workstream](../rc/v1.2.0/workstreams/parser-completeness-corpus.md), [ROADMAP.md](../ROADMAP.md), [dogfood corpus docs](../dogfood-corpus.md).

## Context

taudit now has parser crates for GitHub Actions, Azure DevOps, GitLab CI, and
Bitbucket Pipelines. Older roadmap language and RC language disagree on whether
the release promise is three-platform completeness with a Bitbucket tranche or
a four-platform stable promise.

## Decision

v1.2 RC claims must use measured parser language:

- GitHub Actions, Azure DevOps, and GitLab CI are the release-gated platforms.
- Bitbucket is included as a named parser tranche until the matrix, fixtures,
  fuzz target, and corpus evidence support promotion to the release gate.
- A parser may say `Complete` only for the supported authority surface that is
  listed in the feature matrix.
- Unsupported mainstream constructs must emit typed gaps instead of silent
  under-modeling.

Release notes and docs must avoid broad "complete platform support" language.
They must name supported surfaces, typed gap classes, and corpus evidence.

## Lane Ownership

- **L3 parser parity** owns parser crates and platform fixtures.
- **L6 docs/operator evidence** owns platform promise copy.
- **L1 release coordination** owns changelog wording.

## Acceptance Gates

- parser feature matrix exists for GitHub Actions, Azure DevOps, GitLab CI, and
  Bitbucket
- every matrix row has support state, gap kind, fixture, corpus sample, and
  intended release state
- release notes name Bitbucket status accurately
- no docs claim parser completeness beyond the matrix

## Consequences

taudit can add Bitbucket momentum without overclaiming. Stable platform promises
become evidence-bound and testable.
