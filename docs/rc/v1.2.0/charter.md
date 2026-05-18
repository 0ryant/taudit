# v1.2.0-rc.1 Charter: Authority Evidence Platform

## Decision

Build the first v1.2 release candidate around authority evidence, not rule-pack
volume. `v1.2.0-rc.1` should prove that taudit can expose a public contract,
explain risky authority paths with ordered evidence, and show those results in
the places operators actually adopt tools.

This is a release candidate because the promise is stable in intent but still
needs soak: real-input corpus coverage, public contract checks, release trust
artifacts, and marketplace proof must pass before stable promotion.

## Council Synthesis

The six workstreams converged on one direction:

- The product kernel is the contract platform: `taudit-api`, schemas, JSON,
  SARIF, CloudEvents, fingerprints, and suppressions must be versioned as public
  surfaces.
- The flagship detection value is authority-timed evidence: a finding should
  show how mutable state, authority materialization, helper resolution, and
  authority transport connect in time.
- The adoption layer is the marketplace trust pack: no wrapper or listing should
  claim readiness until hosted runs, receipts, media, and release assets prove
  it.
- The credibility layer is measured parser completeness: platform support is
  reported by corpus evidence and typed gaps, not by slogan.
- The release lane is `v1.2.0-rc.1`: publish sparingly, mark it as prerelease,
  and promote to stable only after the written gates clear.
- The execution model is lane-owned parallelism: API/schema before consumers,
  parser/core before reports, reports before operator docs, release prep last.

## Release Promise

`v1.2.0-rc.1` should make three externally visible promises:

1. **Contract clarity:** public consumers can depend on named API, schema, JSON,
   SARIF, CloudEvents, fingerprint, suppression, and exit-code behavior.
2. **Evidence clarity:** authority findings are backed by ordered typed evidence
   and avoid CVE, disclosure, or witness overclaiming in default output.
3. **Operator clarity:** GitHub Actions, Azure DevOps, VS Code, crates.io, and
   release assets each have bounded adoption docs and proof receipts.

Supporting promises:

1. Parser completeness is measured against pinned real inputs.
2. Every behavior delta is described in the changelog before tagging.
3. Stable promotion is evidence-gated, not calendar-gated.

## Non-Goals

- Do not make `v1.2.0-rc.1` a generic rule-volume release.
- Do not claim full CI interpretation, cloud IAM resolution, or runtime
  exploitation.
- Do not publish a wrapper-only marketplace release without hosted proof.
- Do not mark `taudit-api` as 1.0-ready unless the readiness checklist and
  conformance harness support that claim.
- Do not let planning docs become operator-facing shipped behavior claims.

## First Tranche

| Order | Work | Exit condition |
| --- | --- | --- |
| 0 | Land RC control docs | Charter, six briefs, execution lanes, and semver lane are merged. |
| 1 | Baseline API and schema contract | Public contract matrix and drift checks identify additive versus breaking deltas. |
| 2 | Define authority evidence model | Ordered evidence events and exploit-path graph schema are documented and fixture-backed. |
| 3 | Build real-input corpus gate | Corpus runner, manifest, and parser completeness report exist with typed gaps. |
| 4 | Wire reports and sinks | JSON, SARIF, terminal, and CloudEvents preserve identity, evidence, and suppressions. |
| 5 | Prove adoption surfaces | GitHub Action, Azure DevOps task, VS Code preflight, screenshots, and receipts are bounded by hosted proof. |
| 6 | Cut `v1.2.0-rc.1` | Release harness, changelog detection delta, crate-version map, SBOMs, attestations, and crates.io publish pass. |

## RC Acceptance Gates

The RC is not tag-ready until all of these are true:

- `CHANGELOG.md` contains `## v1.2.0-rc.1` with `Detection delta (read first)`,
  finding-count direction, FP/FN movement, schema/output impact, and migration
  notes.
- The CLI product version, `taudit-api` version, and implementation crate
  version line are recorded before tagging.
- Contract checks cover API/schema/report/SARIF/CloudEvents identity and drift.
- Authority evidence findings require ordered typed evidence and default output
  stays customer-safe.
- Parser completeness is reported from the pinned corpus, with incomplete areas
  represented as typed gaps.
- Marketplace and editor claims are backed by proof receipts, not local-only
  screenshots.
- Release trust artifacts match the stable surface: release notes, archives,
  checksums, SPDX and CycloneDX SBOMs, GitHub attestations, and crates.io
  publish after dependent jobs succeed.

Stable `v1.2.0` promotion remains blocked until the latest RC completes the
soak and promotion gates in `docs/RELEASE_GATES.md` without semantic payload
changes that require a new RC.

## Coordination Rules

Use the execution lanes as the source of truth for follow-up work. Assign one
writer per high-churn path, keep parser lanes crate-disjoint, serialize release
automation edits, and merge from lower-level contracts toward higher-level
operator surfaces.

If a later implementation changes the selected direction, update this charter
before claiming RC readiness.
