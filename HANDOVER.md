# taudit Handover - 2026-05-19

This handover records the release work that landed in the latest session and
what the next operator or agent should do from the repo root.

Current local date for this handover is 2026-05-19 Europe/London. The shipped
commits below were merged on 2026-05-18 local time and are the latest landed
work on `main`.

## Current Repository State

- Branch: `main`.
- Remote sync: `main` is aligned with `origin/main`.
- Latest merge: `d6694a4 Merge pull request #29 from 0ryant/codex/v1.2.0-rc-direction`.
- Merged feature branch: `codex/v1.2.0-rc-direction`.
- Last stable tag before the RC branch: `v1.1.5` at `870ff1a`.
- Working tree note: `.cordance/` and `pai-axiom-project-harness-target.json`
  are untracked in this checkout. They were not part of the merged taudit
  release payload and should not be committed without an explicit owner decision.

## What Shipped

### Stable patch: `v1.1.5`

`v1.1.5` shipped as a stable metadata and findability patch. It did not change
rules, parsers, graph semantics, report schemas, CLI behavior, dependencies, or
output behavior.

The important payload was:

- dedicated README files for public API, core, parser, reporter, and sink crates;
- publishable crate manifests wired to their crate-specific README files;
- crate metadata tuned for crates.io search with targeted keywords, categories,
  docs.rs URLs, and repository metadata;
- root README architecture crate map refreshed;
- pinned install docs updated for `taudit 1.1.5`.

Operator meaning: stable users get better crates.io/docs.rs discovery and
package documentation without any migration work.

### Release candidate line: `v1.2.0-rc.1`

PR #29 landed the `v1.2.0-rc.1: Authority Evidence Platform` direction and RC
payload preparation. The branch added or changed 137 files with roughly 15.7k
insertions. This is a substantial RC foundation, but stable `v1.2.0` is still a
separate promotion step.

The selected direction is not "more rules first." It is:

- public contract clarity across `taudit-api`, schemas, JSON, SARIF,
  CloudEvents, fingerprints, suppressions, baselines, and exit behavior;
- ordered authority evidence, so findings can explain time-ordered authority
  materialization, mutable state, helper resolution, and authority transport;
- measured parser completeness using typed gaps and corpus evidence;
- operator proof surfaces with receipts before any hosted or marketplace claim
  is treated as live;
- release discipline that separates RC tag readiness from stable promotion.

## Major Landed Areas

### 1. RC control plane and lane map

The new control folder is `docs/rc/v1.2.0/`.

Key files:

- `docs/rc/v1.2.0/README.md`
- `docs/rc/v1.2.0/charter.md`
- `docs/rc/v1.2.0/code-complete-lanes.md`
- `docs/rc/v1.2.0/workstreams/execution-lanes.md`
- `docs/rc/v1.2.0/release-map.md`
- `docs/rc/v1.2.0/release-readiness-checklist.md`

The control plane defines lanes L1 through L6 plus QA gates:

- L1: release coordination, version map, changelog, release harness, proof
  receipts;
- L2: API, schemas, contracts, current-output profiles, reference consumers;
- L3: parser completeness and corpus runner;
- L4: core graph, ordered evidence, action-intelligence catalog, rule semantics;
- L5: CLI, reports, sinks, output identity, parity, conformance;
- L6: docs, operator evidence, adoption proof, receipts;
- QA: formatting, lint, tests, contract checks, corpus checks, release readiness.

This should be the starting point for any next parallel-agent wave.

### 2. ADRs 0009 through 0024

The RC branch added the ADR run for v1.2:

- `0009`: v1.2 release contract and SemVer map.
- `0010`: public contract boundary and `taudit-api` readiness.
- `0011`: ordered authority evidence model.
- `0012`: public output identity contract.
- `0013`: evidence rendering and output ceiling.
- `0014`: parser completeness and platform promise.
- `0015`: real-input corpus provenance and runner.
- `0016`: external resolution and enrichment boundary.
- `0017`: current-output profile and contract examples.
- `0018`: suppression, baseline, and exit-code semantics.
- `0019`: reporter and sink sanitization boundary.
- `0020`: output conformance harness and RC gate.
- `0021`: operator proof receipt contract.
- `0022`: adoption doc version and link policy.
- `0023`: ecosystem evidence envelope and stack contracts.
- `0024`: external diagnostic intake boundary.

Operator meaning: the next code work now has explicit decision boundaries.
Agents should implement against these ADRs rather than reopen the same debates.

### 3. Release and QA harnesses

New or expanded offline harnesses landed:

- `scripts/release_harness.py`
- `scripts/conformance_harness.py`
- `scripts/corpus_runner.py`
- `scripts/current_output_profile_check.py`
- `scripts/doc_truth_scan.py`
- `scripts/output_evidence_parity.py`
- `tests/test_release_harness.py`
- `tests/test_conformance_harness.py`
- `tests/test_corpus_runner.py`
- `tests/test_current_output_profile_check.py`
- `tests/test_doc_truth_scan.py`
- `tests/test_output_evidence_parity.py`
- `tests/test_reference_consumers.py`
- `tests/test_action_intelligence_catalog.py`

Important boundary: ADR 0020 conformance is wired, but the skeleton can still
report pending checks. Pending conformance blocks stable promotion. It may be
acceptable for an RC only if the changelog and release notes do not overclaim.

### 4. Public identity and evidence contract work

The RC line added or hardened:

- cross-sink identity checks for `rule_id`, `fingerprint`, `suppression_key`,
  and `finding_group_id`;
- current-output profile docs and checks;
- schema drift controls;
- SARIF public-extra mapping;
- CloudEvents projection mapping;
- evidence parity harness;
- hostile rendering corpus coverage;
- suppression, baseline, and exit-code matrix tests;
- operator evidence output guide;
- ordered evidence wire-field docs.

Key paths include:

- `crates/taudit-core/src/evidence.rs`
- `crates/taudit-core/src/finding.rs`
- `crates/taudit-cli/tests/cross_sink_contract.rs`
- `crates/taudit-cli/tests/hostile_rendering_corpus.rs`
- `crates/taudit-cli/tests/suppression_baseline_exit_matrix.rs`
- `crates/taudit-report-sarif/src/lib.rs`
- `crates/taudit-sink-cloudevents/src/lib.rs`
- `docs/rc/v1.2.0/ordered-evidence-wire-fields.md`
- `docs/rc/v1.2.0/output-identity-field-map.md`
- `docs/rc/v1.2.0/evidence-parity-harness.md`
- `docs/rc/v1.2.0/current-output-profile.md`

Operator meaning: v1.2 is being turned into a contract-bearing release, not a
loose bundle of examples.

### 5. Parser completeness and typed gaps

The branch added fixtures, docs, fuzz seeds, and parser updates for:

- GitHub Actions service containers and credentials;
- Azure DevOps resources, secure files, containers, pipeline artifacts, and
  shared-pool cases;
- GitLab generic artifacts;
- Bitbucket caches, clone options, runner options, contexts, partial forms,
  pipes, services, parallel stages, and stage semantics.

Key paths include:

- `docs/parser-feature-matrix.md`
- `schemas/corpus-manifest.v1.json`
- `scripts/corpus_runner.py`
- `crates/taudit-parse-gha/src/lib.rs`
- `crates/taudit-parse-ado/src/lib.rs`
- `crates/taudit-parse-gitlab/src/lib.rs`
- `crates/taudit-parse-bitbucket/src/lib.rs`
- `crates/taudit-parse-bitbucket/fuzz/**`
- `tests/fixtures/gha-service-containers-and-credentials.yml`
- `tests/fixtures/ado-resources-secure-files-artifacts.yml`
- `tests/fixtures/gitlab-generic-artifacts.yml`
- `tests/fixtures/bitbucket-pipes-services-artifacts.yml`

Operator meaning: parser support should now be described as measured support
plus typed gaps. Avoid broad "full platform support" claims unless a corpus
report proves them.

### 6. Proof ledger and adoption claim ceiling

The branch added `docs/proof/v1.2.0-rc.1/` with receipt templates and a surface
ledger.

Key files:

- `docs/proof/v1.2.0-rc.1/README.md`
- `docs/proof/v1.2.0-rc.1/surface-ledger.md`
- `docs/proof/v1.2.0-rc.1/receipt-template.md`
- `docs/proof/v1.2.0-rc.1/templates/*.md`
- `docs/rc/v1.2.0/adoption-proof-audit.md`
- `docs/rc/v1.2.0/marketplace-proof-state.md`

Important boundary: templates and ledger rows are not proof. A surface is only
proven when a completed receipt records command/run evidence, source commit,
timestamp, operator, outcome, and residual risk.

## Verification Already Run Before Merge

The release branch was verified before it merged to `main` with:

- `python -B -m pytest` - 67 passed.
- `cargo test --workspace` - passed.
- `git diff --check` - passed.
- targeted `rustfmt --edition 2021 --check ...` - passed.
- `python scripts/doc_truth_scan.py --format json` - passed, 232 files, 0 issues.
- `python scripts/release_harness.py check --tag v1.2.0-rc.1` - passed for the
  RC lane.

Residual verification boundary:

- ADR 0020 full conformance was not complete; pending slots remain stable
  promotion blockers.
- Stable `v1.2.0` was not published and should not be treated as ready.
- Release proof receipts under `docs/proof/v1.2.0-rc.1/` are templates or
  planned rows until a tag workflow or equivalent evidence fills them.

## What Is Next

### Immediate hygiene

1. Decide what to do with untracked `.cordance/` and
   `pai-axiom-project-harness-target.json`.
2. Do not commit those files accidentally as part of taudit unless Cordance
   ownership and root-target policy are explicit.
3. Re-run focused checks after any handover or docs edits:
   - `git diff --check`
   - `python scripts/doc_truth_scan.py --format json`

### RC tag readiness

Before tagging or publishing `v1.2.0-rc.1`, refresh evidence for:

- `python scripts/release_harness.py check --tag v1.2.0-rc.1`
- `python scripts/check-crates-publish-metadata.py --expected-release-version 1.2.0-rc.1`
- `python scripts/conformance_harness.py --root . --format json`
- changelog review for the `Detection delta (read first)` contract;
- proof ledger review under `docs/proof/v1.2.0-rc.1/`;
- release workflow semantics: prerelease must not become GitHub Latest.

If conformance still reports pending checks, the RC may still be possible only
if release notes say exactly what is pending. Stable promotion remains blocked.

### Code-complete follow-up lanes

Use `docs/rc/v1.2.0/code-complete-lanes.md` as the queue. Highest-leverage next
work:

1. Replace ADR 0020 conformance placeholders with real current-profile,
   schema, generated-fixture, SARIF, CloudEvents, terminal, suppression,
   baseline, exit-code, and reference-consumer checks.
2. Finish the public contract boundary matrix and make schemas/examples fail on
   drift.
3. Expand the corpus manifest and runner into real corpus evidence, not just
   fixture-level checks.
4. Complete parser-provider lanes one provider at a time, keeping write scopes
   disjoint.
5. Promote ordered evidence from model and builder into report/sink projections
   without exposing internal witness or disclosure-only fields.
6. Fill proof receipts only after release assets, crates.io/docs.rs, GitHub
   Action, Azure DevOps, VS Code, or marketplace evidence actually exists.

### Stable promotion gates

Stable `v1.2.0` requires a separate closeout:

- one-week semantic soak after the latest RC;
- no new P0/P1 public-contract findings;
- public corpus dogfood pass;
- scheduled fuzz clean during soak;
- maintainer dogfood report;
- release trust receipts for assets, checksums, SBOMs, attestations, crates.io,
  and docs.rs;
- `cargo semver-checks check-release --workspace --all-features`;
- no semantic payload changes after the final RC that would require another RC.

## Known Risks

- Some RC docs were written as planning/control docs. Do not quote them as proof
  of implemented behavior unless the corresponding code, test, and receipt now
  exist.
- The conformance harness was intentionally skeletal in places. A passing
  release harness alone is not stable-release evidence.
- Marketplace and hosted adoption surfaces need receipts before operator docs
  can claim they are live, installable, or hosted-smoked.
- Parser completeness must stay measured. Typed gaps are honest; broad platform
  slogans are not.
- Cortex and Cordance did not inspect `taudit` directly through Cordance MCP in
  the final preflight. Treat their data as unavailable for taudit release proof
  unless rerun against an allowed target and recorded as candidate-only evidence.

## Resume Prompt

Recommended next prompt for an implementation agent:

```text
Work from main in C:\Users\0ryant\prj\taudit. Read HANDOVER.md and
docs/rc/v1.2.0/code-complete-lanes.md first. Pick one lane with a disjoint
write scope, implement it against ADRs 0009-0024, and report changed paths,
verification, residual risk, and the next dependency unblocked. Do not treat
proof templates as receipts, and do not commit untracked Cordance artifacts
without explicit operator approval.
```
