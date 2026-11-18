# Next release candidate: working TODO

Status: **proposed plan, not a tag authorization**. Snapshot: 2026-10-04. The
latest published release is `v1.3.3`; `main` is at `e56809c`, and this planning
checkout is `ed1102b` (`docs/corpus-rule-research`). No next-RC version or
payload has been ratified. The old [v1.2.0 RC plan](v1.2.0/README.md) is
historical: that candidate was never tagged or published
([CHANGELOG](../../CHANGELOG.md)).

An item is complete only with a link to the commit, command result, corpus
report, installed-artifact test, or external receipt that proves it. Proposed
research tasks below are not all automatic tag blockers: the first section must
decide which enter the candidate. Source-local tests cannot prove a published
channel or an installed binary.

## 1. Freeze the release contract

- [ ] Choose the product tag and write a short RC charter with the exact payload,
  supported platforms, public contract changes, and explicit deferrals. An
  additive-detection `v1.4.0-rc.1` is plausible under the
  [release strategy](../release-strategy.md), but has not been approved.
- [ ] Decide whether the [fingerprint path defect](../research/fingerprint-path-instability-2026-09.md)
  belongs in this candidate or its **own** RC. [PR #74](https://github.com/0ryant/taudit/pull/74)
  explicitly proposes a separate RC. If included, settle its SemVer treatment
  first: re-keying baselines/suppressions is a migration, and the current
  [release gates](../RELEASE_GATES.md) reserve fingerprint-algorithm breaks for
  a major version.
- [ ] Mark each of the 17 items in the [research RC scope](../research/corpus-rule-research-2026-09.md)
  **in / later / rejected**, with an owner, dependency, acceptance fixture, and
  expected finding delta. The smallest current payload is the two fixes in
  PR #74. Tier 0/Tier 1 are prioritized additions; Tier 3 is proposed new
  detection. None enters the tag solely because it appears in the research.
- [ ] Decide which distribution channels will carry the prerelease. GitHub
  prerelease and crates.io prerelease are the repository's existing RC lane;
  apt, Homebrew, Chocolatey, and Marketplace pins need explicit decisions.
- [ ] Inventory the exact release SHA, dirty state, worktrees, Rust toolchain,
  feature/target matrix, all manifests and lockfiles, and intended asset hashes
  before the tag. Do not reuse `v1.3.3` proofs for changed bytes.

## 2. Reconcile work already in flight

- [ ] Review and verify [PR #74](https://github.com/0ryant/taudit/pull/74):
  mutable remote-script URLs on all four platforms and credential-bearing Git
  remote URLs across interpolation syntaxes. Run its fixtures and measured
  before/after corpus cases on the final candidate. These fixes are already
  implemented on the PR branch, not merged into `main`.
- [ ] Close PR #74 review defects before integration: require an actual variable
  marker so literal usernames such as `patrick` do not look like credential
  variables; redact URL userinfo in findings; bind the fetched URL to the
  command piped into a shell; test multiple URLs on one line; and make
  version/tag mutability claims precise. Add positive and negative fixtures for
  each case, then update rule pages, index, and SARIF rule metadata.
- [ ] Merge or otherwise integrate #74, then update
  [PR #75](https://github.com/0ryant/taudit/pull/75) so the research report does
  not accidentally merge/count #74's commits twice. Both PRs currently lack
  check-run evidence on their head commits.
- [ ] Triage the 12 open Dependabot PRs against the candidate's lockfile,
  advisories, compatibility, and test matrix. Include only verified changes;
  record the rest as deferred.
- [ ] Triage preserved, months-old MCP/marketplace/backup branches against
  current `main`; selectively rework useful commits or record deferral. Do not
  merge stale branches wholesale.

## 3. Candidate detection and parser backlog

The numbering below follows the [September corpus report](../research/corpus-rule-research-2026-09.md).
For every included item: add positive and negative fixtures, check cross-platform
registration, measure false positives and finding/severity/identity deltas on a
frozen corpus, and update its rule documentation and changelog.

### Tier 0: correctness defects (recommended before tag)

- [ ] **0.1 Bitbucket self-hosted runners:** parse sequence-form step `runs-on`
  and `options.runs-on`; test PR reachability and shell-runner labels. Measure
  findings lost when `META_SELF_HOSTED` re-enables existing suppressors.
- [ ] **0.2 Bitbucket imports:** an import-only pipeline must emit a structural
  completeness gap, not a zero-node `complete` all-clear.
- [ ] **0.3 Bitbucket deployment approval:** correct the protected-deployment
  metadata inversion and measure severity changes before enabling 1.4.

### Tier 1: existing-rule precision and coverage (recommended first cut)

- [ ] **1.1 Remote pipe-to-shell:** recognize the listed additional
  interpreters and `sudo`/`env`/assignment wrappers, preserving URL mutability
  checks and negative controls.
- [ ] **1.2 GitLab mutable includes:** cover `component: @ref`, mutable
  `project:` refs, and legacy/raw URL forms; exclude immutable refs and the
  documented bare-major case.
- [ ] **1.3 GHA release trigger:** after 2.1, add `release` to risky triggers.
  Test protected-environment cases so the known 3/16 false positives are not
  shipped.
- [ ] **1.4 Bitbucket deploy branch gate:** after 0.3, stamp the pipeline
  section and extend the existing protected-branch rule to Bitbucket.

### Tier 2: parser fields (include when their dependent detection ships)

- [ ] **2.1 GHA:** parse job `environment:` into approval metadata before 1.3.
- [ ] **2.2 GitLab:** mint Secret nodes for credential-shaped variables used
  only in `script:`; measure effects on 3.1/3.3 and require it for the GitLab
  half of 3.4.
- [ ] **2.3 ADO:** represent pipeline/job-level `container:` image and options;
  verify existing floating-image and related rules can consume the nodes.
- [ ] **2.4 ADO:** stamp `dependsOn`; required for 3.5.

### Tier 3: new detection proposals (scope decision required)

- [ ] **3.1 Credential in argv:** shared helper and four platform registrations;
  keep credential-name, ephemeral-token, stdin, and file-form exclusions.
- [ ] **3.2 Disabled integrity verification:** token match with the report's
  three guards and negative controls.
- [ ] **3.3 Fetch to file then execute:** bind download target to later
  execution within the same job, including verification/immutable-source
  exclusions. Measure the currently unknown union of matched files.
- [ ] **3.4 Secret to durable file/store:** generalize materialization vocabulary,
  handle GHA tool-store allowlists, and wait for 2.2 for GitLab coverage.
- [ ] **3.5 ADO release gate detached from upstream success:** wait for 2.4 and
  test `dependsOn`/condition ordering.
- [ ] **3.6 Unpinned `npx`/global install with credential:** require same-job
  ordering and test benign install controls.

### Separate identity migration, only if selected

- [ ] Write an ADR for repository-root-relative, slash-normalized source paths;
  decide non-Git fallback and whether `graph.source.file` changes publicly.
- [ ] Implement and test equivalent identities for relative, `./`, absolute,
  different CWD, Windows and Linux invocation styles; cover fingerprints,
  `suppression_key`, `finding_group_id`, SARIF partial fingerprints, baselines,
  and graph output.
- [ ] Publish a one-time re-baseline/suppression migration and contract-version
  note. This changes every finding identity and should not ride silently with
  an additive detection cut.

## 4. Make the real-input evidence reproducible

- [ ] Freeze the public corpus by source commit and file digest; use one
  deterministic remeasurement script for every proposed discriminator. Resolve
  the 4,141/4,142 file and per-platform denominator disagreements and rerun
  Bitbucket measurements against one fixed binary.
- [ ] Independently adjudicate matched corpus files and false positives;
  proposer self-review alone is insufficient for precision claims. Re-measure
  the fetch-execute union and choose the argv severity from the threat model.
- [ ] Record a before/after finding inventory by platform, rule, severity,
  completeness, fingerprint, and baseline match for the exact release binary.
  Pay special attention to Tier 0.1's suppressions and Tier 0.3's severity rise.
- [ ] Triage all 27 parse failures as malformed/wrong-platform input or parser
  defect; add fixtures and fixes for real defects.
- [ ] Test a **non-empty** exploit graph for repeatability across processes and
  hosts/OSes; separately exercise concurrent audit-trail and receipt writes.
- [ ] Run the frozen corpus with a Linux **release** build. Extend to the
  packaged Windows/macOS binaries for release claims, and include representative
  enterprise multi-file/template shapes.
- [ ] Populate or explicitly replace the still-stubbed
  [dogfood corpus](../dogfood-corpus.md) with a pinned, documented selection
  of at least 100 real files and a schema-validating runner; link the run result
  from the RC proof. The September 4,141-file sweep is useful candidate
  evidence but is not yet that maintained gate.
- [ ] Exercise all four parser fuzz targets, including Bitbucket, during the RC
  soak. The current scheduled workflow covers GHA, ADO, and GitLab only.

## 5. Repair and run truthful pre-tag gates

- [ ] Fix the advertised high+ self-scan gate in
  [security.yml](../../.github/workflows/security.yml) and
  [quality-gate.sh](../../scripts/quality-gate.sh): `taudit scan` exits 0 even
  above `--severity-threshold`. Use a real `verify` policy gate, or label the
  scan advisory. Always test the candidate binary, not an arbitrary installed
  `taudit`. A direct candidate `verify` probe on current `main` reports 20
  existing high/critical violations, so regression-only enforcement needs a
  reviewed baseline; the current scan cannot honestly be called a hard gate.
- [ ] Make the local strict gate propagate `zizmor` failures instead of
  reporting PASS after a nonzero result. Test failure injection and the final
  PASS/FAIL/SKIP summary.
- [ ] Resolve publish topology: `taudit-mcp` is one of 12 publishable workspace
  crates counted by [metadata validation](../../scripts/check-crates-publish-metadata.py),
  but [release.yml](../../.github/workflows/release.yml) publishes only 11.
  `taudit-mcp@3.1.0` already exists on crates.io and has no change in this
  candidate, so this is a workflow consistency decision rather than an
  automatic blocker. Publish it in dependency order when changed or mark it
  non-publishable deliberately; test `cargo package`/registry dependency
  resolution for every crate that will be published.
- [ ] Refresh [release gates](../RELEASE_GATES.md), [RC index](README.md),
  [release operations](../release-operations.md), and current-state roadmap
  text to stop calling the never-tagged v1.2 RC current. Create the new
  candidate's proof ledger and acceptance checklist.
- [ ] Run a fresh, skip-free `just local-ci-strict` on the exact candidate SHA.
  The current Windows/WSL setup lacks some tools in the Bash environment, so
  install/resolve them before counting a strict run. Its PATH currently selects
  `taudit 1.1.5`, so resolve the candidate executable first. Record each of the 21
  checks and the source identity; old CI runs do not cover this candidate.
- [ ] Explicitly run/record workspace tests, fmt, Clippy, invariant schema
  `--check`, `cargo deny`, `cargo audit`, dependency/license/source checks,
  `doc_truth_scan.py`, and the output conformance harness. Current
  `ed1102b` conformance is 35 pass/0 fail/0 pending, but its scoped
  `ordered_authority_evidence` deferral must be reviewed against the new charter.
- [ ] Audit the four separate parser fuzz lockfiles and the Azure DevOps task's
  npm lockfile; root `Cargo.lock` checks alone do not cover them.
- [ ] Resolve every public-contract P0 and accepted RC-blocker P1. Recheck
  JSON, SARIF, CloudEvents, graph, exit-code and suppression/baseline contracts
  on current output, with the release binary and reference consumers.
- [ ] Decide the version map for CLI, `taudit-api`, and every published
  implementation/MCP crate; update path dependency constraints and lockfiles.
  **Hard blocker for the current payload:** the unmerged rules change
  `taudit-core` bytes while its manifest still says `3.1.0`, a version already
  published to crates.io. Bump core and the CLI's core dependency before a
  registry RC, or the installed CLI will not contain the new rules. Keep the
  changed core on a prerelease version so stable `^3.1.0` consumers cannot
  silently pick up unsoaked semantics; the current metadata checker requires a
  coherent implementation-crate version set.
  Put the exact detection delta, finding direction, FP/FN movement, output and
  fingerprint effects, migration notes, and version map in a named CHANGELOG
  section. The existing `Unreleased` entry already describes work since 1.3.3.
- [ ] Run `release_harness.py check --tag <tag>` and
  `check-crates-publish-metadata.py --expected-release-version <version>` on
  the final tree. Render and review the exact release notes and verify the
  workflow marks the tag prerelease, not Latest.

## 6. Cut, install, and close out the RC

- [ ] Tag the clean, verified commit and read back tag SHA, release object,
  prerelease flag, and absence of the Latest badge.
- [ ] Publish the intended crates to crates.io in dependency order; read back
  every package/version and docs.rs result. Check for a partially completed
  publication before retrying.
- [ ] Build the five target archives from the frozen source, plus per-asset
  SHA-256 and `SHA256SUMS`; verify downloaded archive hashes and every binary
  version/path after installation on its target platform.
- [ ] Produce and verify SPDX/CycloneDX SBOMs and provenance attestations for
  workflow-built bytes. If GitHub Actions remains unavailable, run the
  [local/Azure fallback](../release-operations.md), record runner/build SHA and
  byte hashes, and state explicitly which SBOM/attestation proofs are absent.
- [ ] For each prerelease channel actually selected: install-test signed apt
  index and `.deb`; sync and test Homebrew's four hashes; sync/test Chocolatey
  against the live Windows asset and wait for moderation before claiming
  installability. Do not move stable package-manager pins merely because the RC
  exists.
- [ ] Republish Azure DevOps task `0.1.11` for the bundled runtime security
  fixes after its pinned platform assets are live; verify Marketplace readback
  and an installed task smoke. Republish VS Code only if its source changed.
- [ ] Record release assets, checksums, SBOMs, attestations or explicit gaps,
  crates.io, docs.rs, installed-channel tests, and docs-link results in the new
  proof ledger. Close the RC only after receipts match the released bytes.

## After this RC / explicit deferrals

- [ ] Stable promotion is a separate decision: one-week soak from the latest
  RC, no new public-contract P0/P1, maintained public-corpus run, fuzz run,
  maintainer dogfood report, closeout receipts, and stable semver check under
  [release gates](../RELEASE_GATES.md). A new semantic fix starts a new RC.
- [ ] Keep ADO foreign-pipeline artifact intake, the unproven hardcoded
  credential-literal candidate, and a distinct Bitbucket PR/deployment rule
  outside this RC unless new evidence changes the
  [research recommendation](../research/corpus-rule-research-2026-09.md).
- [ ] Treat GitHub Marketplace Action publication and its still-open hosted
  smoke/proof chain as a separate adoption milestone unless the RC charter
  explicitly includes it ([TODOS](../../TODOS.md)).

## Evidence limits at this snapshot

- `v1.3.3` is the latest [published GitHub release](https://github.com/0ryant/taudit/releases/tag/v1.3.3).
  Nine later commits are on `main`; #74 and #75 are open PRs.
- The September [corpus report](../research/corpus-rule-research-2026-09.md)
  reports a Windows debug-build sweep, but also records denominator conflicts,
  27 untriaged parse failures, and unmeasured precision/baseline shifts.
- GitHub Actions has no fresh quality/security/release proof for #74/#75. The
  next candidate needs current local or hosted evidence tied to its exact SHA.
- This document is a plan and inventory. No tag, registry package, marketplace
  publication, or release artifact was created by writing it.
