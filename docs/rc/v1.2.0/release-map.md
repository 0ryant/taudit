# v1.2.0-rc.1 Release Map

Release candidate name: `v1.2.0-rc.1: Authority Evidence Platform`.

This is the Wave 1 release-coordination map for L1. It shapes the RC lane; it
does not publish the release, edit the changelog, bump manifests, or claim any
unmerged behavior.

## Sources

- [ADR 0009](../../adr/0009-v1-2-release-contract-and-semver-map.md) - accepted
  release contract and SemVer map.
- [Code-complete lanes](code-complete-lanes.md) - L1-01 through L1-08,
  QA-08, and dependency ordering.
- [Release gates and SemVer workstream](workstreams/release-gates-semver.md) -
  prerelease lane discipline, changelog contract, and stable promotion rule.
- [Charter](charter.md) - selected RC direction and release promise.

## Current Baseline

Observed before this map was written:

- CLI product crate `taudit` is still `1.1.5`.
- `taudit-api` is still `0.4.1`.
- implementation crates are still on `3.0.1`.
- `CHANGELOG.md` has no `## v1.2.0-rc.1` section yet.
- `docs/RELEASE_GATES.md` still contains current-cycle language for
  `1.1.0-rc.1`; L1-07 remains pending.

## Version Map

| Surface | Ready decision | Pending decision | Gate |
| --- | --- | --- | --- |
| CLI product crate `taudit` | RC product tag is `v1.2.0-rc.1`; CLI manifest must become `1.2.0-rc.1` before tag. | Manifest and lockfile bump are not done in this wave. | L1-02, L1-03, ADR 0009 |
| `taudit-api` | Current baseline is `0.4.1`. It may stay there only if no public Rust or wire-contract change ships. | L2 must decide stay `0.4.1`, bump prerelease minor, or defer promotion. | L1-02, L1-04, L2-01, L2-02 |
| implementation crates | Current baseline is `3.0.1` across core, parsers, reporters, and CloudEvents sink. | If any implementation crate changes or published Rust API changes, L1 must bump intentionally and coherently. | L1-02, L1-04 |
| schemas | Existing schema files are not yet an RC readiness claim. | L2/L5 must prove graph JSON, scan JSON, SARIF, CloudEvents, exploit graph, baselines, suppressions, and examples. | L2-01, L2-06, L2-07, L2-08, ADR 0020 |
| output identity | `rule_id`, `fingerprint`, `suppression_key`, and `finding_group_id` are the RC identity surface to map. | Identity parity across JSON, SARIF, CloudEvents, and terminal output is pending. Do not claim `finding_group_id` readiness yet. | L2-04, L5-01 |
| suppressions | Existing stable output includes `suppression_key`; that is baseline evidence, not the full RC suppression claim. | Suppression, baseline, and exit-code semantics remain pending until ADR 0018/L5 gates pass. | L5-07, L5-08, ADR 0018 |
| release assets | Stable trust surface is the target: archives, checksums, SPDX and CycloneDX SBOMs, GitHub attestations, crates.io, and docs.rs. | RC receipts do not exist before the tag workflow. Record them under `docs/proof/v1.2.0-rc.1/` only after they exist. | L1-08, L6-05, ADR 0021 |

## Detection delta (read first)

This checklist is the future changelog input for L1-01. Unknowns are pending,
not claimed.

- [ ] PENDING - finding-count direction versus `v1.1.5` and any previous
  `v1.2.0` RC is not known yet.
- [ ] PENDING - false-positive movement is not known yet.
- [ ] PENDING - false-negative movement is not known yet.
- [ ] PENDING - parser completeness and real-input corpus deltas are not known
  yet.
- [ ] PENDING - schema and wire-contract impact is not known yet.
- [ ] PENDING - CLI flag, command, and exit-code impact is not known yet.
- [ ] PENDING - output identity impact for `rule_id`, `fingerprint`,
  `suppression_key`, and `finding_group_id` is not proven yet.
- [ ] PENDING - suppression and baseline migration impact is not known yet.
- [ ] PENDING - crate-version impact is partially shaped but not final:
  `taudit` target is `1.2.0-rc.1`; `taudit-api` and implementation crate lines
  depend on L2/L5 behavior.
- [ ] PENDING - release assets, checksums, SBOMs, attestations, crates.io, and
  docs.rs receipts do not exist before the tag workflow.

## L1 Map

| ID | Status | Release-map decision |
| --- | --- | --- |
| [L1-01](code-complete-lanes.md#l1-release-coordination) | PENDING | Changelog must add `## v1.2.0-rc.1` and start with `Detection delta (read first)`, but behavior delta is not known yet. |
| [L1-02](code-complete-lanes.md#l1-release-coordination) | PARTIAL | CLI target is ready from ADR 0009. `taudit-api` and implementation crate decisions remain pending on L2/L5. |
| [L1-03](code-complete-lanes.md#l1-release-coordination) | PENDING | CLI is currently `1.1.5`; bump to `1.2.0-rc.1` later, then update lockfile if needed. |
| [L1-04](code-complete-lanes.md#l1-release-coordination) | PENDING | Keep or bump API/implementation crates only after public Rust and wire-contract impact is known. |
| [L1-05](code-complete-lanes.md#l1-release-coordination) | COMPLETE | Release harness tests now cover prerelease creation and existing-prerelease normalization with `--latest=false`; live GitHub validation remains out of scope for offline tests. |
| [L1-06](code-complete-lanes.md#l1-release-coordination) | PENDING | ADR 0020 defines the conformance harness gate; local recipe and CI/release wiring remain pending. |
| [L1-07](code-complete-lanes.md#l1-release-coordination) | PENDING | `docs/RELEASE_GATES.md` still needs an RC-tag versus stable-promotion refresh for the v1.2 cycle. |
| [L1-08](code-complete-lanes.md#l1-release-coordination) | PENDING | Proof receipts are post-tag-workflow evidence and must not be prefilled. |

## Acceptance Gates

The RC is tag-ready only when these gates are satisfied with fresh evidence:

| Gate | Required evidence | Status now |
| --- | --- | --- |
| Release harness | `python scripts/release_harness.py check --tag v1.2.0-rc.1` exits zero after CLI/changelog alignment. | PENDING |
| Publish metadata | `python scripts/check-crates-publish-metadata.py --expected-release-version 1.2.0-rc.1` exits zero after version-map decisions. | PENDING |
| Conformance harness | ADR 0020 local command or `just` recipe exists and CI/release path invokes it. | PENDING |
| Changelog | `CHANGELOG.md` contains `## v1.2.0-rc.1`, detection delta first, migration notes, and crate-version map. | PENDING |
| Proof receipts | Release asset, checksum, SBOM, attestation, crates.io, and docs.rs receipts exist under `docs/proof/v1.2.0-rc.1/`. | PENDING |

## Dependency Links

- ADR blocker: [ADR 0009](../../adr/0009-v1-2-release-contract-and-semver-map.md).
- Code-complete lane dependencies: [L1-01](code-complete-lanes.md#l1-release-coordination),
  [L1-02](code-complete-lanes.md#l1-release-coordination),
  [L1-03](code-complete-lanes.md#l1-release-coordination),
  [L1-04](code-complete-lanes.md#l1-release-coordination),
  [L1-05](code-complete-lanes.md#l1-release-coordination),
  [L1-06](code-complete-lanes.md#l1-release-coordination),
  [L1-07](code-complete-lanes.md#l1-release-coordination),
  [L1-08](code-complete-lanes.md#l1-release-coordination).
- Release readiness join: [QA-08](code-complete-lanes.md#qa-and-resilience-gates).
- Proof receipt contract: [ADR 0021](../../adr/0021-operator-proof-receipt-contract.md).
- Conformance harness contract: [ADR 0020](../../adr/0020-output-conformance-harness-and-rc-gate.md).

## Next Dependency Unblocked

This map unblocks L1-02 shaping and lets L2/L5 return concrete version-impact
inputs without requiring a changelog edit during Wave 1.

## Residual Risk

- Concurrent workers may change L2/L5/L6 facts after this map. Re-read the
  source lanes before using this as tag evidence.
- This file records planned gates and observed baselines only. It is not proof
  that the RC payload, release assets, or marketplace/operator surfaces are
  ready.
