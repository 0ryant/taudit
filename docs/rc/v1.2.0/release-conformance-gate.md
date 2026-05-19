# Release Conformance Gate

This note records the L1-06 release-harness integration for the ADR 0020
conformance harness.

## Harness Command

`scripts/release_harness.py check` now invokes the checked-out working tree
command:

```sh
python scripts/conformance_harness.py --root <repo> --format json
```

Historical `--source-ref` checks cannot run this gate because the conformance
harness validates the current checkout. Use `--skip-conformance` only for
historical notes or release backfill.

## Release Interpretation

| Harness result | Release-harness interpretation |
| --- | --- |
| exit `0`, `status: pass`, `full_conformance: true` | RC and stable release checks may continue. |
| exit `3`, `status: incomplete`, `full_conformance: false` | RC checks fail as not release-ready; stable release checks fail as not stable-release-ready. |
| exit `1`, invalid JSON, `status: fail`, or mismatched status/exit/full-conformance fields | RC and stable release checks fail. |

The ADR 0020 harness is now a hard RC gate. A documented
`ordered_authority_evidence` deferral may be mapped inside the harness only
when every other implemented check passes and the JSON summary reports
`status: pass`, zero pending checks, and `full_conformance: true`.

## Scope Boundary

This lane consumes the checked-out working tree. It does not validate
historical source refs, GitHub release assets, crates.io publication, SBOMs, or
attestations. Those remain separate release and proof-ledger receipts.

## Next Dependency Unblocked

L1-07 and QA-08 can now use the same ADR 0020 pass requirement for RC tag
readiness and stable promotion. Stable promotion still has additional soak,
corpus, fuzz, and closeout receipt gates.
