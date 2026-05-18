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
| exit `3`, `status: incomplete`, `full_conformance: false` | RC checks may name the pending conformance state, but stable release checks fail as not stable-release-ready. |
| exit `1`, invalid JSON, `status: fail`, or mismatched status/exit/full-conformance fields | RC and stable release checks fail. |

The current ADR 0020 skeleton still exits `3` while placeholder checks remain.
That is useful RC evidence only as a named pending state; it is not stable
promotion evidence.

## Scope Boundary

This lane does not change `scripts/conformance_harness.py`, provider parsers,
core evidence code, output sinks, changelog, version files, or release workflow
YAML. It only teaches the release harness how to consume the conformance
summary and where to draw the stable-promotion boundary.

## Next Dependency Unblocked

L1-07 and QA-08 can now distinguish RC tag readiness from stable promotion in
release-gate docs and CI recipes while L2/L5 replace ADR 0020 placeholder
checks with full conformance assertions.
