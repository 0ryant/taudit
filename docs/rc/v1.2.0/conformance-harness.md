# ADR 0020 Conformance Harness Skeleton

This document records the L5-11 offline skeleton for
`v1.2.0-rc.1`. It creates the local command shape required by ADR 0020 without
claiming full output conformance.

## Command

Run from the repository root:

```sh
python scripts/conformance_harness.py --root . --format json
```

`--format text` is available for humans. The JSON output is deterministic for a
given repository state and contains:

- `status`: `pass` when all checks are implemented and clean, `incomplete`
  when placeholder checks remain, otherwise `fail`;
- `full_conformance`: always `false` in this skeleton;
- `counts`: implemented pass/fail counts plus pending placeholder count;
- `checks`: ordered check records with `id`, `kind`, `status`, `path`, and
  `message`.

The process exits `0` only for full pass, `3` while placeholder checks remain,
and `1` when an implemented check fails.

## Implemented Offline Checks

The skeleton currently checks only local files and never uses network access.

- Presence of configured schema and example paths under `contracts/` and
  `schemas/`.
- Discovery of checked-in `contracts/examples/*.json`.
- JSON parsing for every discovered contract example.

Failure output names the violated path, which gives ADR 0020 a stable local
starting point before generated fixture and schema-validation work lands.

## Pending Slots

The harness deliberately includes pending placeholders for current-profile and
parity work:

- report JSON;
- CloudEvents;
- SARIF;
- exploit graph JSON;
- suppressions and baselines;
- terminal verbose output;
- identity parity;
- evidence parity;
- reference consumers;
- exit-code matrix.

These placeholders are not release evidence. They preserve the ADR 0020 surface
area so L2, L5, QA, and L1 can wire concrete checks into known slots.

## Not Yet Claimed

This skeleton does not validate JSON Schema, generate CLI fixtures, compare
cross-sink identity, run reference consumers, validate SARIF, check current
profile field presence, or enforce the exit-code matrix. `full_conformance:
false` must remain until those checks are implemented and verified.

## Next Dependency Unblocked

QA and L1 can now reference a local conformance command while L2/L5 replace the
placeholder slots with generated fixture, schema, current-profile, and parity
checks.
