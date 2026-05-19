# ADR 0020 Conformance Harness

This document records the current ADR 0020 output conformance harness for
`v1.2.0-rc.1`. The harness is now a release gate, not a placeholder inventory.
It validates checked-in contract examples, generated CLI artifacts, current
profile receipts, cross-sink parity, reference consumers, and Rust contract
tests from the checked-out repository.

## Command

Run from the repository root:

```sh
python scripts/conformance_harness.py --root . --format json
```

`--format text` is available for humans. `--skip-generated` exists only for
fast unit tests of the harness itself; release checks must run generated checks.

The JSON output is deterministic for a given repository state and contains:

- `harness`: `adr-0020-output-conformance`;
- `status`: `pass`, `fail`, or `incomplete`;
- `full_conformance`: `true` only when generated checks ran and every gate
  passed;
- `generated_checks`: whether CLI-generated artifacts were produced and
  validated;
- `counts`: pass/fail/pending totals;
- `checks`: ordered check records with `id`, `kind`, `status`, `path`, and
  `message`.

The process exits `0` for pass, `3` for incomplete, and `1` for a failed
implemented check. Release tooling treats `incomplete` as not release-ready for
the RC tag and not stable-release-ready for the stable tag.

## Implemented Checks

The harness runs local-only checks. It does not use network access.

- Required schema, example, and fixture path presence.
- JSON parsing for every checked-in `contracts/examples/*.json` file.
- Current-output profile checks for checked-in report JSON and CloudEvents
  examples.
- Reference consumer coverage for report and CloudEvents identity fields.
- Generated CLI report JSON, SARIF, and CloudEvents fixtures from
  `tests/fixtures/over-privileged.yml`.
- Current-output profile checks across the generated JSON, SARIF, and
  CloudEvents artifacts.
- Evidence parity across generated JSON, SARIF, and CloudEvents artifacts.
- Generated exploit graph JSON and current-profile validation.
- Generated baseline files and baseline current-profile validation.
- Terminal `--no-color --verbose` identity and triage rendering checks.
- Rust contract tests for suppression/baseline exit semantics, cross-sink
  identity, and hostile rendering.

## Ordered Evidence Boundary

`ordered_authority_evidence` is explicitly deferred for this RC unless and
until production JSON, SARIF, CloudEvents, exploit graph, and terminal verbose
projection all emit the public object. The harness accepts only the documented
absence of that one field as a scoped RC deferral. Any other current-profile or
parity pending item is a release-blocking failure.

The deferral must be named in `CHANGELOG.md`,
`current-output-profile.md`, `evidence-parity-harness.md`, and
`operator-evidence-output-guide.md`. If any of those files stop recording the
boundary, the conformance harness fails.

## Not Claimed

This harness proves the local checked-out artifacts it generates and inspects.
It does not prove a GitHub release exists, crates.io publication happened, SBOM
assets were uploaded, attestations verify, or docs.rs rendered. Those receipts
remain under `docs/proof/v1.2.0-rc.1/` and the release harness.

## Next Dependency Unblocked

QA-08 and L1 can use the ADR 0020 command as a hard RC release gate. L4/L5 can
ship `ordered_authority_evidence` later by replacing the documented deferral
with positive generated fixtures and parity checks across every promised sink.
