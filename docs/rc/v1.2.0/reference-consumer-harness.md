# Reference Consumer Harness Skeleton

Status: L2-10 compatibility harness skeleton for `v1.2.0-rc.1`.

This harness is a small downstream-compatibility probe. It is not a full output
conformance harness and it is not evidence that every downstream language,
runtime, JSON parser, SIEM, or SDK can consume every taudit output.

## Purpose

The skeleton answers one narrow question:

> Can an independent, stdlib-only Python consumer read checked-in taudit report
> JSON and CloudEvents examples, extract known completeness and identity fields,
> and ignore additive metadata it does not understand?

The reference consumer lives at
`examples/consumers/python/report_identity_summary.py`.

It deliberately does not import taudit Rust code, generated schemas, or external
Python packages. That keeps the probe close to a conservative downstream
consumer: parse JSON, select known fields, leave unknown fields opaque.

## Covered Inputs

- Report JSON examples under `contracts/examples/*-report.json`.
- CloudEvents finding examples under
  `contracts/examples/*.cloudevent.json`.
- JSONL files containing one CloudEvent JSON object per line.
- Temp test fixtures with future root fields, metadata keys, CloudEvents
  extension attributes, and finding/data fields.

## Reported Fields

For report JSON, the consumer reports:

- `schema_version` and optional `schema_uri`;
- `graph.source.file`;
- `graph.completeness`;
- `summary.completeness`;
- `summary.total_findings`;
- the first finding's `severity`, `category`, `rule_id`, `fingerprint`,
  `suppression_key`, `finding_group_id`, and `source` when present.

For CloudEvents, the consumer reports:

- CloudEvents envelope fields: `specversion`, `id`, `type`, and `subject`;
- completeness extension: `tauditcompleteness`;
- finding payload `severity` and `category`;
- identity and scan provenance extensions: `tauditruleid`,
  `tauditfindingfingerprint`, `tauditsuppressionkey`,
  `tauditfindinggroup`, `tauditpipelineid`, `tauditscanrunid`,
  `correlationid`, and `tauditplatform` when present;
- event provenance: `provenancerepo`, `provenanceproducer`,
  `provenanceversion`, and `provenancekind`.

Missing optional identity fields are reported as JSON `null`. Unknown metadata,
unknown extension attributes, and unknown finding fields are ignored.

## Usage

```sh
python3 examples/consumers/python/report_identity_summary.py \
  contracts/examples/clean-report.json \
  contracts/examples/over-privileged-finding.cloudevent.json
```

Each input document emits one compact JSON summary line. The output is intended
for smoke tests and downstream examples, not as a stable public schema of its
own.

## Verification

The focused harness test is:

```sh
pytest tests/test_reference_consumers.py
```

The test covers checked-in report and CloudEvents examples plus temp mutated
examples with unknown additive fields.

## Boundary

This skeleton complements, but does not replace:

- compatibility schema validation;
- current-output profile checks;
- cross-sink equality tests for JSON, SARIF, and CloudEvents identity fields;
- language-specific SDK or SIEM integration tests.

Treat a pass here as evidence that one conservative Python consumer can tolerate
additive fields while reading known compatibility fields. Do not treat it as a
release-wide guarantee for all downstream consumers.

## Next Dependency Unblocked

L2/L5/QA lanes can now wire this skeleton into broader conformance work or use
it as a reference shape while building ADR 0020 current-profile checks.
