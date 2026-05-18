# taudit-report-json

JSON report adapter for taudit authority graphs and findings.

This crate renders taudit analysis results as a versioned JSON document with the full authority graph, findings, severity summary, completeness gaps, stable fingerprints, suppression keys, and risk metadata. It is the right sink for dashboards, custom CI gates, SIEM importers, data warehouses, and API services that need structured CI/CD security output.

## Output Contract

The scan report uses:

- `schema_version: "1.0.0"`
- `schema_uri: "https://taudit.dev/schemas/taudit-report.schema.json"`
- `graph`: the full authority graph
- `findings`: findings with `rule_id`, fingerprint, suppression key, and inherited finding fields
- `summary`: counts, worst severity, graph completeness, and protected resource categories

The crate also exposes `GraphExport` for standalone `taudit graph --format json` output.

## Install

```toml
[dependencies]
taudit-core = "3"
taudit-report-json = "3"
```

## Basic Use

```rust
use taudit_core::ports::ReportSink;
use taudit_report_json::JsonReportSink;

let mut out = Vec::new();
JsonReportSink.emit(&mut out, &graph, &findings)?;
```

## When To Use It

- You need machine-readable taudit output for automation.
- You want the full graph and findings in one document.
- You need stable fingerprints for deduplication, suppression, or trend analysis.
- You are building an integration that does not want SARIF or CloudEvents semantics.

## Related Docs

- Product README: <https://github.com/0ryant/taudit>
- JSON report schema: <https://github.com/0ryant/taudit/blob/main/contracts/schemas/taudit-report.schema.json>
- Authority graph schema: <https://github.com/0ryant/taudit/blob/main/schemas/authority-graph.v1.json>
- Finding fingerprint contract: <https://github.com/0ryant/taudit/blob/main/docs/finding-fingerprint.md>
