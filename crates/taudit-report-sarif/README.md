# taudit-report-sarif

SARIF 2.1.0 report adapter for graph-backed taudit findings.

This crate renders taudit findings into SARIF for GitHub Code Scanning, Azure DevOps code scanning consumers, IDEs, security dashboards, and other SARIF-aware tooling. It preserves taudit rule IDs, severity mapping, stable fingerprints, finding group IDs, and sanitized Markdown boundaries for attacker-controlled pipeline content.

## What It Emits

- A SARIF 2.1.0 JSON document with one `runs[0]` entry.
- Built-in taudit rule metadata plus optional custom-rule metadata.
- Per-result `ruleId`, levels, locations, message text, fingerprints, and taudit-specific properties.
- Markdown escaping for attacker-controlled strings before SARIF render boundaries.

## Install

```toml
[dependencies]
taudit-core = "3"
taudit-report-sarif = "3"
```

## Basic Use

```rust
use taudit_core::ports::ReportSink;
use taudit_report_sarif::SarifReportSink;

let mut out = Vec::new();
SarifReportSink.emit(&mut out, &graph, &findings)?;
```

## Multi-File SARIF

```rust
use taudit_report_sarif::SarifReportSink;

let mut out = Vec::new();
SarifReportSink.emit_multi(&mut out, &[(&graph_a, findings_a), (&graph_b, findings_b)])?;
```

Use `emit_multi_with_custom_rules` when custom YAML invariants must also appear in the SARIF `tool.driver.rules` array.

## Related Docs

- Product README: <https://github.com/0ryant/taudit>
- SARIF output docs: <https://github.com/0ryant/taudit#outputs>
- Rule catalogue: <https://github.com/0ryant/taudit/blob/main/docs/rules/index.md>
- Finding fingerprint contract: <https://github.com/0ryant/taudit/blob/main/docs/finding-fingerprint.md>
