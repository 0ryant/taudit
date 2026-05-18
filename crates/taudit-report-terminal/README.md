# taudit-report-terminal

Terminal report adapter for taudit authority findings.

This crate renders graph-backed taudit findings for humans in shells and CI logs. It is the default user-facing report sink behind `taudit scan` terminal output, including severity labels, authority paths, completeness annotations, partial-graph context, and control-character sanitization at the terminal render boundary.

## What It Provides

- `TerminalReport`, a `ReportSink` implementation for human-readable output.
- `verbose` mode for inline partial-graph and node detail.
- `strip_control_chars` to remove terminal escape and Unicode steering payloads from attacker-controlled strings.
- Run banner and summary helpers for CLI composition.

## Install

```toml
[dependencies]
taudit-core = "3"
taudit-report-terminal = "3"
```

## Basic Use

```rust
use taudit_core::ports::ReportSink;
use taudit_report_terminal::TerminalReport;

let mut out = Vec::new();
TerminalReport { verbose: false }.emit(&mut out, &graph, &findings)?;
```

## When To Use It

- You are embedding taudit in a CLI and want the same terminal output as the product binary.
- You need readable CI log output for GitHub Actions, Azure DevOps, GitLab CI, or Bitbucket Pipelines.
- You need a render-boundary sanitizer for strings sourced from untrusted pipeline YAML.

## Related Docs

- Product README: <https://github.com/0ryant/taudit>
- CLI usage: <https://github.com/0ryant/taudit/blob/main/USERGUIDE.md>
- Golden paths: <https://github.com/0ryant/taudit/blob/main/docs/golden-paths.md>
