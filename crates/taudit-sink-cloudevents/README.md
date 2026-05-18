# taudit-sink-cloudevents

CloudEvents JSONL sink for taudit graph-derived findings.

This crate emits one CloudEvents 1.0 JSON object per taudit finding, newline-delimited for streaming into event buses, SIEM pipelines, data lakes, incident automation, and cross-tool correlation workflows. It preserves taudit rule IDs, fingerprints, suppression keys, pipeline IDs, scan-run IDs, repository provenance, and graph completeness metadata.

## Output Shape

Each emitted line is a CloudEvents 1.0 event with taudit extension attributes, including:

- `tauditfindingfingerprint`
- `tauditsuppressionkey`
- `tauditruleid`
- `tauditcompleteness`
- `tauditpipelineid`
- `tauditscanrunid`
- `correlationid`
- provenance fields for repository, producer, and version

## Install

```toml
[dependencies]
taudit-core = "3"
taudit-sink-cloudevents = "3"
```

## Basic Use

```rust
use taudit_core::ports::ReportSink;
use taudit_sink_cloudevents::CloudEventsJsonlSink;

let mut out = Vec::new();
CloudEventsJsonlSink::new().emit(&mut out, &graph, &findings)?;
```

## Correlation IDs

Use explicit IDs when a larger automation flow needs stable joins across multiple scans.

```rust
use taudit_sink_cloudevents::CloudEventsJsonlSink;

let sink = CloudEventsJsonlSink::with_ids(
    Some("operator-flow-123".into()),
    Some("scan-run-456".into()),
);
```

If not supplied, the sink checks `TAUDIT_CORRELATION_ID` and `TAUDIT_SCAN_RUN_ID`, then mints UUIDs.

## Related Docs

- Product README: <https://github.com/0ryant/taudit>
- CloudEvents schema: <https://github.com/0ryant/taudit/blob/main/contracts/schemas/taudit-cloudevent-finding-v1.schema.json>
- Finding fingerprint contract: <https://github.com/0ryant/taudit/blob/main/docs/finding-fingerprint.md>
