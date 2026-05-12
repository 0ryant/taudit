# Seam Freeze v1 — Correlation, Provenance, Subject, Compliance Summary

**Status:** Draft for Tranche 1 (`docs/ecosystem-stage-board.md` § Tranches → Tranche 1).
**Owner repo for this draft:** CellOS.
**Participating repos:** CellOS, `tsafe`, `tencrypt`, `taudit`, `0ryant-shell`.

## 1. Goal

Freeze **one** stable set of correlation, provenance, subject, and compliance-summary
fields that every participating tool can reference without re-versioning. After freeze:

- A single field name (e.g. `correlationId`) means the same thing in every repo.
- Adding a participant to the seam is a doc/version bump in this file, not a contract
  change in any tool.
- Any tool can join two events emitted by two other tools using only seam fields,
  with no operator-supplied hint and no repo-local interpretation.

This is the **vocabulary** layer. Execution semantics, replay, and operator surfaces
land in Tranches 2–4.

## 2. CellOS field inventory

Today CellOS already emits most of the envelope. The fields below are what
participate in cross-tool correlation as of `crates/cellos-core/src/types.rs` and
`crates/cellos-core/src/events.rs` on `main`.

### 2.1 `Correlation` struct (cellos-core/src/types.rs)

Carried on `ExecutionCellSpec.correlation`, mirrored into CloudEvents `data` when
emitted.

| Field | JSON | Type | Stable? | Notes |
|------|------|------|---------|-------|
| `platform` | `platform` | `Option<String>` | stable | Free-form runner identity (`github-actions`, `azure-devops`, `0ryant-shell`, etc.). |
| `external_run_id` | `externalRunId` | `Option<String>` | stable | Workflow / job execution ID from the calling system. |
| `external_job_id` | `externalJobId` | `Option<String>` | stable | Logical job ID inside the calling system. |
| `tenant_id` | `tenantId` | `Option<String>` | stable | Operator-declared tenant string. No CellOS-side authority binding yet. |
| `labels` | `labels` | `Option<HashMap<String,String>>` | tentative | Untyped escape hatch; do **not** rely on specific keys across tools. |

### 2.2 `compliance_summary_data_v1` event (cellos-core/src/events.rs)

`dev.cellos.events.cell.compliance.v1.summary`, schema
`contracts/schemas/cell-compliance-summary-v1.schema.json`. The compliance receipt
participating tools should consume to attribute a run.

| Field | Type | Stable? | Notes |
|------|------|---------|-------|
| `cellId` | string | stable | CellOS-assigned per-run cell identifier. |
| `specId` | string | stable | Hash/identifier of the ExecutionCell spec. |
| `runId` | string (optional) | stable | Per-run execution ID emitted by supervisor. |
| `lifetimeTtlSeconds` | integer | stable | Declared TTL from spec. |
| `egressRuleCount` | integer | stable | Declared egress rule count. |
| `secretDeliveryMode` | string\|object | stable | One of `env`, `runtimeBroker`, `runtimeLeasedBroker`. |
| `policyPackId` / `policyPackVersion` / `policyBundleDigest` | string | stable | Policy attribution; absent when no pack declared. |
| `placement` | object | stable | Optional `poolId`, `kubernetesNamespace`, `queueName`. |
| `commandExitCode` | integer | stable | Subprocess exit code. |
| `correlation` | object | stable | Verbatim copy of §2.1 — joins compliance to caller's workflow. |

### 2.3 CloudEvents envelope fields used cross-tool

| Envelope field | Meaning here | Stable? |
|----------------|-------------|---------|
| `id` | CloudEvents v1 event ID, unique per emission. | stable |
| `source` | URI identifying emitter (`/cellos/supervisor/<host>`). | stable |
| `type` | `dev.cellos.events.cell.<phase>.v<n>.<verb>`. | stable per type/version |
| `subject` | `cell:<cellId>` today. **Tentative — see §4.** | tentative |
| `time` | RFC3339 UTC. | stable |

## 3. Gap table

What needs to land for the seam to close. Each row is a *receiver-side* expectation
that CellOS cannot satisfy alone.

| Gap | Producer must emit | Consumer expects | Tracking ticket | Status |
|-----|-------------------|-----------------|-----------------|--------|
| **G1 — broker correlation ID** | tsafe SecretBroker emits a broker-generated `correlationId` on every secret issuance / rotation / revoke event, with no operator hint required. | CellOS supervisor receives it via the broker socket protocol and stamps it onto the next `lifecycle.*` event for the cell that consumed (or was disrupted by) the secret. | SEC-16 (`docs/ROADMAP_JOBS.md`); L5-17 (this repo). | **Open** |
| **G2 — provenance chain on receipts** | tencrypt emits `provenance.parent` linking signed-export artifacts back to the originating `compliance.summary` event. | taudit can walk artifact → compliance.summary → spec → derivation token without operator-supplied joins. | Tranche 3 (export and receipt surfaces). | **Open** |
| **G3 — subject normalization** | All tools agree `subject` is a typed URN (`urn:cellos:cell:<cellId>`, `urn:tsafe:lease:<leaseId>`, etc.), not a free-form string. | `0ryant-shell` and `tedit` route by `subject` prefix instead of repo-local heuristics. | This freeze (§4 below). | **Open** |
| **G4 — compliance.summary cross-pointer** | `compliance_summary_data_v1` carries `provenanceEnvelope.parent` when the run was caused by a tsafe rotation event. | taudit can attribute a run failure to an upstream rotation without log archaeology. | Depends on G1. | **Open** |

## 4. Proposed additions

Minimum viable additions to close the seam. **Three new fields**, no new top-level
type yet — keeps the freeze narrow per the Tranche 1 stop condition.

| Name | Type | Where it lives | Producer | Consumers |
|------|------|----------------|----------|-----------|
| `correlationId` | `String` (URN form: `urn:<tool>:corr:<ulid>`) | New required field on `Correlation`. Generated by whichever tool first observes the work; copied verbatim by every downstream emitter. | First-touch tool (tsafe broker on secret issuance, CellOS supervisor on direct spec submission, 0ryant-shell on user invocation). | CellOS, taudit, tencrypt, 0ryant-shell. |
| `provenance.parent` | `Option<String>` (URN of parent event ID) | New nested object `provenance` on `Correlation` and on `compliance_summary_data_v1`. | Whoever caused the next event (tsafe → CellOS for rotation-driven rerun; tencrypt → CellOS for re-encrypted artifact replay). | taudit (graph build), tencrypt (chain of custody), CellOS (cause attribution in lifecycle events). |
| `subject` | `String` (URN: `urn:<tool>:<kind>:<id>`) | Typed wrapper over the existing CloudEvents `subject` field. Documented as required, not free-form. | Every emitter. | All consumers; routing key for 0ryant-shell and tedit. |

The `provenance` object stays a single struct (`{ parent: String, parentType: String }`)
rather than a full `ProvenanceEnvelope` type. We can promote it to a top-level type
in v2 if Tranche 3 (export receipts) demands more fields. **Resist** adding `chain:
Vec<String>`, `signedBy`, etc. in v1 — those belong to tencrypt's signed-export work.

### 4.1 Mapping to existing CellOS fields

- `correlationId` is **additive** to §2.1 and does not replace `externalRunId` /
  `externalJobId`. The latter remain caller-system-local; `correlationId` is the
  cross-tool join key.
- `provenance.parent` is **additive** to `compliance_summary_data_v1`. When absent
  (most runs today), nothing changes for consumers.
- `subject` is **already** in the CloudEvents envelope; this freeze just promotes
  it from "convention" to "URN, validated".

## 5. Freeze criteria

"Frozen" means **all** of the following are true:

1. **Schema version published** — `contracts/schemas/seam-correlation-v1.schema.json`
   exists in CellOS, validates the three additions in §4, and is referenced from
   `cell-compliance-summary-v1.schema.json` and the `Correlation` `$defs`.
2. **Commit hash recorded** — this document records the CellOS commit SHA that
   introduced the schema in a `## 6. Freeze record` section appended on freeze day.
3. **Cross-repo doc updates** — `tsafe`, `tencrypt`, `taudit`, and `0ryant-shell`
   each land a doc/PR pointing at the same `seam-correlation-v1.schema.json` URL
   and version, with at least the producer/consumer rows from §3 mapped onto their
   own emitters.
4. **One golden example per direction** — committed to `contracts/examples/`:
   - tsafe → CellOS rotation correlation (covers G1, G4).
   - CellOS → tencrypt export receipt (covers G2).
   - 0ryant-shell → CellOS spec submission (covers `correlationId` first-touch).
5. **Board reflects the freeze** — `docs/ecosystem-stage-board.md` Tranche 1 row
   marked closed with a link to this document at the frozen commit.

Until **all five** criteria are satisfied, the seam is **draft**, and consumers
should treat the §4 additions as "may rename before v1".

## 6. Freeze record

*To be appended on freeze day. Format:*

```
- v1.0.0 — frozen at CellOS <commit-sha> on <YYYY-MM-DD>
  - tsafe pointer: <commit-sha>
  - tencrypt pointer: <commit-sha>
  - taudit pointer: <commit-sha>
  - 0ryant-shell pointer: <commit-sha>
```

## 7. Out of scope (do not creep)

- tencrypt signed-export envelope shape (Tranche 3).
- Replay semantics for divergent runs (Tranche 2).
- RBAC / multi-tenant authority binding on `tenantId` (Tranche 4).
- Any new top-level `ProvenanceEnvelope` type — revisit in v2 if Tranche 3 needs it.
- Backfilling `correlationId` onto historical events — receivers must tolerate absence.

---

## taudit field inventory

*Added by taudit maintainer review — 2026-04-29.*

### Existing correlation/provenance fields

| Field | Location in codebase | Type | Stability |
|-------|----------------------|------|-----------|
| `CloudEventV1.correlationid` | `crates/taudit-sink-cloudevents/src/lib.rs` | `String` (caller-supplied non-empty id via sink constructor or `TAUDIT_CORRELATION_ID`; UUIDv4 fallback per `emit` call) | stable — same value applied to every finding event in one sink emission; documented as "shared correlation key for a single operator flow" |
| `CloudEventV1.tauditfindingfingerprint` | `crates/taudit-sink-cloudevents/src/lib.rs`; computed by `compute_fingerprint` in `taudit-core/src/finding.rs` | `String` (32-hex SHA-256) | stable — byte-identical to SARIF `partialFingerprints[primaryLocationLineHash]`, JSON `findings[].fingerprint`, and `BaselineFinding.fingerprint`; **the** cross-run dedup key |
| `CloudEventV1.tauditfindinggroup` | `crates/taudit-sink-cloudevents/src/lib.rs`; computed by `compute_finding_group_id` | `String` (UUIDv5 over namespace + fingerprint) | stable — collapses per-hop findings against the same authority root |
| `CloudEventV1.tauditcompleteness` | `crates/taudit-sink-cloudevents/src/lib.rs` | `String` (`"complete"` / `"partial"` / `"unknown"`) | stable |
| `CloudEventV1.tauditcompletenessgaps` | `crates/taudit-sink-cloudevents/src/lib.rs` | `Option<Vec<{kind, reason}>>` | stable — typed `GapKind` (`expression`/`structural`/`opaque`) paired with prose reason; omitted entirely on Complete/Unknown |
| `CloudEventV1.tauditplatform` | `crates/taudit-sink-cloudevents/src/lib.rs` | `Option<String>` (`"ado"`/`"gha"`/`"gitlab"`) | stable — sourced from `graph.metadata["platform"]`, allowlisted |
| `CloudEventV1.provenancerepo` | `crates/taudit-sink-cloudevents/src/lib.rs` (constant `"taudit"`) | `String` | stable |
| `CloudEventV1.provenanceproducer` | `crates/taudit-sink-cloudevents/src/lib.rs` (constant `"taudit-sink-cloudevents"`) | `String` | stable |
| `CloudEventV1.provenanceversion` | `crates/taudit-sink-cloudevents/src/lib.rs` (`env!("CARGO_PKG_VERSION")`) | `String` | stable per release |
| `CloudEventV1.provenancekind` | `crates/taudit-sink-cloudevents/src/lib.rs` (constant `"finding"`) | `String` | stable |
| `CloudEventV1.id` | `crates/taudit-sink-cloudevents/src/lib.rs` | `String` (UUIDv4) | stable — per-event envelope id |
| `CloudEventV1.source` | `crates/taudit-sink-cloudevents/src/lib.rs` (constant `"taudit"`) | `String` | stable but **not** URI-shaped today |
| `CloudEventV1.subject` | `crates/taudit-sink-cloudevents/src/lib.rs` (set to `graph.source.file`) | `Option<String>` (file path) | stable in shape, **not URN-form** |
| `CloudEventV1.ty` | `crates/taudit-sink-cloudevents/src/lib.rs` (`io.taudit.finding.<category_snake>`) | `String` | stable per category |
| `Baseline.pipeline_content_hash` | `crates/taudit-core/src/baselines.rs` (`pub struct Baseline`) | `String` (`sha256:<hex>`) | stable — primary baseline join key, survives renames |
| `Baseline.pipeline_identity_material_hash` | `crates/taudit-core/src/baselines.rs` | `Option<String>` | stable (additive since v1.1.0) — hash of include/template/repository/delegation material to invalidate suppressions on identity drift |
| `BaselineFinding.fingerprint` | `crates/taudit-core/src/baselines.rs` | `String` (32-hex SHA-256) | stable — same fingerprint as in CloudEvents/SARIF/JSON |
| `Baseline.captured_with.{taudit_version,rules_version}` | `crates/taudit-core/src/baselines.rs` (`pub struct CapturedWith`) | `String` × 2 | stable — tool/rules provenance at `init` time |
| `Baseline.captured_at` / `captured_by` | `crates/taudit-core/src/baselines.rs` | `DateTime<Utc>` / `String` | stable |

Notes:
- taudit has a **real** `correlationid` field already (the only repo of the four with this name in source today). The sink can now consume a caller-supplied non-empty id through `CloudEventsJsonlSink::with_correlation_id` or `TAUDIT_CORRELATION_ID`; otherwise it mints one UUIDv4 per `emit` call.
- taudit has **no** persistent "scan run ID" or "pipeline run ID" stored anywhere — each invocation is stateless from the tool's perspective; the only persistent identity is `Baseline.pipeline_content_hash` (which keys *what was scanned*, not *which scan*).
- taudit has **no** parent-event pointer on findings or baselines.

### Gap assessment (vs §4 proposed additions)

| Proposed field | Status in taudit |
|----------------|-----------------|
| `correlationId` | **present as `correlationid` with inbound support.** The field name matches §4 (lowercase, no separators — already CloudEvents-1.0-correct). The sink accepts an injected non-empty id through constructor arg or `TAUDIT_CORRELATION_ID`, and falls back to `Uuid::new_v4()` when absent. The remaining gap is shape: taudit does not enforce the proposed `urn:<tool>:corr:<ulid>` form. |
| `provenance.parent` | **absent.** No `parent` / `parent_id` field on `CloudEventV1`, `Finding`, or `Baseline`. The flat `provenance{repo,producer,version,kind}` quartet describes *self*, not *causation*. For G2/G4, taudit needs `provenanceparent` (or a nested `provenance` object once §4 lands). |
| `subject` URN | **present as a free-form string, not URN.** `subject = graph.source.file` (file path). Needs to become `urn:taudit:pipeline:<contentHash>` or `urn:taudit:finding:<fingerprint>` to match §4. The file path is also a leak vector for absolute-path local-dev runs. |

### Repo-specific additions needed

*Fields taudit would need to produce/consume that are not yet in §4:*

- **`pipelineId`** (URN: `urn:taudit:pipeline:sha256:<hex>`) — `Baseline.pipeline_content_hash` is already the natural identifier. Promote it to a top-level seam field so a CellOS run that later fails can be attributed to the exact pipeline-content version taudit scanned, even after the pipeline file is edited.
- **`scanRunId`** — taudit needs a per-invocation run id distinct from `correlationid` so multiple sinks emitted from the same scan share the run, while `correlationid` remains the *operator-flow* key (which may span multiple scans). Today `correlationid` conflates the two roles.
- **`findingFingerprint` as a seam field** — `tauditfindingfingerprint` (and SARIF/JSON equivalents) is taudit's stable cross-run dedup key. For G2 (provenance graph build), CellOS/tencrypt receipts that reference a taudit finding should carry the fingerprint as `provenance.parent = urn:taudit:finding:<fingerprint>` rather than the per-emission `CloudEvent.id`.
- **`baselineCapturedWith` as seam-visible provenance** — `Baseline.captured_with.{taudit_version,rules_version}` is currently baseline-internal. For seam-level reproducibility (taudit → SIEM → re-run), the rules_version should appear on each emitted CloudEvent (not just in the on-disk baseline), so consumers can answer "would re-running today produce the same finding set?" without parsing the baseline file.
- **Inbound `correlationId` channel** — shipped for the CloudEvents sink: `CloudEventsJsonlSink::with_correlation_id(Some(non_empty))` and `TAUDIT_CORRELATION_ID` both feed `correlationid`; empty values fall back to `Uuid::new_v4()`.
