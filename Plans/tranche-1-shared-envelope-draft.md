# Tranche 1 Draft: Shared Evidence Envelope

This document is the first concrete output of `Tranche 1 - seam freeze`.

Goal: freeze one shared CloudEvents-style envelope and correlation vocabulary tightly enough that sibling repos can stop guessing.

## Scope

This tranche standardizes only the common envelope and shared extension attributes.

It does not standardize:

- repo-local payload fields inside `data`
- transport choices such as local JSONL vs. message bus
- repo-local policy semantics
- remediation or UX behavior in consumers

## Draft artifact

- Schema: `contracts/schemas/ecosystem-evidence-envelope-v0.schema.json`
- Example: `contracts/examples/ecosystem-evidence-envelope.example.json`

## Canonical shared fields

These fields are now the draft minimum for any ecosystem evidence that wants to participate in the shared operator flow:

| Field | Meaning |
|---|---|
| `specversion` | CloudEvents version, currently `1.0` |
| `id` | event identifier unique in the producing system |
| `source` | producing tool or subsystem |
| `type` | stable event type name |
| `subject` | operator-facing subject of the event |
| `time` | RFC 3339 timestamp |
| `datacontenttype` | currently `application/json` |
| `correlationid` | cross-repo join key for a single operator flow |
| `provenancerepo` | repository that emitted the event |
| `provenanceproducer` | binary, command, or subsystem that produced it |
| `provenanceversion` | optional producer or schema version |
| `provenancekind` | high-level class such as `finding`, `execution`, or `authority` |
| `data` | repo-local payload |

## Draft mapping by repo

### taudit

Current state:

- already emits a CloudEvents finding envelope
- already has a checked-in schema and example

Delta to conform:

- shipped in this repo slice for CloudEvents finding output: `correlationid`, `provenancerepo`, `provenanceproducer`, `provenanceversion`, `provenancekind`
- remaining decision: whether taudit keeps a taudit-specific finding schema only, or also treats the shared envelope schema as a first-class contract in CI and docs

### tencrypt

Current state:

- README and tracking docs say it emits audit JSONL and CloudEvents JSONL
- no checked-in schema or example was found in this workspace snapshot

Delta to conform:

- publish a checked-in schema or example for emitted CloudEvents-style evidence
- adopt shared envelope fields above the repo-local certificate payload
- carry `correlationid` across lifecycle artifacts

### 0ryant-shell

Current state:

- council roadmap names shared event contracts and taudit ingest parity as Wave 1 and Wave 2 work
- no checked-in schema or example was found in this workspace snapshot

Delta to conform:

- define emitted event shapes against the shared envelope
- decide which execution and error events deserve shared correlation
- preserve repo-local runtime semantics inside `data`

### tsafe

Current state:

- roadmap prioritizes authority contracts and audit explanation over generic integration breadth

Delta to conform:

- emit execution-boundary and authority-context evidence using the shared envelope without flattening tsafe's authority semantics
- make `data` carry allowed, denied, and stripped context in a machine-readable way

### tedit

Current state:

- primarily a consumer in this tranche, not a primary producer

Delta to conform:

- consume `correlationid`, `type`, `subject`, and `provenance*` predictably when showing cross-tool state
- avoid inventing a second envelope just for editor refresh semantics

## Decisions made in this draft

1. Standardize a thin envelope first, not a shared payload schema.
2. Treat `correlationid` as required for shared-flow evidence.
3. Keep provenance explicit instead of inferring it from `source` alone.
4. Allow repo-local payloads to evolve independently under `data`.

## Open follow-up work

1. Decide whether taudit extends its current CloudEvents finding schema directly or emits both current and shared-envelope-compatible examples during transition.
2. Confirm whether tencrypt and 0ryant-shell already emit fields that can map directly to `correlationid` and `provenance*`.
3. Decide whether tsafe needs a dedicated authority event type registry or can start with a smaller set of execution-boundary events.
4. Decide whether a shared error envelope belongs in this tranche or the next seam-freeze tranche.

## Next implementation move

Use this draft as the comparison baseline and record the exact field deltas for taudit, tencrypt, tsafe, and 0ryant-shell in the next loop.