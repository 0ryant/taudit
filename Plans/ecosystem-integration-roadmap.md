# Ecosystem Integration Roadmap

This roadmap synthesizes a council debate across the sibling repos in `/Users/rytilcock/prj`:

- `taudit`
- `tsafe`
- `tencrypt`
- `tedit`
- `0ryant-shell` (`0sh` / CellShell)

## Council synthesis

The council converged on one principle: build a thin interoperability layer, not a shared runtime.

That means:

- shared contracts and evidence shapes at the seam
- repo-local adapters inside each product
- one visible end-to-end workflow early so the contracts are exercised by real operator use

## Current cross-repo facts

- `tedit` already depends on `0ryant-shell` for `cellshell-repl`, `cellshell-lsp`, and the not-yet-designed `TEDIT=1` typed output protocol.
- `tedit` also calls out `tsafe` prompt environment metadata and `taudit` CloudEvents export as ecosystem dependencies.
- `0ryant-shell` explicitly calls for a `SecretProvider` backed by `tsafe` and an `AuditSink` backed by `taudit` graph export / JSON / CloudEvents.
- `tencrypt` already emits audit JSONL and CloudEvents-compatible evidence.
- `taudit` already emits CloudEvents JSONL and machine-readable report contracts.
- `tsafe` is the declared-authority system of record for secret scope and execution context.

## Shared seams to standardize

These should be versioned, example-backed contracts, not a central platform crate.

1. `SecretProvider`
2. `AuditSink`
3. `PromptMetadata`
4. `TEDIT=1` typed output protocol
5. Stable correlation IDs and provenance fields
6. One CloudEvents-style evidence envelope with repo-specific data payloads

## What should stay decentralized

- execution runtimes
- repo-local storage models
- editor UX details
- policy authoring and ignore semantics
- release cadence per repo

## Phased roadmap

### Phase 1: Freeze the seam

Goal: make the shared boundary explicit and testable.

Owners:

- `taudit`: finding envelope, severity vocabulary, correlation fields, example fixtures
- `tsafe`: secret-resolution and execution-context contract, prompt metadata shape
- `0ryant-shell`: `SecretProvider` + `AuditSink` port definitions, `TEDIT=1` protocol draft
- `tedit`: consumer requirements for prompt metadata and typed shell output
- `tencrypt`: evidence field alignment against the shared envelope

Tasks:

- define one versioned evidence envelope with required fields for `id`, `source`, `subject`, `time`, correlation, and repo-local payload
- define `PromptMetadata` for active tsafe profile / contract / namespace / trust mode
- define the minimal `TEDIT=1` protocol for typed output and source-span links
- publish golden examples in each repo and validate them in CI

Exit criteria:

- every repo can validate the same seam locally with fixtures
- no repo is blocked on hidden or implied metadata

### Phase 2: Implement repo-local adapters

Goal: wire the seam without creating a central integration runtime.

Owners:

- `0ryant-shell`: tsafe-backed `SecretProvider`, taudit-compatible `AuditSink`, correlation propagation
- `tsafe`: emit prompt metadata and secret lifecycle evidence at execution boundaries
- `taudit`: ingest or at least preserve shell and tool provenance consistently in findings/evidence output
- `tencrypt`: align emitted evidence to the shared envelope and propagate correlation IDs
- `tedit`: consume prompt metadata and typed shell output from the shell boundary

Tasks:

- `0ryant-shell` resolves secrets through `tsafe`, not ad hoc subprocess text substitution
- `0ryant-shell` emits auditable semantic events that remain taudit-friendly
- `tencrypt` propagates shared correlation and provenance fields into its evidence JSONL and CloudEvents output
- `tedit` renders ambient tsafe context from `PromptMetadata`

Exit criteria:

- shell, cert workflow, and scanner outputs share correlation semantics
- adapters remain local to each repo

### Phase 3: Ship one golden operator workflow

Goal: prove the seam through a daily-use flow.

Recommended golden path:

1. author or inspect a workflow/script in `tedit`
2. see active `tsafe` authority context in shell/editor
3. execute through `0ryant-shell`
4. emit correlated evidence from `tsafe`, `0ryant-shell`, and `tencrypt`/`taudit`
5. surface `taudit` findings inline or adjacent to that same operator flow

Owners:

- `tedit` + `0ryant-shell`: visible shell/editor continuity
- `tsafe`: persistent context visibility and secret authority provenance
- `taudit`: findings surfaced with stable drill-through identifiers
- `tencrypt`: evidence example as one auditable workload in the flow

Exit criteria:

- one end-to-end demo exists and is documented
- the workflow exercises the shared contracts under real use, not just synthetic fixtures

### Phase 4: Expand integration breadth

Goal: deepen automation only after the seam and the golden workflow are stable.

Candidate follow-ons:

- richer taudit ingestion of shell and execution evidence
- policy enforcement hooks driven by tsafe or taudit findings
- additional typed output surfaces in `tedit`
- CI compatibility tests across sibling repos

## Recommended order of attack

1. Draft and freeze the seam documents and fixtures.
2. Implement `0ryant-shell` adapters for `tsafe` and `taudit`.
3. Expose ambient tsafe context in `tedit`.
4. Prove one golden workflow with taudit findings and tencrypt evidence.
5. Only then broaden integrations.

## Explicit non-goals

- one shared monorepo runtime
- forced release synchronization across all repos
- centralizing every schema into one crate before the workflow is proven

The council’s core recommendation is simple: standardize the handoff, not the products.