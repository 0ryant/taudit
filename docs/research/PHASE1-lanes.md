# Phase 1 lanes — ADR 0002 (`--rich-labels`)

**ADR:** `docs/adr/0002-authority-signal-roadmap-phased.md` (Phase 1 only).  
**Non-goals preserved:** no JSON/schema changes; default diagram labels unchanged (`DiagramLabelDetail::Compact`); no APIs or risk scores.

## Gap vs ADR wording

`taudit map` currently supports `text` and `dot` only. Phase 1 adds **`MapFormat::Mermaid`** so `taudit map --format mermaid` matches `taudit graph --format mermaid` (same renderers and flags).

## Frozen interface (`taudit-core`)

Public enum and signatures (callers pass `DiagramLabelDetail::default()` for compact / unchanged behavior):

```rust
// crates/taudit-core/src/map.rs
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum DiagramLabelDetail {
    #[default]
    Compact,
    Rich,
}

pub fn render_dot(
    graph: &AuthorityGraph,
    filter_job: Option<&str>,
    label_detail: DiagramLabelDetail,
) -> String;

pub fn render_mermaid(
    graph: &AuthorityGraph,
    filter_job: Option<&str>,
    label_detail: DiagramLabelDetail,
) -> String;
```

**Rich label content (existing metadata only):** for each node, include `Debug` trust zone string (same as table map rows), plus when present `META_IDENTITY_SCOPE` and `META_PERMISSIONS` (abbreviated). No new graph edges or propagation.

**Internal helpers (not frozen):** `diagram_node_label(node, detail)`, length caps, optional refactor of `mermaid_node_line` to accept pre-escaped display text.

## Lane table

| Lane | Owner scope | Exclusive write paths | Allowed shared read-only | Forbidden |
|------|-------------|------------------------|---------------------------|-----------|
| **L1 — Core render** | Core diagram API | `crates/taudit-core/src/map.rs` | `crates/taudit-core/src/graph.rs` (metadata constants only; **no edits** unless a type is required — prefer importing existing `META_*` from `graph`) | Changes to `AuthorityGraph` shape, JSON export, propagation, default label text for `Compact` |
| **L2 — CLI** | Flags + wiring | `crates/taudit-cli/src/main.rs` | Any crate (read) | Editing `map.rs`, doc files, `tests/fixtures/` |
| **L3 — Docs** | User-facing copy | `USERGUIDE.md`, `docs/authority-graph.md` | ADR / this file (read) | Code changes |
| **L4 — Fixtures / CLI tests** | E2E assertions | `tests/fixtures/*.yml` (new or minimal existing), `crates/taudit-cli/tests/*.rs` (one new test module or file) | `main.rs` (read only) | Editing `map.rs` |

## Merge order

1. **L1** → `taudit-core` compiles; unit tests in `map.rs` updated for new parameter.  
2. **L2** → CLI passes `DiagramLabelDetail`, adds `--rich-labels`, validates incompatible combos (`json` / `text`).  
3. **L4** → binary/integration tests: default vs `--rich-labels` on Mermaid + DOT using `tests/fixtures/clean.yml` (or smaller dedicated YAML).  
4. **L3** → docs last (flag names stable).

## Conflict risk

- **`crates/taudit-cli/src/main.rs` is single-threaded** — only **L2** may edit it; L4 must not touch `main.rs`.
- **L1 vs L4:** L4 must not add tests inside `taudit-core`; use CLI process tests only.

## Deferred (not Phase 1)

- (none — `man/taudit.1` updated for `--rich-labels` and `map --format mermaid`.)

## Orchestration note (this run)

Lanes were executed **sequentially in one workspace** (L1→L2→L4→L3) by the orchestrator to avoid concurrent edits to the same clone; merge order matches this document.

## Verification (repo root)

After merge: `cargo fmt --all` && `cargo test` (workspace).
