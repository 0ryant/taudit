# Implementation backlog: graph leverage (2026-04-27)

Derived from [research](./2026-04-27-graph-as-product-research.md), [council](./2026-04-27-council-graph-as-product.md), and [ADR 0001](../adr/0001-graph-native-exports-and-leverage.md).

## Phase A — Shipped in same delivery as ADR 0001 (done, v1.0.6)

| ID | Task | Acceptance | Verify |
|----|------|------------|--------|
| A1 | `render_mermaid` in `taudit-core` + `graph --format mermaid` | Parity with `render_dot` for `--job` filter; deterministic output; `%%` partiality when not `Complete` | `cargo test -p taudit-core map::tests`; `taudit graph --format mermaid .github/workflows/security.yml` |
| A2 | Document in USERGUIDE + ADR link | New subsection under graph/DOT; example code block | [USERGUIDE.md](../../USERGUIDE.md) + [ADR 0001](../adr/0001-graph-native-exports-and-leverage.md) |
| A3 | CHANGELOG entry | v1.0.6 | [CHANGELOG.md](../../CHANGELOG.md) |

## Phase B — Hardening (done, v1.0.7)

| ID | Task | Acceptance | Verify |
|----|------|------------|--------|
| B1 | EPIPE-safe stdout for `taudit map` (text + dot) | No panic on `| head -c 1` | `cargo test -p taudit --test broken_pipe` |
| B2 | EPIPE audit: `scan` + other stdout-heavy commands | `SilenceBrokenPipe` on streaming stdout; `try_write_stdout` / `try_println!` elsewhere | Same + `just check` |
| B3 | `examples/consumers` — Mermaid pointer | README | [examples/consumers/README.md](../../examples/consumers/README.md) |

## Phase C — Contract depth (separate ADRs)

| ID | Task | Note |
|----|------|------|
| C1 | SARIF `region` / startLine where YAML span available | New ADR; GitHub Code Scanning |
| C2 | Parser: reduce `Partial` for reusable workflows (GHA) | Long-running; see ROADMAP V1-5 |

---

## Test plan (Phase A)

1. `cargo test -p taudit-core map::tests` — Mermaid unit tests
2. `cargo test -p taudit` — integration / CLI
3. `cargo clippy --workspace --all-targets -- -D warnings`
4. `just quality-gate` or project equivalent before merge

## Code review checklist (any PR touching graph export)

- [ ] No new graph construction paths — only **rendering** from `AuthorityGraph`
- [ ] **Escaping** safe for Mermaid + GitHub (quotes, newlines, `[` `]`)
- [ ] **`--job`** matches DOT
- [ ] **Deterministic** — stable ordering
- [ ] **Docs** — USERGUIDE + ADR if behaviour visible to users

## Bug-hunt / red-team (diff for Phase A)

- [ ] **Label injection:** `"]` or `-->` in **fake** step names — must not break Mermaid
- [ ] **Huge graphs** — >200 nodes: still renders or documented limit
- [ ] **Partial graph** — `%%` line present when `completeness` partial
- [ ] **Pipe** — `graph --format mermaid | head -c 1` exits 0
- [ ] **Cross-platform** — Windows line endings in output? (use `\n` only in strings)

## Iteration

After merge: gather **one** real repo workflow screenshot in a discussion/issue; if Mermaid chokes, open a **bug** with the **minimal** `AuthorityGraph` JSON (not full customer YAML).

## Closure

When Phase A is merged and tagged: mark this section **Done** in a follow-up commit or link the release in CHANGELOG.
