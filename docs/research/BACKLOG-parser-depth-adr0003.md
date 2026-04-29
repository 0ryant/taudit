# Parser / resolution backlog (ADR 0003 Phase 4.1)

Triage-driven work to reduce **high-risk** `partial` / `unknown` graphs without turning taudit into a full workflow compiler. Each item should ship with **fixtures + tests** and a note in [`docs/authority-graph.md`](../authority-graph.md) if `completeness` semantics change.

| Priority | Area | Hypothesis | Acceptance sketch |
|----------|------|------------|---------------------|
| P1 | GitHub composite actions | Large `partial` share when `uses: ./path` or composite internals unresolved | Corpus metric: % workflows with composite; fixture with known secret path through composite; graph `complete` or documented gap |
| P2 | Reusable workflows (`workflow_call`) | Authority chains break at callee boundary | Fixture: caller + callee; edges across call or explicit `completeness_gaps` entry |
| P3 | `workflow_dispatch` / dynamic `uses` | Unresolvable refs → `partial` | Rule: no false `complete`; gap string stable |
| P4 | Shell / expression inference | Secrets in opaque strings | Narrow wins only; tests from anonymized snippets |

**Non-goals:** Parity with GitHub’s full expression evaluator; online resolution of action marketplaces.

**Related:** [ADR 0002 Phase 4](../adr/0002-authority-signal-roadmap-phased.md) (diagram collapse, `--risk-only`, dense-graph tuning) — orthogonal rendering/scale work.
