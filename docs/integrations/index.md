# Stack Integrations

> taudit is one layer of a small, composable stack. This page is the
> two-minute orientation for downstream tool authors. Per-layer specs
> live next to it.

## The three layers

```
   YAML pipelines (GHA / ADO / GitLab CI)        ← substrate
            │
            ▼
   ┌──────────────────────┐
   │  taudit (graph)      │  deterministic authority graph + invariants
   └──────────┬───────────┘  taudit graph --format json
              │
              ▼
   ┌──────────────────────┐
   │  tsign (attestation) │  signs (graph digest, commit, predicate)
   └──────────┬───────────┘  in-toto Statement, DSSE-wrapped, cosign-signed
              │
              ▼
   ┌──────────────────────┐
   │  axiom (enforcement) │  per-PR / per-deploy decisions across many repos
   └──────────┬───────────┘  decision JSON (allow / block / flag_for_review)
              │
              ▼
       Merge bots, deploy gates, SIEM
```

Each layer is single-purpose, externally verifiable, and replaceable:

- **taudit** — *what does authority look like?* Parses pipeline YAML
  into a typed graph and applies invariants. Today.
  Ships in v0.9.0.
- **tsign** — *who saw this graph and when?* Attaches signed claims to
  graph digests so a verifier can prove "this pipeline matched the
  approved shape at commit `<S>`". Sibling project, **coming in
  tsign v0.1**.
- **axiom** — *should we let this through?* Aggregates attested graphs
  across repos, applies organisational policy, emits decisions
  external systems consume. Sibling project, **coming in axiom v0.1**.

## Contract surfaces

Three contracts pin the layers together. Each is versioned in its
envelope so consumers can pin to a major and fail loudly on a break.

| Contract | Owned by | Where |
|---|---|---|
| Authority graph JSON | taudit | [`schemas/authority-graph.v1.json`](../../schemas/authority-graph.v1.json) — `schema_version: "1.0.0"` today |
| in-toto predicate `taudit.dev/attestations/authority-graph/v0.1` | tsign | [`tsign-consumer.md`](tsign-consumer.md) |
| axiom decision JSON | axiom | [`axiom-consumer.md`](axiom-consumer.md) — `decision_schema_version: "0.1.0"` today |

The graph schema is `1.x.y` — additive changes only, breaking changes
require a `2.0.0` bump (see
[`docs/authority-graph.md`](../authority-graph.md#versioning)). The two
proposed contracts are explicitly `0.x` to leave room for evolution
before the sibling projects publish.

## Why this composition matters

- **Each layer is single-purpose.** taudit doesn't sign. tsign doesn't
  decide. axiom doesn't parse YAML. The seams are sharp and the blast
  radius of any bug is contained to one layer.
- **Each layer is replaceable.** An org that already has a different
  attestation system can substitute it for tsign as long as it produces
  the predicate. An org that wants its own enforcement engine can skip
  axiom and consume attestations directly.
- **Each layer is externally verifiable.** The graph is deterministic —
  any verifier can rehash. The attestation is a standard in-toto
  Statement — any cosign client can verify. The decision JSON is
  versioned and self-describing — any external system can pin to it.
- **Each layer is useful standalone.** taudit ships value today
  without tsign or axiom. tsign would be useful even without axiom
  consuming it. axiom is the multiplier when everything is in place.

## What you can do today, standalone

taudit's standalone surface already covers the local-only flavour of
what tsign and axiom will do at scale:

| Need | Today | At-scale equivalent |
|---|---|---|
| Get the graph | `taudit graph --format json` | feeds tsign |
| Render the graph | `taudit graph --format dot \| dot -Tsvg` | docs / incident review |
| Local PR gate | `taudit verify --policy .taudit/policy.yml` | becomes axiom's per-evaluation engine |
| SARIF for code scanning | `taudit scan --format sarif` | independent of the stack |
| Event sink | `taudit scan --format cloudevents` | independent of the stack |

`taudit verify` is the local-only flavour of what axiom does at scale —
same invariant DSL, same exit-code contract
([`docs/verify.md`](../verify.md)). Adopting it now means your
invariants port unchanged when axiom lands.

## Per-layer specs

- **[`tsign-consumer.md`](tsign-consumer.md)** — input contract,
  proposed in-toto predicate, attestation example, verification flow,
  open questions on partial graphs and external KV refs.
- **[`axiom-consumer.md`](axiom-consumer.md)** — input contract,
  cross-repo aggregation, proposed policy layout, decision JSON
  contract, open questions on version skew and emergency overrides.

## Background

- **[`docs/positioning.md`](../positioning.md)** — long-form framing
  for why authority modelling is the right primitive.
- **[`docs/authority-graph.md`](../authority-graph.md)** — the graph
  schema and the v1 versioning guarantee.
- **[`docs/ROADMAP.md`](../ROADMAP.md)** — where the stack is going.
