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
  into a typed graph and applies invariants. **Shipped** on crates.io (1.0.x).
  **Try it:** copy-paste flows on committed fixtures live in
  [Golden paths](../golden-paths.md); CI and `just pre-push-gate` smoke them via
  [`scripts/golden-paths.sh`](../../scripts/golden-paths.sh).
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

## Related tooling (outside the three-layer diagram)

| Layer | Role | Contract / docs |
|-------|------|-------------------|
| **tsafe** | Scoped secret execution — reduce ambient token exposure when findings recommend it | Product loop in [`docs/DOCTRINE.md`](../DOCTRINE.md) |
| **CellOS / isolation runtime** | Contain execution when findings require isolation | [`CellosRemediation`](../../crates/taudit-core/src/finding.rs) hints in findings |
| **actionlint** (et al.) | Workflow correctness, contexts, expression sanity | [actionlint](https://github.com/rhysd/actionlint) — **complementary** to taudit, not replaced by it ([`docs/positioning.md`](../positioning.md)) |

**Future (not shipped):** consuming external linter SARIF or diagnostics as
**optional context** for triage would be a separate integration, behind an
explicit flag and ADR — not merged into the core graph parser.

## CI mirrors (ADO, GitLab, Bitbucket)

For **Azure DevOps** (e.g. org **0ryant**), **GitLab CI**, and **Bitbucket Pipelines**, see **[`ci-mirrors.md`](ci-mirrors.md)** — root **`azure-pipelines.yml`**, **`.gitlab-ci.yml`**, and **`bitbucket-pipelines.yml`** mirror the Rust + governance + taudit checks where the platform supports it.

## GitHub Actions: stack-integration (this repo)

The [`stack-integration`](../../.github/workflows/stack-integration.yml) workflow assumes **tsafe** and **CellOS** live in **the same GitHub org as this repository** (default repo ids **`{owner}/tsafe`** and **`{owner}/CellOS`** on `github.com`, where `{owner}` is this repo’s owner). The Actions **`GITHUB_TOKEN`** can clone those repos when they are private to the org. It runs **`taudit scan`** on tsafe’s `.github/workflows/` (override repo id with **`SIBLING_TSAFE_REPO`** if the name differs).

For **CellOS**, it prefers a **`cellos-supervisor` image from GHCR** (`ghcr.io/<owner>/cellos-supervisor:<tag>`, tag **`CELLOS_SUPERVISOR_TAG`** or full **`CELLOS_SUPERVISOR_IMAGE`**), runs [`scripts/cellos_smoke_docker.sh`](../../scripts/cellos_smoke_docker.sh), and **falls back** to cloning **`SIBLING_CELLOS_REPO`** / `<owner>/CellOS` and [`scripts/cellos_smoke.sh`](../../scripts/cellos_smoke.sh) if the image pull fails. The Docker path bind-mounts the **Linux `taudit` binary** from the runner (`ubuntu-latest`); on a macOS host, use [`cellos_smoke.sh`](../../scripts/cellos_smoke.sh) instead (or cross-compile `taudit` to `*-unknown-linux-gnu`).

Build and push that image with **[`publish-cellos-ghcr`](../../.github/workflows/publish-cellos-ghcr.yml)** (Dockerfile under [`packaging/docker/cellos-supervisor/`](../../packaging/docker/cellos-supervisor/)); it checks out CellOS from GitHub at **`main`** (push to this repo on Dockerfile changes, or **workflow_dispatch**). The **tsafe vault CLI is not invoked** in CI. **`quality.yml` / `security.yml`** set `TAUDIT_CORRELATION_ID` on self-scans for CloudEvents correlation.

**Azure DevOps:** the same stack smoke is a **separate** pipeline (GitHub service connection + optional GHCR secrets), not part of the default secretless mirror — see **[`ci-mirrors.md` — Stack-integration (sketch)](ci-mirrors.md#stack-integration-separate-ado-pipeline-sketch)** and **[`azure-pipelines.stack-integration.yml`](../../azure-pipelines.stack-integration.yml)**.

## What you can do today, standalone

taudit's standalone surface already covers the local-only flavour of
what tsign and axiom will do at scale:

| Need | Today | At-scale equivalent |
|---|---|---|
| Get the graph | `taudit graph --format json` | feeds tsign |
| Render the graph (Graphviz) | `taudit graph --format dot \| dot -Tsvg` | high-fidelity SVG/PNG |
| Render the graph (Mermaid) | `taudit graph --format mermaid` | paste into Markdown (no `dot` binary) |
| Local PR gate | `taudit verify --policy .taudit/policy.yml` | becomes axiom's per-evaluation engine |
| SARIF for code scanning | `taudit scan --format sarif` | independent of the stack |
| Event sink | `taudit scan --format cloudevents` | independent of the stack |

`taudit verify` is the local-only flavour of what axiom does at scale —
same invariant DSL, same exit-code contract
([`docs/verify.md`](../verify.md)). Adopting it now means your
invariants port unchanged when axiom lands.

## Cross-format finding dedup

Every finding taudit emits carries the same stable 32-hex
**fingerprint** in three different output formats:

| Format       | Field                                                        |
|--------------|--------------------------------------------------------------|
| SARIF        | `partialFingerprints["primaryLocationLineHash"]` and `partialFingerprints["taudit/v1"]` |
| JSON         | `findings[].fingerprint`                                     |
| CloudEvents  | extension attribute `tauditfindingfingerprint`               |

SIEMs ingesting from any of these channels can join on the
fingerprint to dedup re-runs, route to the same suppression DB, and
preserve user-managed state across CI invocations. GitHub Code
Scanning uses `partialFingerprints` natively to carry suppressions
and dismissals across SARIF uploads.

The standalone Finding shape is published at
[`schemas/finding.v1.json`](../../schemas/finding.v1.json) so
downstream consumers (SIEM rules, suppression DBs, ticket sync) can
validate finding payloads without loading the report wrapper or the
CloudEvents envelope.

See [`docs/finding-fingerprint.md`](../finding-fingerprint.md) for
the formula, the stability guarantee, the SARIF baseline-mapping
integration with GitHub Code Scanning, and the contract for future
major-version formula bumps.

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
