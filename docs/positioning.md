# Positioning

> CI/CD is an untyped authority system. taudit makes it explicit, inspectable, and enforceable.

## The problem

CI/CD pipelines move secrets, identities, and tokens between steps every minute of every day, but the platforms that run them have no type system for authority. Permissions are YAML strings. Trust boundaries are implicit. Whether a `GITHUB_TOKEN` reaches an unpinned action three jobs downstream is something engineers infer by reading the file top to bottom and hoping. Reviews catch obvious mistakes; everything else ships. This is not a tooling gap — it is a missing layer of the platform.

## The model

taudit treats a pipeline as a directed graph of authority propagation. The primitives are fixed:

- **NodeKinds** — `Step`, `Secret`, `Identity`, `Image`, `Artifact`. Each one names a concrete thing in the pipeline.
- **TrustZones** — `FirstParty` (your code), `ThirdParty` (SHA-pinned external code), `Untrusted` (tag-pinned actions, fork PRs, user input). Every node carries a zone.
- **EdgeKinds** — `HasAccessTo`, `Produces`, `Consumes`, `UsesImage`, `DelegatesTo`, `PersistsTo`. Each edge names how authority moves.

The graph is deterministic: same YAML in, same graph out, byte for byte. It is inspectable: you can dump it, diff it, render it as DOT. It is exportable: JSON today, a versioned schema in v1.0. The graph is the product. Findings, SARIF, the terminal report — all of those are consumers of the graph.

See [`docs/authority-graph.md`](authority-graph.md) for the full specification.

## The product surface

```
parse  →  graph  →  invariants  →  verify  →  enforce
```

1. **Parse** GitHub Actions, Azure DevOps, or GitLab CI YAML into the typed authority graph.
2. **Generate** the graph as a first-class artifact (DOT, JSON, SARIF).
3. **Apply invariants** — 61 built-in checks, plus custom rules loaded from YAML.
4. **Verify** — `taudit verify` (v1.0) gates PRs against an explicit invariant set instead of fuzzy severity thresholds.
5. **Enforce** — exit codes, SARIF for code-scanning, CloudEvents for SIEM, PR-bot diffs for review.

## The stack

taudit is the graph layer. It is meant to be composed with sibling projects, not extended into them:

- **taudit** — generates the authority graph and checks invariants over it.
- **tsign** — attestation layer. Consumes the graph to attach signed claims about which authority paths existed at build time.
- **axiom** — enforcement brain. Consumes graphs and attestations to make merge / deploy decisions across many repos.
- **CI providers** (GHA, ADO, GitLab) — substrate. taudit reads their YAML; it does not replace them.

tsign and axiom are sibling projects, not features of taudit. They depend on taudit's graph being a stable contract.

## Not in scope

Per [doctrine](DOCTRINE.md) anti-goals — these stay out of scope permanently:

- Secret pattern scanning (use `gitleaks`).
- CVE scanning (use `trivy`).
- IaC policy engines (use `checkov`).
- Runtime monitoring — taudit reads pipeline YAML, offline, always.
- Cloud API resolution — what each cloud permission *means* is out of scope; taudit classifies scope (broad / constrained / unknown).

## Why determinism matters

Determinism is the bridge to PR-gate enforcement. A reviewer can only block a merge on a finding they trust to reproduce. Probabilistic scanners produce findings that flicker between runs; nobody wires them into required checks. taudit's graph is a pure function of the input YAML. The same workflow always yields the same graph, the same invariants always fire, and the same exit code falls out the bottom. That is the property that makes `taudit verify` safe to put on the critical path of every merge.
