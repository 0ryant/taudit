# tsign — Attestation Consumer

> tsign is a sibling project (not yet released). It is the **attestation
> layer** of the stack. This document specifies how it should consume
> taudit's authority graph so that downstream verifiers can prove
> "this pipeline's authority shape was approved at commit `<S>`".

taudit produces a deterministic graph. tsign signs claims about that
graph. A verifier later checks the signature, refetches the graph, and
hash-compares. The graph is the contract; tsign never reinterprets it.

## Input contract

tsign reads exactly one source: the JSON document emitted by

```bash
taudit graph --format json <pipeline.yml>
```

This document conforms to
[`schemas/authority-graph.v1.json`](../../schemas/authority-graph.v1.json).
The `schema_version` envelope (`1.0.0` today) is part of the contract.
tsign MUST refuse documents whose `schema_version` falls outside the
major version it supports — the same rule taudit asks of every consumer
in [`docs/authority-graph.md`](../authority-graph.md).

The graph is canonicalised before hashing. The recommended canonical
form is RFC 8785 (JCS) over the full envelope; the resulting digest is
the value tsign signs.

## Attestation shape — proposal v0.1

tsign produces an [in-toto](https://in-toto.io/) Statement whose
`predicateType` is:

```
https://taudit.dev/attestations/authority-graph/v0.1
```

The predicate is intentionally narrow: it pins a graph digest to a
commit, not the full graph. Verifiers refetch the graph on demand.

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "git+https://github.com/acme/widgets@.github/workflows/release.yml",
      "digest": {
        "sha256": "f1c2…<sha256 of the canonicalised authority-graph JSON>"
      }
    }
  ],
  "predicateType": "https://taudit.dev/attestations/authority-graph/v0.1",
  "predicate": {
    "graph_schema_version": "1.0.0",
    "graph_schema_uri": "https://taudit.dev/schemas/authority-graph.v1.json",
    "taudit_version": "0.9.0",
    "source": {
      "repo": "https://github.com/acme/widgets",
      "git_ref": "refs/heads/main",
      "commit_sha": "5b8…",
      "pipeline_path": ".github/workflows/release.yml"
    },
    "completeness": "complete",
    "node_count": 42,
    "edge_count": 67,
    "invariant_set": {
      "builtin_set_version": "0.9.0",
      "custom_invariants_digest": "sha256:9d4…"
    },
    "produced_at": "2026-04-26T12:00:00Z"
  }
}
```

`subject[0].digest.sha256` is the digest of the canonicalised
`taudit graph --format json` output. `predicate.invariant_set` lets a
verifier reason about *which rules were considered green* at sign time
without embedding the rules.

## Signing

The Statement above is wrapped in a [DSSE](https://github.com/secure-systems-lab/dsse)
envelope and signed. cosign keyless is the recommended path:

```bash
taudit graph --format json .github/workflows/release.yml \
  | tsign attest --predicate-type https://taudit.dev/attestations/authority-graph/v0.1 \
                 --subject-name "git+$REPO@$PIPELINE" \
                 --output release.intoto.jsonl
cosign attest-blob --predicate release.intoto.jsonl --type custom \
                   --bundle release.bundle release.intoto.jsonl
```

`tsign attest` is **coming in tsign v0.1**. Until it ships, the
Statement above can be hand-assembled — the predicate URI and shape are
the parts that matter.

## Verification

```bash
# 1. Fetch the bundle and verify the signature.
cosign verify-blob --bundle release.bundle release.intoto.jsonl

# 2. Refetch the graph at the recorded commit and rehash.
git checkout 5b8…
taudit graph --format json .github/workflows/release.yml \
  | jcs | sha256sum
# Compare against subject[0].digest.sha256 in the Statement.

# 3. Optionally re-evaluate policy.
taudit verify .github/workflows/release.yml --policy .taudit/policy.yml
```

A graph mismatch means the pipeline drifted from the approved shape.

## What this enables

- **Authority drift detection.** A reviewer can prove "this PR's
  pipeline matches the authority shape we signed off at commit `<S>`".
- **Decoupled trust.** Signers and verifiers never need to share rules
  — only the graph and a predicate URI.
- **Replayable audits.** The graph is deterministic; the attestation is
  small. Years-later replay is feasible.

## Open questions

- **Partial graphs.** Should tsign refuse to sign `partial` graphs, or
  sign them with `predicate.completeness: "partial"` so the verifier
  can decide? Current proposal: sign, surface the flag, let policy at
  the axiom layer reject.
- **Secrets from external KV refs.** Some secrets are pulled at runtime
  from external KV (Vault, AWS Secrets Manager, tsafe). The graph
  records the *reference*, not the value. tsign attests the reference
  shape. End-to-end secret provenance needs a second predicate type —
  out of scope for v0.1.
- **Invariant-set hashing.** `custom_invariants_digest` is proposed as a
  recursive sha256 of the YAML invariant files in lexical order. Spec
  is informal; a stable canonicalisation lands with tsign v0.1.

## See also

- [`docs/authority-graph.md`](../authority-graph.md) — the schema
- [`docs/positioning.md`](../positioning.md) — why this layering
- [`docs/integrations/axiom-consumer.md`](axiom-consumer.md) — what
  consumes these attestations at scale
- [`docs/integrations/index.md`](index.md) — stack overview
