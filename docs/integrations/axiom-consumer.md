# axiom — Enforcement Consumer

> axiom is a sibling project (not yet released). It is the **enforcement
> brain** of the stack. It consumes signed authority-graph attestations
> from many repos and emits per-PR / per-deploy decisions backed by an
> auditable chain. This document specifies the contracts axiom should
> implement.

`taudit verify --policy <FILE_OR_DIR>` is the local-only flavour of
what axiom does at scale. Same invariant DSL, same exit-code semantics
([`docs/verify.md`](../verify.md)) — axiom adds cross-repo aggregation,
attestation chain validation, and a decision contract external systems
(merge bots, deploy gates) can consume.

## Input contract

Per evaluation, axiom takes:

1. **A signed authority-graph attestation** matching predicate
   `https://taudit.dev/attestations/authority-graph/v0.1`
   ([`tsign-consumer.md`](tsign-consumer.md)). Provides the graph
   digest, source commit, completeness, and taudit version.
2. **The graph itself** — fetched fresh from `taudit graph --format json`
   at the attested commit. axiom rehashes and refuses on mismatch.
3. **Organisational policy** — taudit invariants checked into an axiom
   policy bundle. Format is the same YAML invariant DSL `taudit verify`
   already loads.

The graph schema (`1.x.y`) is the only contract between taudit and
axiom. Add invariants without bumping axiom; bump axiom only when the
schema major changes.

## Cross-repo aggregation

axiom maintains a database keyed by `(repo, pipeline_path)` whose value
is the most recent attested graph digest plus a small derived index:
node-kind counts, identity scopes, trigger types, third-party action
SHAs. The index makes org-wide drift queries cheap without storing
every graph in full.

Concrete drift questions axiom answers from this index:

- "Which 12 repos started using `pull_request_target` last week?"
- "Which pipelines added a new SHA-pinned action whose digest no other
  repo in the org has seen?"
- "Which repos saw their identity scope move from `constrained` to
  `broad` between two attestations?"

The graph digest itself is the strongest aggregation primitive: any
non-trivial pipeline change produces a new digest, so aggregation
across repos is a database `GROUP BY` away.

## Policy layout — proposal v0.1

axiom's working tree is declarative:

```
axiom/
├── policies/
│   ├── default.yml             # default policy applied to all repos
│   └── high-privilege.yml      # stricter policy for prod-deploying repos
├── repos/
│   ├── acme-widgets.yml        # repo → policy binding + overrides
│   └── acme-billing.yml
└── invariants/
    └── no_pr_target_with_secrets.yml   # standard taudit invariant YAML
```

```yaml
# policies/default.yml
version: 0.1
include_builtin: true                    # taudit's 61 built-ins on by default
require:
  - id: no_pr_target_with_secrets
  - id: no_unpinned_actions
on_partial_graph: flag_for_review        # honour graph completeness
on_attestation_missing: block
on_taudit_version_below: "0.9.0"         # refuse stale signers
```

```yaml
# repos/acme-widgets.yml
version: 0.1
repo: github.com/acme/widgets
policy: default
overrides:
  - pipeline: .github/workflows/canary.yml
    policy: high-privilege
```

The runtime evaluator is `taudit verify` itself — axiom is the
orchestrator that resolves policy bindings, fetches attestations,
validates them, and persists decisions.

## Decision contract — proposal v0.1

axiom emits one decision document per evaluation. Schema is versioned
in its envelope so consumers (auto-mergers, deploy gates) can pin.

```json
{
  "decision_schema_version": "0.1.0",
  "decision": "block",
  "subject": {
    "repo": "github.com/acme/widgets",
    "commit_sha": "5b8…",
    "pipeline_path": ".github/workflows/release.yml",
    "pr_number": 482
  },
  "policy_ref": {
    "bundle_commit": "a91…",
    "policy_id": "default"
  },
  "graph": {
    "schema_version": "1.0.0",
    "digest_sha256": "f1c2…",
    "completeness": "complete",
    "taudit_version": "0.9.0"
  },
  "attestation_chain": [
    {
      "predicate_type": "https://taudit.dev/attestations/authority-graph/v0.1",
      "envelope_sha256": "7d…",
      "signer": "https://github.com/acme/widgets/.github/workflows/release.yml@refs/heads/main",
      "verified_at": "2026-04-26T12:01:14Z"
    }
  ],
  "violations": [
    {
      "invariant_id": "no_pr_target_with_secrets",
      "severity": "critical",
      "evidence_ref": "graph://nodes/14"
    }
  ],
  "produced_at": "2026-04-26T12:01:15Z"
}
```

`decision` is one of `allow`, `block`, `flag_for_review`. `violations`
is empty on `allow`. `evidence_ref` points into the attested graph by
node id (the same dense ids the schema uses). External systems gate on
`decision`; humans drill in via `violations` and the attestation
chain.

## What this enables

- **Org-wide pipeline governance as code.** The policy is a directory
  of YAML, not a Slack thread.
- **Replayable audits.** Decisions, attestations, and graphs are all
  hashed and pinned to commits.
- **Tool-agnostic gates.** Any merge bot or deploy controller that can
  read the decision JSON can act on it.

## Open questions

- **taudit version skew.** Repos move at different speeds. Proposal:
  axiom treats `taudit_version` as a minimum-version policy field
  (`on_taudit_version_below`). Older signers are blocked, not silently
  trusted.
- **Emergency overrides.** Real orgs need a break-glass. Proposal:
  overrides are themselves attestations (predicate
  `https://taudit.dev/attestations/policy-override/v0.1`), bound to a
  human signer, with an expiry. The decision JSON records the override
  in `attestation_chain` so audits surface it. Not yet specified.
- **Multi-pipeline repos.** A repo with 30 workflows produces 30
  decisions per commit. Aggregation rules (any-block-blocks,
  weighted-by-pipeline-criticality) are policy concerns and stay out
  of the decision schema.

## See also

- [`docs/verify.md`](../verify.md) — the local enforcement entrypoint
- [`docs/integrations/tsign-consumer.md`](tsign-consumer.md) — the
  attestation contract axiom consumes
- [`docs/integrations/index.md`](index.md) — stack overview
- [`docs/positioning.md`](../positioning.md) — why this layering
