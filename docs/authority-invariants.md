# Authority Invariants

CI/CD is an untyped authority system. Pipelines hand secrets and identities
across trust boundaries with no compile-time check, no schema, no type
system to catch the moment a production token reaches a tag-pinned action.
**Authority invariants are the types you assert.** Each one is a
declarative property the authority graph must satisfy; taudit emits a
finding for every propagation path that violates one.

taudit ships **61 built-in invariants** covering the common shapes
(propagation across trust boundaries, broad scopes, unpinned actions,
PR-context exposure, persisted credentials, etc.). On top of those, you
can write **custom authority invariants** as YAML files and load them with
`--invariants-dir` to encode policy that is specific to your organisation.

> The mechanism was previously called *custom rules* and is loaded via
> `--rules-dir`. Both names work — `--invariants-dir` is the new spelling
> and the docs use it; `--rules-dir` remains as an alias forever.

## Quick start

Copy the [starter library](../invariants/starter/), edit one or two
metadata predicates to match your tagging scheme, and run:

```bash
taudit scan --invariants-dir invariants/starter .github/workflows/

# Verify which invariants are active
taudit invariants list --invariants-dir invariants/starter
```

## How it works

When you pass `--invariants-dir ./invariants/` to `taudit scan`, taudit:

1. Reads every `*.yml` and `*.yaml` file in the directory in sorted order
   (deterministic output).
2. Parses each file into one invariant definition.
3. Runs the built-in propagation engine to generate every authority path in
   the graph.
4. Evaluates your invariants against those paths — the same paths the
   built-in invariants use.
5. Emits violations alongside the built-in findings in whatever output
   format you chose (terminal / JSON / SARIF / CloudEvents).

Custom-invariant findings are indistinguishable from built-in findings in
SARIF, JSON, and terminal output — except that the message includes the
invariant id in brackets (e.g., `[my_invariant_id] Name: source -> sink`).

Custom invariants **complement** the built-in ones; both run on every
`taudit scan` invocation.

## Invariant file format

Each YAML file declares one invariant. All top-level fields are required
except `description`. Match predicates under `match:` are all optional —
an absent predicate matches everything (wildcard).

```yaml
# Required — unique identifier. Appears in SARIF rule entries, terminal
# output, and the finding message. Use snake_case.
id: my_prod_identity_to_untrusted

# Required — human-readable name.
name: Production identity reaching untrusted step

# Optional — shown as the manual remediation action in findings. If absent,
# the recommendation reads "Review custom rule '<id>'".
description: "Production-tagged identities must not reach untrusted code paths"

# Required — severity of findings emitted by this invariant.
# Valid: critical, high, medium, low, info
severity: critical

# Required — maps the finding to a built-in category for SARIF rule
# metadata and reporting. Valid values listed below.
category: authority_propagation

# Optional — match predicates. ANDed together. An absent predicate is a
# wildcard.
match:
  source:
    # Optional. Valid: secret, identity, step, artifact, image
    node_type: identity

    # Optional. Valid: first_party, third_party, untrusted
    trust_zone: first_party

    # Optional. Require ALL listed key/value pairs in the node's metadata.
    metadata:
      environment: production

  sink:
    node_type: step
    trust_zone: untrusted
    metadata: {}

  path:
    # Optional. Path must cross into one of these zones. Empty/absent =
    # match all paths regardless of crossing.
    crosses_to:
      - untrusted
```

## Predicate reference

### `source` and `sink`

| Field | Type | Effect |
|-------|------|--------|
| `node_type` | string | Match only nodes of this kind. |
| `trust_zone` | string | Match only nodes in this trust zone. |
| `metadata` | map | Match only nodes whose metadata contains ALL listed key/value pairs. |

`source` and `sink` match the source and sink of a propagation path. A path
has exactly one source (the authority origin — Secret or Identity) and one
sink (the endpoint — typically a Step).

### `path.crosses_to`

When present and non-empty, the path must cross a trust boundary into one
of the listed zones. A path "crosses" when the propagation traversal moves
from a higher-trust zone into one of the listed zones. Empty list or
absent `path:` matches every path.

### Wildcards

Any absent predicate field matches everything. An invariant with no
`match:` block at all fires on every propagation path in the graph — use
this only for policy-wide auditing.

## Valid values

### NodeKind (`node_type`)

| Value | Description |
|-------|-------------|
| `secret` | Pipeline secret (GitHub secret, ADO variable group secret, inline variable). |
| `identity` | Runtime identity (GITHUB_TOKEN, ADO service connection, cloud federated identity). |
| `step` | Pipeline step or task. |
| `artifact` | Build artifact produced and consumed by steps. |
| `image` | Action reference (`uses:`) or container image. |

### TrustZone (`trust_zone`, `crosses_to`)

| Value | Description |
|-------|-------------|
| `first_party` | Code in your own organisation/repo — trusted. |
| `third_party` | External code, SHA-pinned — immutable but cross-boundary. |
| `untrusted` | External code without SHA pinning, or PR-context code — not fully controlled. |

### FindingCategory (`category`)

| Value |
|-------|
| `authority_propagation` |
| `over_privileged_identity` |
| `unpinned_action` |
| `untrusted_with_authority` |
| `artifact_boundary_crossing` |
| `floating_image` |
| `long_lived_credential` |
| `persisted_credential` |
| `trigger_context_mismatch` |
| `cross_workflow_authority_chain` |
| `authority_cycle` |
| `uplift_without_attestation` |
| `self_mutating_pipeline` |
| `checkout_self_pr_exposure` |
| `variable_group_in_pr_job` |
| `self_hosted_pool_pr_hijack` |
| `service_connection_scope_mismatch` |

## Examples from the starter library

The five files in [`invariants/starter/`](../invariants/starter/) illustrate
the predicate vocabulary on real-world shapes:

- **`no-untrusted-with-prod-secret.yml`** — `source.metadata.environment:
  production` + `sink.trust_zone: untrusted` + `path.crosses_to:
  [untrusted]`. The canonical "no production secret reaches code I don't
  control" invariant.
- **`no-broad-identity-to-untrusted.yml`** — `source.node_type: identity` +
  `source.metadata.identity_scope: broad` + `sink.trust_zone: untrusted`.
  Uses the parser-set `identity_scope: broad` metadata so it works on any
  GHA or ADO graph out of the box.
- **`no-untrusted-image-with-secret.yml`** — `source.node_type: secret` +
  `sink.trust_zone: untrusted`. The dual of the built-in `floating_image`
  rule, framed from the secret side.
- **`prefer-oidc-over-static-secrets.yml`** — pure source predicate
  (`source.node_type: secret` + `source.metadata.environment: production`)
  with no sink or path filter. Demonstrates a wildcard-sink invariant —
  fires for the *existence* of the source, not for any particular path.
- **`no-third-party-step-with-identity.yml`** — `source.node_type:
  identity` + `sink.node_type: step` + `sink.trust_zone: third_party`.
  A stricter posture than the built-ins: forbids identity propagation into
  any third-party code, even SHA-pinned.

## Inspecting active invariants

```bash
# Every invariant taudit will run on the next scan — built-ins plus custom.
taudit invariants list --invariants-dir invariants/starter
```

Output is a plain-text three-column table: `id`, `severity`, `source`. The
`source` column is `built-in` for shipped invariants and the YAML file path
for custom ones. Use this in CI to assert that your policy directory is
loaded correctly before proceeding.

## SARIF output

In SARIF output, custom invariants appear as dynamic rule entries in the
`driver.rules` array alongside the built-ins. Each custom entry uses:

- `id`: the `id` field from your YAML
- `name`: the `name` field
- `shortDescription.text`: the `name` (or `description` if name is absent)
- `fullDescription.text`: the `description` field
- `defaultConfiguration.level`: derived from `severity`
  (`critical`/`high` → `error`, `medium` → `warning`, `low`/`info` → `note`)
- `properties.tags`: inherited from the built-in category's tag list

This makes custom invariant findings compatible with GitHub Code Scanning,
Azure DevOps SARIF upload, and any other SARIF-aware security tool.

## Error handling

taudit reports parse errors per file and exits non-zero. Files with invalid
YAML or unknown field values (e.g., an unrecognised severity) are not
silently ignored — they halt the scan so you know your policy is not being
applied.

```bash
taudit scan --invariants-dir ./invariants/ pipeline.yml 2>&1 | grep "failed to parse"
```

The error message includes the file path and the specific parse failure
location.

## Semver guarantee

The custom-invariant YAML schema is part of taudit's public API. Field
names, valid values, and matching semantics will not change in
backwards-incompatible ways within a major version. New optional fields
may be added; existing invariants will continue to load and evaluate as
they always did.
