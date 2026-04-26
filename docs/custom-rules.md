# Custom Rules → Authority Invariants

> **This page has moved.** Custom rules have been renamed to **authority
> invariants** — same mechanism, sharper framing. The full reference now
> lives at [`docs/authority-invariants.md`](./authority-invariants.md).

## TL;DR

- The mechanism is unchanged: YAML files in a directory, one invariant per
  file, evaluated against propagation paths alongside the 17 built-ins.
- The CLI flag has been renamed: `--invariants-dir` is the new spelling.
  `--rules-dir` is preserved as an alias and will keep working
  indefinitely.
- A new subcommand, `taudit invariants list [--invariants-dir <path>]`,
  prints every loaded invariant (built-in plus custom) so you can verify
  your policy is wired up.
- A starter library of five real, copy-and-edit invariants ships in
  [`invariants/starter/`](../invariants/starter/).

## Where to read

- **Concept and schema** → [`docs/authority-invariants.md`](./authority-invariants.md)
- **Examples to copy** → [`invariants/starter/`](../invariants/starter/)
- **Built-in invariants** → [`docs/rules/index.md`](./rules/index.md)

## Why the rename

CI/CD is an untyped authority system. "Authority invariants" names what
these declarations actually are — properties the authority graph must
satisfy — rather than the generic-engineering term "rules." The new name
also sharpens the relationship to the built-in checks: every check, custom
or shipped, is an invariant the graph either satisfies or violates.

The underlying file format, evaluation semantics, and SARIF output are all
unchanged. Existing `--rules-dir` invocations and existing YAML files keep
working without modification.

## Rule File Format

Each YAML file defines one rule. All fields at the top level are required except `description`. Match predicates under `match:` are all optional — an absent predicate matches everything (wildcard).

```yaml
# Full schema — every field documented

# Required — unique identifier for this rule. Appears in SARIF rule entries,
# terminal output, and the finding message. Use snake_case.
id: my_prod_identity_to_untrusted

# Required — human-readable name for the rule.
name: Production identity reaching untrusted step

# Optional — shown as the manual remediation action in findings.
# If absent, the recommendation reads "Review custom rule '<id>'".
description: "Production-tagged identities must not reach untrusted code paths"

# Required — severity of findings emitted by this rule.
# Valid values: critical, high, medium, low, info
severity: critical

# Required — maps the finding to a built-in category for SARIF rule metadata
# and reporting. Use any built-in category id.
# Valid values listed below.
category: authority_propagation

# Optional — match predicates. All predicates are ANDed together.
# An absent predicate matches everything (wildcard).
match:
  source:
    # Optional — require the source node to be this kind.
    # Valid values: secret, identity, step, artifact, image
    node_type: identity

    # Optional — require the source node to be in this trust zone.
    # Valid values: first_party, third_party, untrusted
    trust_zone: first_party

    # Optional — require the source node's metadata to contain ALL of these
    # key/value pairs. Absent = wildcard (match any metadata).
    metadata:
      environment: production

  sink:
    # Optional — require the sink node to be this kind.
    node_type: step

    # Optional — require the sink node to be in this trust zone.
    trust_zone: untrusted

    # Optional — require the sink node's metadata to contain all key/value pairs.
    metadata: {}

  path:
    # Optional — require the propagation path to cross into one of these trust zones.
    # If the list is empty (or the field is absent), all paths match regardless of
    # whether they cross a boundary at all.
    # Valid values: first_party, third_party, untrusted
    crosses_to:
      - untrusted
```

## Match Predicates

Predicates narrow which propagation paths fire a finding. All predicates are optional and independent — any combination is valid.

### `source` and `sink` predicates

| Field | Type | Effect |
|-------|------|--------|
| `node_type` | string OR list of strings | Matches nodes of this kind (or any kind in the list) |
| `trust_zone` | string OR list of strings | Matches nodes in this trust zone (or any zone in the list) |
| `metadata` | map | Matches nodes whose metadata satisfies ALL listed predicates (see operators below) |
| `not` | sub-matcher | Inverts the inner sub-matcher. Matches when the inner does NOT match |

`source` and `sink` predicates match the source and sink nodes of a propagation path respectively. A path has exactly one source (the authority origin — a secret or identity) and one sink (the endpoint — typically a step).

### `path.crosses_to` predicate

When present and non-empty, the path must cross a trust boundary into one of the listed zones. A path "crosses" when the propagation traversal moves from a higher-trust zone to one of the listed zones. If the list is empty or `path:` is absent, all paths match.

### Absent predicate = wildcard

Any absent predicate field matches everything. A rule with no `match:` block at all fires on every propagation path in the graph — use this only for policy-wide auditing.

### Negation (`not:`)

Wrap any sub-matcher in `not:` to invert it. Available on `source`, `sink`, and inside `metadata`.

```yaml
match:
  source:
    not:
      trust_zone: untrusted        # source is anything OTHER than untrusted

  sink:
    not:
      node_type: [secret, identity]  # sink is anything OTHER than a secret/identity

  source:
    metadata:
      not:
        oidc: "true"               # match nodes whose oidc field is absent or != "true"
```

Nested `not` is allowed and double-negation collapses naturally: `not: { not: X }` ≡ `X`.

### Typed metadata predicates

A metadata field may be a bare string (equality, back-compat) or an operator object:

| Operator | Type | Semantics |
|----------|------|-----------|
| `equals` | string | Field must equal this value exactly (same as bare string) |
| `not_equals` | string | Field must be absent OR not equal to this value |
| `contains` | string | Field must be present and contain this substring |
| `in` | list of strings | Field must be present and equal one of the listed values |

```yaml
match:
  source:
    metadata:
      identity_scope:
        equals: broad
      permissions:
        contains: "contents: write"
      role:
        in: [admin, owner, write]
      environment:
        not_equals: development
```

All operators on the same field are ANDed. Unknown operator names cause a parse error so typos do not silently match nothing.

### Multi-value `node_type` / `trust_zone`

Both fields accept either a single value or a list. The list form matches if the node is any of the listed kinds/zones (any-of semantics).

```yaml
match:
  source:
    node_type: [secret, identity]   # any authority-bearing source
  sink:
    trust_zone: [third_party, untrusted]   # any boundary-crossing sink
```

The single-value form (`node_type: secret`) continues to work unchanged.

## Valid Values

### NodeKind (`node_type`)
| Value | Description |
|-------|-------------|
| `secret` | A pipeline secret (GitHub secret, ADO variable group secret, inline variable) |
| `identity` | A runtime identity (GITHUB_TOKEN, ADO service connection, cloud federated identity) |
| `step` | A pipeline step or task |
| `artifact` | A build artifact produced and consumed by steps |
| `image` | An action reference (`uses:`) or container image |

### TrustZone (`trust_zone`, `crosses_to`)
| Value | Description |
|-------|-------------|
| `first_party` | Code in your own organisation/repo — trusted |
| `third_party` | External code, SHA-pinned — immutable but cross-boundary |
| `untrusted` | External code without SHA pinning, or PR-context code — not fully controlled |

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

## Full Working Example

This rule fires when any identity tagged with `environment: production` in its metadata reaches an untrusted step, regardless of how many hops the propagation takes.

```yaml
# rules/prod-identity-to-untrusted.yml
id: prod_identity_to_untrusted
name: Production identity reaching untrusted step
description: >
  Identities tagged for production use must not propagate to untrusted
  execution contexts. If this fires, trace the propagation path and
  remove the identity from any step in an untrusted trust zone.
severity: critical
category: authority_propagation
match:
  source:
    node_type: identity
    trust_zone: first_party
    metadata:
      environment: production
  sink:
    node_type: step
    trust_zone: untrusted
  path:
    crosses_to:
      - untrusted
```

Save this file as `./rules/prod-identity-to-untrusted.yml` and run:

```bash
taudit scan --rules-dir ./rules/ your-pipeline.yml
```

When the rule fires, the terminal output shows:

```
[CRITICAL] prod_identity_to_untrusted — Production identity reaching untrusted step
  [prod_identity_to_untrusted] Production identity reaching untrusted step: PROD_DEPLOY_IDENTITY -> some-third-party-action
  Action: Identities tagged for production use must not propagate to untrusted execution contexts...
```

## Usage

```bash
# Scan with custom rules
taudit scan --rules-dir ./rules/ .github/workflows/ci.yml

# Scan a directory of pipelines with custom rules
taudit scan --rules-dir ./org-rules/ .github/workflows/

# Combined with other flags
taudit scan \
  --rules-dir ./rules/ \
  --format sarif \
  --output results.sarif \
  .github/workflows/
```

Files that fail to parse are reported as errors. taudit exits non-zero if any file in the rules directory cannot be parsed — add `--ignore` entries in your `.tauditignore` if you want to suppress specific built-in findings alongside custom ones.

## SARIF Output

In SARIF output, custom rules appear as dynamic rule entries in the `driver.rules` array alongside the built-in rules. Each custom rule entry uses:
- `id`: the `id` field from your YAML
- `name`: the `name` field from your YAML
- `shortDescription.text`: the `name` field (or description if name is absent)
- `fullDescription.text`: the `description` field
- `defaultConfiguration.level`: derived from `severity` (`critical`/`high` → `error`, `medium` → `warning`, `low`/`info` → `note`)
- `properties.tags`: inherited from the built-in category's tag list

This makes custom rule findings compatible with GitHub Code Scanning, Azure DevOps SARIF upload, and any SARIF-aware security tool.

## Error Handling

taudit reports parse errors for each invalid rule file and exits non-zero. Files with invalid YAML or unknown field values (e.g., an unrecognised severity) are not silently ignored — they halt the scan so you know your policy is not being applied.

To debug a failing rule file:

```bash
taudit scan --rules-dir ./rules/ pipeline.yml 2>&1 | grep "failed to parse"
```

The error message includes the file path and the specific parse failure location.
