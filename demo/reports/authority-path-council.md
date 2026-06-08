# Authority Path council note

## Decision

Make `Authority Path` the taudit language. Treat `Developer Tool Authority Path` as a named lens or demo/checklist, not a separate product until non-CI inputs become first-class.

Product verdict:

```text
Current taudit:       Authority Path for CI/CD
Current narrow lens:  exploit/helper-authority path view
Near-roadmap taudit:  declarative developer-tool authority paths
Different product:    endpoint/device enforcement for VS Code extensions, packages, MCP servers, and local agents
```

The shape is taudit. The data source is the boundary. `Developer Tool Authority Path` is not a named current surface in the repo; `Authority Path` is the stronger umbrella.

## Current taudit

Current taudit is already an authority graph analyzer for CI/CD. It parses pipeline YAML into nodes for steps, secrets, identities, images, and artifacts, then evaluates graph predicates over authority propagation.

Demoable today:

- mutable or unpinned GitHub Actions receiving secrets
- broad `GITHUB_TOKEN` permissions
- OIDC-enabled jobs with no provenance evidence
- artifact movement across trust boundaries
- self-hosted runner and PR authority paths
- terminal findings plus JSON, DOT, Mermaid, and summary graph exports

Observed repo evidence:

- `README.md`: taudit is explicitly positioned as a CI/CD authority graph analyzer; the graph is the product.
- `USERGUIDE.md`: documents `scan`, `map`, `graph`, `verify`, Mermaid/DOT/JSON/summary exports.
- `docs/authority-graph.md`: defines the canonical graph model and export contract.
- `docs/rules/unpinned_action.md`: covers mutable GitHub Action refs.
- `docs/rules/untrusted_with_authority.md`: covers untrusted steps with direct secret/identity access.
- `docs/rules/authority_propagation.md`: covers authority crossing into lower-trust sinks.
- `docs/adr/0006-exploit-path-view-and-ruleset.md`: already frames path-shaped views as projections over the canonical authority graph.
- `crates/taudit-cli/src/main.rs`: current `graph` surface supports `--view authority|exploit` and `--format json|dot|mermaid|summary`.
- `schemas/exploit-graph.v1.json`: exploit-path output is a deterministic projection contract, not a proof of exploitation.

This means the demo should not sound like a new product invented overnight. It should sound like taudit showing a current, concrete slice of a broader authority-path thesis.

The better wording is:

```text
taudit finds and exports CI/CD authority paths: deterministic graph-backed
paths showing how secrets, tokens, identities, artifacts, and helper
invocations can carry authority across trust boundaries.
```

## Near-roadmap taudit

The proposed `Authority Path` primitive fits taudit if it stays graph-native:

- executable principal
- identity / mutability / trust boundary
- execution context
- inherited authority
- evidence trail
- rotation set

Each checklist answer should become graph nodes and edges, not prose only.

Recommended object:

```text
ExecutablePrincipal
  kind: ci_action | reusable_workflow | shell_step | container_image |
        package_script | vscode_extension | mcp_server | ai_agent | internal_tool
  identity: owner, publisher, repo/name, version/ref, digest/sha, source_url
  mutability: immutable_sha | digest | tag | branch | semver | latest | auto_update | unknown
  trust_boundary: first_party | same_org | approved_vendor | public_third_party | unknown_third_party
  execution_context: runner | self_hosted_runner | developer_laptop | codespace | devcontainer
  inherited_authority: files, repos, secrets, tokens, oidc, cloud_roles, package_publish, deploy, signing, network
  evidence: workflow_logs, audit_logs, egress_logs, endpoint_logs, provenance, attestations
  rotation_set: tokens, secrets, sessions, cloud roles, artifacts, packages, releases
```

Recommended edge family:

```text
runs_as
can_read_file
can_write_file
can_use_token
can_read_secret
can_assume_role
can_write_repo
can_publish_package
can_deploy_environment
can_call_network
produces_artifact
artifact_consumed_by
observed_by
requires_rotation_of
crosses_trust_boundary
```

Flagship rule family:

```text
mutable executable + trust-boundary crossing + inherited high authority = deny / critical
```

High authority includes secrets, write tokens, OIDC, production deploy, package publish, release/signing authority, privileged artifact handoff, and self-hosted runner reach.

## Not current taudit

taudit does not currently inspect a developer laptop, installed VS Code extension inventory, MCP server runtime environment, endpoint telemetry, browser tokens, SSH agent contents, or actual network egress.

Those are candidate future inputs into the graph, not current claims.

This is where adjacent products live:

- Aikido-style device/package/extension blocking: endpoint enforcement and feed-backed install policy.
- EDR/XDR: process, file, network, and host telemetry after execution.
- Enterprise VS Code controls: publisher/extension/version allowlists and private marketplace policy.
- Secrets platforms: rotation workflow and credential inventory.
- CNAPP/cloud IAM: actual cloud role reach and cloud-side evidence.

taudit should integrate or consume evidence from these surfaces. It should not pretend static CI YAML analysis can observe them directly.

## Same-day demo scope

Use the current demo workflow as the product proof:

```text
vendor/deploy-action@v2
  -> mutable third-party executable
  -> GITHUB_TOKEN with contents/packages/id-token write
  -> PROD_API_KEY / RELEASE_TOKEN / CLOUD_DEPLOY_TOKEN
  -> release-bundle artifact
  -> production environment
```

Use `graphs/summary.json` for the executive readout:

```text
boundary_path_count: 8
distinct_authority_sources: 4
distinct_sinks: 5
top sink: vendor/deploy-action@v2, 4 paths
graph_completeness: complete
```

Use `reports/scan.txt` for the operator readout:

```text
11 critical
2 high
7 medium
1 low
```

The pitch is not "we detected a bad extension." The pitch is "we can show hidden authority paths before they become incident response."

## Future capability path

Phase 1: name and package the lens.

- Add documentation and examples for `Authority Path`.
- Keep CLI unchanged: `scan`, `map`, `graph`, `summary`.
- Use CI/CD examples only.

Phase 2: add declarative non-CI intake.

- `taudit path ingest developer-tool.yml`
- manual/declarative records for VS Code extensions, MCP servers, agents, package scripts
- no endpoint claims; everything is user-supplied or imported evidence

Phase 3: connect evidence sources.

- VS Code enterprise extension allowlists
- GitHub organization action policies
- GitHub audit logs and workflow logs
- package lockfiles and SBOMs
- endpoint/egress evidence from partner tools

Phase 4: enforce through policy.

- deny mutable third-party executable code when authority is high
- require immutable identity for authority-bearing execution
- require rotation-set definition for authority-bearing tool paths
- require evidence for production deployment paths

## Metrics

Track value with outcome measures:

- time to map one workflow path
- number of hidden authority paths surfaced
- number of mutable high-authority executables found
- false-positive rate after customer review
- time to produce a rotation set
- percentage of privileged paths with usable evidence
- number of remediations that split trust domains without breaking workflow

## Recommended wording

Say:

> The GitHub incident demonstrates the same structural failure taudit is built to expose in CI/CD and agentic developer workflows: trusted environments can delegate real authority to mutable executable code. taudit maps that inherited authority and turns it into evidence and policy.

Avoid:

> taudit would have prevented the GitHub incident.
