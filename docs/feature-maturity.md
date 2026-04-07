# Feature Maturity Assessment

Every feature classified by current state, what MVP means, and the path to production quality.

**Legend:**
- **Current** -- honest assessment of what exists today
- **MVP** -- minimum to ship with confidence
- **AAA** -- fully polished, competitive with commercial tools

---

## Core Domain (taudit-core)

### Authority Graph

| | Status |
|---|---|
| **Current** | SOLID. Typed nodes (Step, Secret, Artifact, Identity, Image), typed edges (HasAccessTo, Produces, Consumes, UsesImage, DelegatesTo), TrustZone annotations (FirstParty, ThirdParty, Untrusted). Metadata on nodes. Full serialization via serde. 2 unit tests. |
| **MVP** | Ship as-is. |
| **AAA** | Adjacency index for large graphs (currently linear scan -- fine for pipeline scale). Graph diffing between pipeline versions. Subgraph extraction per job. |

### Propagation Engine

| | Status |
|---|---|
| **Current** | SOLID. BFS from every authority source (Secret + Identity). Configurable max_hops (default 4). PropagationPath with full edge ID vector. Trust boundary crossing detection. 4 unit tests. |
| **MVP** | Ship as-is. |
| **AAA** | Isolation boundary support (explicit breaks in propagation). Weighted edges (risk scoring). Cycle detection. |

### Analysis Rules

| | Status |
|---|---|
| **Current** | SOLID. 5 MVP rules implemented: AuthorityPropagation (severity-graduated), OverPrivilegedIdentity, UnpinnedAction (deduplicated), UntrustedWithAuthority, ArtifactBoundaryCrossing. Sorted by severity. 4 unit tests. |
| **MVP** | Ship as-is. |
| **AAA** | 4 stretch rules: EgressBlindspot, MissingAuditTrail, FloatingImage, LongLivedCredential. Custom rule loading. Policy-as-code (YAML rule definitions). |

### Finding & Recommendation Model

| | Status |
|---|---|
| **Current** | SOLID. 5 severity levels. 9 finding categories (5 MVP + 4 stretch). 6 recommendation variants routing to tsafe, CellOS, or manual action. PropagationPath as first-class path evidence. |
| **MVP** | Ship as-is. |
| **AAA** | SARIF output for GitHub code scanning integration. Confidence scoring. Finding suppression (`.tauditignore`). |

---

## Parsers

### GitHub Actions (taudit-parse-gha)

| | Status |
|---|---|
| **Current** | SOLID. Parses workflow/job-level permissions, step `uses:`/`run:`, secret references in `env:` and `with:` blocks. Trust zone classification (local = FirstParty, SHA-pinned = ThirdParty, tag-pinned = Untrusted). 7 unit tests. |
| **MVP** | Ship as-is. |
| **AAA** | Reusable workflow support (`workflow_call`). Composite action parsing. Matrix strategy awareness. Expression evaluation (`${{ github.event_name }}`). Trigger-based trust classification (pull_request_target = untrusted). |

### Azure DevOps (taudit-parse-ado)

| | Status |
|---|---|
| **Current** | Not implemented. Stretch target. |
| **MVP** | Basic YAML pipeline parsing: stages, jobs, steps, service connections. |
| **AAA** | Template expansion. Variable groups. Environment approvals as isolation boundaries. |

### GitLab CI (taudit-parse-gitlab)

| | Status |
|---|---|
| **Current** | Not implemented. Stretch target. |
| **MVP** | Basic `.gitlab-ci.yml` parsing: stages, jobs, secrets, images. |
| **AAA** | `include:` template resolution. Protected branch rules as trust boundaries. |

---

## Report Adapters

### Terminal Report (taudit-report-terminal)

| | Status |
|---|---|
| **Current** | SOLID. Coloured severity labels, graph summary header, propagation path visualization with arrows, green fix recommendations. |
| **MVP** | Ship as-is. |
| **AAA** | `--quiet` mode (summary only). `--verbose` mode (full node metadata). `--no-color` flag. |

### JSON Report (taudit-report-json)

| | Status |
|---|---|
| **Current** | SOLID. Full authority graph + findings + summary. Pretty-printed. JSON Schema in contracts/schemas/. |
| **MVP** | Ship as-is. |
| **AAA** | JSON Schema CI validation. Stable schema versioning. SARIF output adapter. |

### CloudEvents Sink (taudit-sink-cloudevents)

| | Status |
|---|---|
| **Current** | Not implemented. Stretch target. |
| **MVP** | Findings as CloudEvents JSONL to stdout or file. |
| **AAA** | Direct JetStream/Kafka publish. Correlation with CellOS execution events. |

---

## CLI (taudit-cli)

### `taudit scan`

| | Status |
|---|---|
| **Current** | SOLID. Clap CLI. Directory walking for .yml/.yaml. Terminal and JSON output formats. Configurable --max-hops. Exit code 1 on findings. |
| **MVP** | Ship as-is. |
| **AAA** | `--exclude` glob patterns. `--severity-threshold` (exit 1 only for critical). `--baseline` file (suppress known findings). Watch mode. |

### `taudit map` (stretch)

| | Status |
|---|---|
| **Current** | Not implemented. |
| **MVP** | Authority map table: who gets what (step x secret/identity matrix). |
| **AAA** | Interactive TUI. Graphviz DOT export. |

### `taudit diff` (stretch)

| | Status |
|---|---|
| **Current** | Not implemented. |
| **MVP** | Before/after authority graph diff between pipeline versions. |
| **AAA** | Git integration (diff between commits). PR comment bot. |

---

## Infrastructure

### CI Pipeline

| | Status |
|---|---|
| **Current** | SOLID. quality.yml with SHA-pinned actions, fmt + clippy + test + deny + contract validation. |
| **MVP** | Ship as-is. |
| **AAA** | Release workflow with multi-platform binaries. cargo-audit. Fuzzing. |

### Supply Chain

| | Status |
|---|---|
| **Current** | SOLID. deny.toml with license allowlist, yanked advisory check, source verification. Dependabot for actions + cargo. |
| **MVP** | Ship as-is. |
| **AAA** | SBOM generation. Signed releases. |

---

## Summary: What to Ship

### Ship Now (MVP -- already solid)

1. Authority graph with typed nodes, edges, trust zones
2. BFS propagation engine with configurable depth
3. 5 analysis rules with severity graduation and deduplication
4. Finding model with path evidence and remediation routing
5. GitHub Actions parser with trust zone classification
6. Terminal report with coloured output and propagation paths
7. JSON report with schema
8. CLI with scan command, format selection, exit codes
9. CI pipeline, deny.toml, Dependabot
10. Test fixtures + 17 unit tests

### Next (high-impact stretch)

| Priority | Feature | Impact |
|----------|---------|--------|
| 1 | Finding suppression (`.tauditignore`) | Reduces noise for known-accepted risks |
| 2 | `taudit map` (authority matrix) | Visual "who gets what" for security review |
| 3 | Reusable workflow / composite action parsing | Real-world GHA coverage |
| 4 | Azure DevOps parser | Second platform |
| 5 | SARIF output | GitHub code scanning integration |
| 6 | Stretch rules (egress, audit trail, floating image, long-lived cred) | Deeper analysis |
| 7 | `taudit diff` | PR-time authority change detection |
| 8 | CloudEvents sink | CellOS observability integration |
