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
| **Current** | SOLID. Typed nodes (Step, Secret, Artifact, Identity, Image), typed edges (HasAccessTo, Produces, Consumes, UsesImage, DelegatesTo), TrustZone annotations (FirstParty, ThirdParty, Untrusted). Metadata on nodes. Full serialization via serde. 5 unit tests. |
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
| **Current** | SOLID. 5 MVP rules + 2 stretch rules (`LongLivedCredential`, `FloatingImage`). AuthorityPropagation (severity-graduated), OverPrivilegedIdentity, UnpinnedAction (deduplicated), UntrustedWithAuthority, ArtifactBoundaryCrossing. Sorted by severity. 14 unit tests. |
| **MVP** | Ship as-is. |
| **AAA** | 2 remaining stretch rules: EgressBlindspot and MissingAuditTrail. Custom rule loading. Policy-as-code (YAML rule definitions). |

### Finding & Recommendation Model

| | Status |
|---|---|
| **Current** | SOLID. 5 severity levels. 9 finding categories (5 MVP + 4 stretch). 6 recommendation variants routing to tsafe, CellOS, or manual action. PropagationPath as first-class path evidence. Ignore and baseline suppression are implemented at the CLI layer. |
| **MVP** | Ship as-is. |
| **AAA** | Confidence scoring. Richer suppression management beyond `.tauditignore` and baseline reports. |

---

## Parsers

### GitHub Actions (taudit-parse-gha)

| | Status |
|---|---|
| **Current** | SOLID. Parses workflow/job-level permissions, step `uses:`/`run:`, secret references in `env:` and `with:` blocks. Trust zone classification (local = FirstParty, SHA-pinned = ThirdParty, tag-pinned = Untrusted) plus trigger-based `pull_request_target` handling for `run:` steps. |
| **MVP** | Ship as-is. |
| **AAA** | Reusable workflow support (`workflow_call`). Composite action parsing. Matrix strategy awareness. Expression evaluation (`${{ github.event_name }}`). Deeper trigger-aware modelling beyond basic `pull_request_target` support. |

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
| **Current** | SOLID. Coloured severity labels, graph summary header, propagation path visualization with arrows, green fix recommendations, `--verbose` node metadata output, and `--no-color` support with automatic tty detection. |
| **MVP** | Ship as-is. |
| **AAA** | Further presentation polish for large reports and richer terminal summarisation. |

### JSON Report (taudit-report-json)

| | Status |
|---|---|
| **Current** | SOLID. Full authority graph + findings + summary. Pretty-printed. JSON Schema in contracts/schemas/. |
| **MVP** | Ship as-is. |
| **AAA** | JSON Schema CI validation. Stable schema versioning. |

### SARIF Report (taudit-report-sarif)

| | Status |
|---|---|
| **Current** | SOLID. Emits SARIF 2.1.0 logs with rule catalogue, severity mapping, and source-file locations for code scanning ingestion. |
| **MVP** | Ready for repo-level validation in GitHub code scanning. |
| **AAA** | Schema validation in CI. Rule help pages linked to stable public docs. |

### CloudEvents Sink (taudit-sink-cloudevents)

| | Status |
|---|---|
| **Current** | SOLID. Hand-rolled CloudEventV1 envelope with taudit-specific and shared-envelope schema validation. One JSONL line per finding. Type prefix `io.taudit.finding.{category}`. Correlation and provenance fields included. 13 unit tests. |
| **MVP** | Ship as-is. |
| **AAA** | Direct JetStream/Kafka publish. Correlation with CellOS execution events. Governance correlation ID extension attribute. |

---

## CLI (taudit-cli)

### `taudit scan`

| | Status |
|---|---|
| **Current** | SOLID. Clap CLI. Directory walking for .yml/.yaml. Terminal, JSON, SARIF, and CloudEvents output formats. Configurable `--max-hops`, `--severity-threshold`, `--exclude`, `--baseline`, `--quiet`, `--verbose`, and `--no-color`. Exit code 1 on actionable findings. |
| **MVP** | Ship as-is. |
| **AAA** | Watch mode. Additional output shaping for larger monorepos. |

### `taudit map`

| | Status |
|---|---|
| **Current** | SOLID. Authority map table: step x authority matrix with trust zone annotations. 2 unit tests. |
| **MVP** | Ship as-is. |
| **AAA** | Interactive TUI. Graphviz DOT export. |

### `taudit diff`

| | Status |
|---|---|
| **Current** | SOLID. Before/after authority graph diff between two workflow files with terminal and JSON output. |
| **MVP** | Ship as-is. |
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
10. CloudEvents JSONL sink with JSON Schema contract
11. Authority map command
12. SARIF output adapter for code scanning ingestion
13. Finding suppression via `.tauditignore`, baseline, and severity threshold
14. `taudit diff` command with terminal and JSON output
15. LongLivedCredential and FloatingImage stretch rules
16. Test fixtures + 86 tests across workspace crates

### Next (high-impact stretch)

| Priority | Feature | Impact |
|----------|---------|--------|
| 1 | Reusable workflow / composite action parsing | Real-world GHA coverage |
| 2 | Azure DevOps parser | Second platform |
| 3 | Stretch rules (egress, audit trail) | Deeper analysis |
| 4 | Governance correlation schema | Cross-tool event linking (taudit/tsafe/CellOS) |
| 5 | Git-integrated diffing and PR automation | Makes `taudit diff` useful in review workflows |
