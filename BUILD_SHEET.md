# taudit — Pipeline Authority Scanner

## What You're Building

taudit is a Rust CLI that models **authority propagation** through CI/CD pipelines. Not a scanner — a privilege dataflow analyser.

Existing tools (Checkov, gitleaks, trivy) scan artefacts and flag patterns. taudit builds a **directed graph of how authority flows** across steps, identities, secrets, and trust boundaries — then detects where privilege leaks, accumulates, or crosses into untrusted domains.

**One-liner:** "taudit shows how authority propagates through your pipelines, so you can prove least privilege."

## System Context

taudit is one layer in a closed governance loop: **taudit** (detect over-authority) --> **tsafe** (constrain secrets) --> **CellOS** (contain execution) --> runtime --> **taudit** (re-observe). Authority-scope findings emit `Recommendation::TsafeRemediation`; execution-isolation findings emit `Recommendation::CellosRemediation`. Keep that routing clean.

## Design Constraints

- Rust workspace, single developer, 10-20 hour build budget
- Day-1 value without requiring tsafe or CellOS installed
- Must not reinvent gitleaks (secret scanning), trivy (CVE scanning), or checkov (IaC policy)
- Output: authority graph (JSON) + human-readable report + optional CloudEvents audit stream
- Start with GitHub Actions only. ADO/GitLab are stretch crates, not MVP.
- YAML parsing: use `serde_yaml` (mature, serde-native). GHA YAML is polymorphic (`on:` can be string/list/map, `env:` at workflow/job/step level) — use `serde_yaml::Value` for flexible parsing, then map to typed structs where possible.
- Error handling: `thiserror` for `taudit-core` error enum (typed, no I/O), `anyhow` in `taudit-cli` (composition root, string context ok).

## Crate Architecture

Ports/adapters pattern (see CellOS `EXTENSIBILITY.md` and `cellos-core/src/ports.rs`):

| Crate | Type | Tier | Role |
|-------|------|------|------|
| `taudit-core` | Domain Library | MVP | No I/O. Authority graph, propagation engine, finding rules, traits. |
| `taudit-cli` | Binary | MVP | Clap CLI. Composition root. Wires adapters. |
| `taudit-parse-gha` | Parser Adapter | MVP | GitHub Actions YAML --> authority graph |
| `taudit-report-terminal` | Report Adapter | MVP | Coloured terminal report with propagation paths |
| `taudit-report-json` | Report Adapter | MVP | Structured JSON output |
| `taudit-parse-ado` | Parser Adapter | Stretch | Azure Pipelines YAML --> authority graph |
| `taudit-sink-cloudevents` | Event Adapter | Stretch | Findings --> CloudEvents JSONL |

## Core Domain Model (taudit-core)

### The Authority Graph

Central data structure. Directed graph: typed nodes, typed edges, trust zone annotations.

```rust
pub type NodeId = usize;

pub enum NodeKind { Step, Secret, Artifact, Identity, Image }

pub enum TrustZone {
    FirstParty,   // repo owner's code/config
    ThirdParty,   // marketplace actions, external images (pinned)
    Untrusted,    // unpinned actions, fork PRs, user input
}

pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,
    pub name: String,
    pub trust_zone: TrustZone,
    pub metadata: HashMap<String, String>, // pinning, digest, scope, permissions, etc.
}

/// Edge semantics model authority/data flow, not syntactic YAML relations.
/// "Can authority propagate along this edge?" is the design test.
pub enum EdgeKind {
    HasAccessTo,   // step -> secret or identity (authority granted)
    Produces,      // step -> artifact (data flows out)
    Consumes,      // step -> artifact (data flows in)
    UsesImage,     // step -> image/action (execution delegation)
    DelegatesTo,   // step -> step (cross-job/action boundary)
}

pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
}

pub struct AuthorityGraph {
    pub source: PipelineSource,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

pub struct PipelineSource {
    pub file: String,
    pub repo: Option<String>,
    pub git_ref: Option<String>,  // avoid r#ref
}
```

**Graph methods:** `add_node`, `add_edge`, `edges_from(id)` (outgoing), `edges_to(id)` (incoming — needed for reverse lookups like "which steps access this secret"), `authority_sources()` (nodes with kind Secret or Identity — the BFS start set), `nodes_in_zone()`.

**Implementation note:** No petgraph needed. Linear scan of `Vec<Edge>` is fine for pipeline-scale graphs (10-200 nodes). If profiling shows otherwise, build an adjacency index later.

### Propagation Engine

BFS from each **authority-bearing source node** (Secret and Identity — not just secrets), follow edges, detect trust boundary crossings. Identity is an authority source from day one because broad identity propagation is one of the strongest future findings.

```rust
pub type EdgeId = usize;

pub struct PropagationPath {
    pub source: NodeId,          // the authority origin (Secret or Identity)
    pub sink: NodeId,            // where it ended up
    pub edges: Vec<EdgeId>,      // the full path — this IS the product
    pub crossed_boundary: bool,
    pub boundary_crossing: Option<(TrustZone, TrustZone)>,
}

/// Authority sources = nodes with kind Secret or Identity.
/// BFS from each source. Flag paths that cross trust zones.
/// Propagation continues unless an explicit isolation boundary breaks it.
/// max_hops: configurable safety cap, default 4. Override via CLI --max-hops.
/// Do not build theory around hop count — just implement generic traversal with a cap.
pub fn propagation_analysis(graph: &AuthorityGraph, max_hops: usize) -> Vec<PropagationPath>;
```

This is ~50 lines of BFS. The path output is first-class because the path is what makes findings persuasive:

```
MY_SECRET --> step:build --> artifact:dist.zip --> step:publish-third-party
```

That path is the product.

### Finding Rules

**MVP rules (1-5):** fully derivable from pipeline YAML alone.

| # | Rule | Graph Pattern | Severity |
|---|------|--------------|----------|
| 1 | **AuthorityPropagation** | BFS path from Secret or Identity crosses TrustZone boundary | Critical |
| 2 | **OverPrivilegedIdentity** | Identity node scope (metadata) > union of edge targets' needs | High |
| 3 | **UnpinnedAction** | Image node in ThirdParty, no `digest` in metadata | Medium |
| 4 | **UntrustedWithAuthority** | Step in Untrusted zone has direct HasAccessTo edge to Secret or Identity | Critical |
| 5 | **ArtifactBoundaryCrossing** | Artifact Produced by privileged step, Consumed across trust boundary | High |

**Stretch rules (6-9):** require heuristics or metadata enrichment beyond YAML. Implement after MVP proves value.

| # | Rule | Why Stretch |
|---|------|------------|
| 6 | **EgressBlindspot** | GHA YAML doesn't declare network policy; needs convention-based heuristic |
| 7 | **MissingAuditTrail** | "Has audit" not parseable from YAML; needs metadata enrichment source |
| 8 | **FloatingImage** | Straightforward but lower priority than graph-based rules |
| 9 | **LongLivedCredential** | "Is this static?" requires naming heuristic (e.g. `AWS_ACCESS_KEY_ID`) |

```rust
pub enum FindingCategory {
    // MVP
    AuthorityPropagation,      // secret or identity crossed trust boundary
    OverPrivilegedIdentity,    // identity scope > actual usage
    UnpinnedAction,            // 3rd party action without SHA pin
    UntrustedWithAuthority,    // untrusted step has direct access to secret/identity
    ArtifactBoundaryCrossing,  // artifact produced by privileged step consumed across boundary
    // Stretch
    EgressBlindspot,
    MissingAuditTrail,
    FloatingImage,
    LongLivedCredential,
}

pub struct Finding {
    pub severity: Severity,
    pub category: FindingCategory,
    pub path: Option<PropagationPath>,
    pub nodes_involved: Vec<NodeId>,
    pub message: String,
    pub recommendation: Recommendation,
}

/// Routing: scope findings --> TsafeRemediation; isolation findings --> CellosRemediation.
pub enum Recommendation {
    TsafeRemediation { command: String, explanation: String },
    CellosRemediation { reason: String, spec_hint: String },
    PinAction { current: String, pinned: String },
    ReducePermissions { current: String, minimum: String },
    FederateIdentity { static_secret: String, oidc_provider: String },
    Manual { action: String },
}
```

### Traits (Ports)

```rust
pub trait PipelineParser: Send + Sync {
    fn platform(&self) -> &str;
    fn parse(&self, content: &str, source: &PipelineSource) -> Result<AuthorityGraph, TauditError>;
}

/// W: output destination (stdout, file, buffer). Injected by composition root.
pub trait ReportSink<W: std::io::Write>: Send + Sync {
    fn emit(&self, writer: &mut W, graph: &AuthorityGraph, findings: &[Finding]) -> Result<(), TauditError>;
}

pub trait AnalysisRule: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, graph: &AuthorityGraph) -> Vec<Finding>;
}
```

## CLI Commands

```
# MVP
taudit scan <path>              # Scan pipeline file(s), print terminal report
taudit scan --format json       # Structured JSON authority graph + findings
taudit scan --max-hops 5        # Override propagation depth (default: 4)

# Stretch
taudit scan --format sarif      # SARIF for GitHub code scanning
taudit map <path>               # Authority map table (who gets what)
taudit diff <before> <after>    # Authority diff between pipeline versions
taudit policy check <path>      # Check against policy file
```

### Example Output

```
$ taudit scan .github/workflows/deploy.yml

Authority Graph: deploy.yml
  Steps: 5 | Secrets: 4 | Actions: 3 | Identities: 1

Findings (3 critical, 2 high, 1 medium):

CRITICAL  Secret propagation across trust boundary
          AWS_SECRET_ACCESS_KEY (secret)
            --> build (1st party, reads secret)
            --> dist.tar.gz (artifact, written by build)
            --> deploy (3rd party action, consumes artifact)
          Fix: tsafe exec --ns build -- make dist

HIGH      Untrusted action with direct secret access
          actions/some-deploy@main (unpinned, untrusted)
            <-- reads DEPLOY_TOKEN (secret)
          Fix: Pin to SHA + cellos run --network deny-all --broker env:DEPLOY_TOKEN

HIGH      Over-privileged GITHUB_TOKEN
          permissions: write-all (granted)
          permissions: { contents: read } (needed)
          Fix: Set explicit permissions block

MEDIUM    Floating container image
          node:18 (no digest pin)
          Fix: Pin to node:18@sha256:<digest>
```

## Reference Projects

### CellOS `/Users/rytilcock/CellOS/`
- `Cargo.toml` — workspace pattern (`resolver = "2"`, `[workspace.package]`, `[workspace.dependencies]`)
- `cellos-core/src/ports.rs` — trait (port) definitions
- `cellos-supervisor/src/composition.rs` — composition root (407 LOC)
- `cellos-sink-jsonl/`, `cellos-export-s3/` — adapter crate examples
- `contracts/schemas/` + `contracts/examples/` — JSON Schema + CI validation
- `justfile` — `just check` mirrors CI; recipes: fmt, clippy, test, contracts, deny, audit
- `.github/workflows/quality.yml` — pinned SHAs, multi-stage gate
- `EXTENSIBILITY.md` (repo root) — ports/adapters checklist
- `PLAN.md` (repo root) — roadmap format
- `docs/DOCTRINE.md` — one-page product statement

### tsafe `/Users/rytilcock/prj/tsafe/`
- `crates/tsafe-cli/src/cmd_*.rs` — one module per subcommand group
- `crates/tsafe-cli/src/cli.rs` — Clap command tree
- `crates/tsafe-cli/src/helpers.rs` — shared CLI helpers
- `crates/tsafe-cli/tests/integration/test_*.rs` — integration tests per command
- `docs/pitch.md` — internal sales doc (write one for taudit)
- `docs/feature-maturity.md` — Current/MVP/AAA classification
- `docs/architecture/ADR-001.md` through `ADR-005.md` — decision records
- Release profile in root `Cargo.toml`: `lto = true, codegen-units = 1, strip = true`

### Engineering Doctrine `/Users/rytilcock/prj/engineering-doctrine/`
- `doctrine/patterns/build-surface-model.md` — name your build surfaces
- `doctrine/principles/testing-strategy.md` — test pyramid, contract tests
- `doctrine/principles/dependencies-supply-chain.md` — Cargo.lock, Dependabot, SCA
- `doctrine/principles/semantic-versioning.md` — SemVer rules
- `doctrine/principles/build.md` — local=CI, scripts in repo
- `doctrine/checklists/build-readiness.md` + `release-readiness.md`

## Bootstrap Order

1. `cargo init --name taudit` workspace root + shared deps
2. `taudit-core` — AuthorityGraph, Node, Edge, TrustZone, propagation engine, traits, TauditError
3. `taudit-parse-gha` — GitHub Actions YAML --> AuthorityGraph
4. **Write 3 test fixture workflows** (clean, over-privileged, propagation-leaky) + parser tests. This is the hardest crate — validate before proceeding.
5. `taudit-report-terminal` — coloured output with propagation paths
6. `taudit-cli` — Clap, composition root, `taudit scan` working end-to-end
7. `taudit-report-json` — structured JSON + JSON Schema in `contracts/`
8. Justfile, CI (`.github/workflows/quality.yml`), `deny.toml`, Dependabot
9. `docs/pitch.md`, `docs/DOCTRINE.md`, `docs/feature-maturity.md`
10. Stretch: `taudit-parse-ado`, rules 6-9, `taudit map/diff`, SARIF, CloudEvents sink

## Self-Test

Run taudit against your own pipelines before calling MVP:
1. `taudit scan /Users/rytilcock/CellOS/.github/workflows/` — expect: pinning findings, token scope findings
2. `taudit scan /Users/rytilcock/prj/tsafe/.github/workflows/` — expect: secret usage pattern findings
3. Test fixtures with deliberate over-privilege — expect: propagation findings with full paths

If it can't find real findings in your own pipelines, it's not ready.
