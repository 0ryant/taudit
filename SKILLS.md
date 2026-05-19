# Skills — taudit

> Golden agent-facing recipes for the CI/CD authority graph analyzer. Audience: AI agents (Claude / Cursor / Codex / etc.) and the humans configuring them.

## When to reach for this repo

Use taudit when the question is "what authority does this pipeline actually grant, and to whom?" — modeling how secrets, identities, tokens, and artifacts propagate across GitHub Actions, Azure DevOps, GitLab CI, and Bitbucket Pipelines as a typed graph. Use it for PR-gate enforcement of explicit invariants over that graph. Do **not** use taudit as a YAML schema linter (use `actionlint`), a CVE scanner (use `trivy`), or a general-purpose policy engine (use `checkov`) — taudit's product is the deterministic authority graph; findings, SARIF, and merge gates are consumers of it.

## Skills index

- [scan-then-verify](#skill-scan-then-verify) — `taudit scan` for findings, `taudit verify` for the PR-gate
- [baseline-init-for-existing-repos](#skill-baseline-init-for-existing-repos) — capture a per-pipeline baseline so `verify` only fails on NEW findings
- [graph-export-as-artifact](#skill-graph-export-as-artifact) — emit the canonical authority graph as the first-class artifact (`dot` / `mermaid` / `json` / `summary`)
- [severity-threshold-in-CI](#skill-severity-threshold-in-ci) — route findings into CI gates by severity (`--severity-threshold high`), with critical findings always exiting non-zero

---

## Skill: scan-then-verify

**When:** You need to either (a) surface findings on a pipeline for human review or SARIF ingestion, or (b) gate a PR against an explicit invariant set. Use `scan` for discovery and reporting; use `verify` once you have a policy directory and want merge discipline.

**How (golden invocation):**

```bash
# 1. Discovery: scan emits findings (informational, exit 0 by default)
taudit scan .github/workflows/ --format json --quiet > taudit.json

# 2. SARIF for code-scanning ingestion (GitHub, Azure DevOps)
taudit scan .github/workflows/ --format sarif -o taudit.sarif

# 3. PR-gate: verify against an explicit policy directory
taudit verify --policy invariants/starter/ .github/workflows/ --platform github-actions
```

**Expected output:** `scan` returns a JSON report (`schema_version: "1.0.0"`) with `graph` + `findings` + `summary`; SARIF conforms to 2.1.0 with stable `partialFingerprints["taudit/v1"]`. `verify` exits **0** (clean), **1** (violations against policy), or **2** (policy/graph load error) — see `docs/verify.md`. Each finding carries a byte-identical fingerprint across JSON / SARIF / CloudEvents so SIEM and code-scanning consumers can join across re-runs.

**Common pitfalls:**
- Running `verify` without `--policy` is a configuration error, not "scan with gating." `verify` requires an explicit invariant set; otherwise its semantics are undefined.
- `taudit graph` has **no** `-o` flag — it writes only to stdout. Use shell redirection (`> graph.json`). `scan` and `verify` *do* support `-o`.
- Starter invariants are strict — on many real repos, first `verify` run exits 1. That is normal; either tune the policy or capture a baseline (next skill).

**See also:** [`docs/verify.md`](docs/verify.md), [`docs/golden-paths.md`](docs/golden-paths.md) (Paths D and H), [`docs/finding-fingerprint.md`](docs/finding-fingerprint.md).

---

## Skill: baseline-init-for-existing-repos

**When:** Rolling taudit onto a legacy repo with hundreds of historical findings. Without a baseline, the first `verify` run drowns the team in pre-existing debt; with one, `verify` only fails on NEW findings introduced after the baseline timestamp.

**How (golden invocation):**

```bash
# One-time snapshot — captures starting state per pipeline by content hash
taudit baseline init .github/workflows/

# Commit the contract so the team shares the same baseline
git add .taudit/baselines/
git commit -m "chore(taudit): capture authority-graph baseline"

# Now verify only fails on findings NOT in the baseline
taudit verify --policy invariants/ .github/workflows/
```

**Expected output:** `.taudit/baselines/` contains one file per workflow keyed by content hash (so merge conflicts touch at most one file). Each fingerprint is identical to the SARIF / JSON / CloudEvents fingerprints, so SIEMs see the same identity. `verify` will exit 0 unless a NEW finding (one not in the baseline) lands.

**Common pitfalls:**
- **Critical findings still count toward exit 1 by default**, even if in the baseline — security analysts can't suppress critical without a 90-day-bounded explicit waiver. This is intentional, not a bug.
- Baselines are opt-in: no `.taudit/` directory means today's behavior, byte-identical. Don't assume the baseline is "on" without checking for the directory.
- Per-pipeline keying means renaming a workflow file invalidates its baseline. Document workflow renames as part of the PR, not a baseline regeneration.

**See also:** [`docs/baselines.md`](docs/baselines.md), [`docs/adoption-day0-day1.md`](docs/adoption-day0-day1.md), [`docs/finding-fingerprint.md`](docs/finding-fingerprint.md).

---

## Skill: graph-export-as-artifact

**When:** The graph IS the product; findings are consumers of it. Export the graph as a first-class artifact for visualization (DOT / Mermaid), programmatic consumption by sibling tools (JSON), or triage rollups (summary). Use this when a downstream tool — tsign, axiom, runtime cells, custom auditors — needs the authority structure independent of any rule output.

**How (golden invocation):**

```bash
# JSON — schema-conformant interchange (schema_version: "1.0.0", schema_uri pin-able)
taudit graph .github/workflows/release.yml --format json > graph.json

# DOT — render to SVG with Graphviz for docs, slides, incident reports
taudit graph .github/workflows/release.yml --format dot | dot -Tsvg -o release.svg

# Mermaid — paste into Markdown / wikis without installing Graphviz
taudit graph .github/workflows/release.yml --format mermaid

# Summary — bounded propagation rollup (boundary-crossing paths only)
taudit graph .github/workflows/release.yml --format summary | jq '.totals'

# Per-job subgraph when the full workflow graph is too dense
taudit graph .github/workflows/release.yml --format dot --job build | dot -Tsvg -o build.svg
```

**Expected output:** JSON validates against [`schemas/authority-graph.v1.json`](schemas/authority-graph.v1.json) with a top-level envelope `{ schema_version, schema_uri, graph: { source, nodes, edges, completeness, completeness_gaps, completeness_gap_kinds, metadata } }`. `completeness` is one of `complete` / `partial` / `unknown` — pin to the major version, validate the envelope, and **treat `partial` graphs as a floor on risk** (every edge is real; more may exist that the parser couldn't see).

**Common pitfalls:**
- `taudit graph` writes **only to stdout** — there is no `-o` / `--output` flag. Use `>` for files. (This differs from `scan` and `verify`, which both support `-o`.)
- `--job` filters the **diagram** views (dot / mermaid) but JSON and summary stay full-graph by design — you need the lossless `completeness_gaps` for downstream gating.
- Don't reverse-engineer `Node.metadata` for routine privilege questions. The `authority_summary` field on `has_access_to` → identity edges (`trust_zone`, `identity_scope`, `permissions_summary`) is the stable contract for that.
- `--rich-labels` only affects diagram text; JSON is unchanged. Use rich labels for small teaching slices, default for large graphs.

**See also:** [`docs/authority-graph.md`](docs/authority-graph.md), [`schemas/authority-graph.v1.json`](schemas/authority-graph.v1.json), [`docs/golden-paths.md`](docs/golden-paths.md) (Paths B, C, E, F).

---

## Skill: severity-threshold-in-CI

**When:** You want `scan` to participate in a CI gate without standing up a full `verify` policy. `--severity-threshold` routes the exit code by finding severity; `critical` findings **always** exit non-zero unless explicitly waived. Use this as the lightweight gate before policies are tuned, or alongside `verify` for layered defense.

**How (golden invocation):**

```yaml
# .github/workflows/security.yml — pin the binary, gate on high+
- name: Authority audit
  run: |
    cargo install taudit --version 1.1.5 --locked
    taudit scan .github/workflows/ --severity-threshold high

# Or via the official Action (also pin the version)
- uses: 0ryant/taudit-action@<sha>
  with:
    severity-threshold: high
    format: sarif
    output: taudit.sarif
```

```bash
# Local equivalent — quiet CI logs + SARIF upload
taudit scan .github/workflows/ \
  --severity-threshold high \
  --format sarif \
  -o taudit.sarif \
  --quiet \
  --omit-empty
```

**Expected output:** Exit `0` if no findings at or above the threshold; exit `1` if any finding meets the threshold. **Critical findings always exit 1** unless explicitly waived via a baseline entry with a 90-day-bounded justification — the security-analyst non-negotiable. SARIF carries stable fingerprints so GitHub Code Scanning deduplicates across re-runs and preserves user-managed state (dismissals, suppressions).

**Common pitfalls:**
- Don't conflate `--severity-threshold` (scan-time exit-code routing) with `verify --policy` (declarative invariants). They compose, but they're different gates.
- Pin the taudit binary version in CI (`--version 1.1.5 --locked` or `--version <pinned>` in the Action `with:` block). Floating versions defeat the purpose of a deterministic gate.
- `Taudit@1` (the Azure DevOps task) downloads a version-pinned release asset and verifies its SHA-256; don't bypass that with manual installs in the pipeline.
- `taudit` audits the pipeline that runs it — there is **no self-exemption**. A taudit step can still appear in findings. If you want a repo dogfood lane non-blocking, do that via baseline or suppressions, not a hidden exemption.

**See also:** [`docs/examples/ci-gate-taudit-verify.yml`](docs/examples/ci-gate-taudit-verify.yml), [`docs/release-strategy.md`](docs/release-strategy.md), [`docs/integrations/github-marketplace-action-contract.md`](docs/integrations/github-marketplace-action-contract.md), self-audit semantics in the [`README.md`](README.md).

---

## How this repo composes with the ecosystem

- **tsign** consumes `taudit graph --format json` to attach signed claims about which authority paths existed at build time; the graph is the contract between layers.
- **axiom** (the enforcement brain) consumes graphs + attestations to make merge / deploy decisions across many repos — the per-repo taudit gate is the local signal that axiom aggregates.
- **cortex** / **doctrine-mcp** can ingest CloudEvents JSONL from `taudit scan --format cloudevents` for event-driven memory rows / doctrine queries.
- **tsafe** is the remediation routing target for `authority_propagation` findings — `tsafe exec --ns <scoped-namespace> -- <command>` narrows the authority surface that taudit flagged.

## What this repo will NOT do

- **Not a secret scanner** (use [gitleaks](https://github.com/gitleaks/gitleaks)) — taudit references secrets *by name* via the YAML; it does not detect committed secret values.
- **Not a CVE scanner** (use [trivy](https://github.com/aquasecurity/trivy)) — taudit reasons about *authority propagation in pipeline definitions*, not about vulnerabilities in compiled dependencies.
- **Not a policy engine** (use [checkov](https://github.com/bridgecrewio/checkov)) — taudit evaluates *built-in graph predicates + custom invariants over the authority graph*, not a separate policy runtime over arbitrary IaC.
- **Not a runtime monitor** — taudit reads pipeline YAML offline, always. If you need runtime observation, that's the job of `corcept` (hooks) or `cellos` (cell lifecycle events).
