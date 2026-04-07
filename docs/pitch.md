# taudit -- Internal Pitch

> **One-line pitch:** taudit shows how authority propagates through your pipelines, so you can prove least privilege.

---

## The Problem We Solve

Existing CI/CD security tools scan for known patterns: leaked secrets (gitleaks), CVEs (trivy), policy violations (checkov). They answer "is this bad?" one artefact at a time.

None of them answer the question that actually matters:

**"Where does authority flow in my pipeline, and is it scoped to only what's needed?"**

Consider a real GitHub Actions workflow:

```yaml
permissions: write-all
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: make build
        env:
          AWS_KEY: "${{ secrets.AWS_ACCESS_KEY_ID }}"
      - uses: some-org/publish@v1
        with:
          token: "${{ secrets.NPM_TOKEN }}"
```

What's wrong here?

1. **`permissions: write-all`** -- GITHUB_TOKEN can push code, create releases, modify packages. The job only needs `contents: read`.
2. **`actions/checkout@v4`** -- tag-pinned, not SHA-pinned. A supply chain attack on this action gets `write-all` GITHUB_TOKEN + both secrets.
3. **`AWS_ACCESS_KEY_ID`** -- a long-lived static credential injected into a build step that also has network access. No isolation.
4. **`NPM_TOKEN`** -- passed to an unpinned third-party action. The action author can change what `v1` points to at any time.

A pattern scanner flags the tag pin (maybe). taudit shows the full authority graph:

```
AWS_ACCESS_KEY_ID (secret) --> build (1st party) --> actions/checkout@v4 (untrusted, unpinned)
NPM_TOKEN (secret) --> Publish (untrusted) --> some-org/publish@v1 (untrusted, unpinned)
GITHUB_TOKEN (write-all) --> build, Publish (both have full write access)
```

The graph is the product. The path is the proof.

---

## What taudit Does

1. **Parses pipeline YAML** into a typed authority graph: steps, secrets, identities, artifacts, images, trust zones.
2. **Runs BFS propagation analysis** from every authority source (secret + identity), detecting trust boundary crossings.
3. **Applies 5 rules** that find real security issues: authority propagation, over-privileged identity, unpinned actions, untrusted steps with direct authority, artifact boundary crossing.
4. **Outputs actionable findings** with full propagation paths and specific remediation: which tool to use, what command to run.

---

## What We Replace

| Today | With taudit |
|-------|-------------|
| Manual review of who gets what secrets | Authority graph shows it |
| "Is this action pinned?" one at a time | All unpinned actions flagged, deduplicated |
| No visibility into token scope vs usage | Over-privileged identity detection |
| No propagation analysis at all | BFS from every authority source |
| "Add a policy" (no evidence) | Path evidence: source --> ... --> sink |
| Generic "fix your pipeline" advice | Specific: `tsafe exec --ns build` or `cellos run --network deny-all` |

---

## The Control Loop

taudit doesn't work alone. It's the detection layer in a closed loop:

```
taudit scan .github/workflows/
    |
    | findings: "AWS_KEY reaches untrusted step"
    v
tsafe exec --ns build -- make dist
    |
    | constraint: secret scoped to build step only
    v
cellos run --network deny-all --broker env:NPM_TOKEN
    |
    | containment: execution isolated, egress blocked
    v
runtime executes
    |
    v
taudit scan .github/workflows/
    |
    | no findings (authority properly scoped)
```

taudit detects. tsafe constrains. CellOS contains. Repeat.

---

## Why Not Just Another Scanner?

Scanners answer "is this artefact bad?" taudit answers "where does authority go?"

| Capability | gitleaks | trivy | checkov | taudit |
|------------|---------|-------|---------|--------|
| Secret pattern detection | Yes | - | - | No (not our job) |
| CVE scanning | - | Yes | - | No (not our job) |
| IaC policy | - | - | Yes | No (not our job) |
| Authority graph | - | - | - | **Yes** |
| Propagation analysis | - | - | - | **Yes** |
| Trust boundary detection | - | - | - | **Yes** |
| Path evidence in findings | - | - | - | **Yes** |
| Remediation routing | - | - | - | **Yes** |

taudit is complementary. Run it alongside your existing tools.

---

## Deployment Effort

| Step | Effort |
|------|--------|
| Install | Single binary (Rust, no runtime) |
| First scan | `taudit scan .github/workflows/` (30 seconds) |
| CI integration | Add one step to quality.yml |
| Rollback | Delete the binary. Zero lock-in. |

No infrastructure changes. No cloud APIs. No config files. Point it at YAML and get results.
