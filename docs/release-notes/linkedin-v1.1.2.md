# LinkedIn Changelog: taudit v1.1.2

taudit v1.1.2 is the new stable cut.

The headline: taudit now does a better job of separating authority inventory from exploit-candidate review paths.

In the last 24 hours we shipped:

- `taudit graph --view exploit`: a second graph mode for deterministic exploit-candidate paths. The authority graph still answers “where does authority go?” The exploit-candidate graph answers “where can earlier mutable runner state influence a later credential-bearing execution boundary?”
- Cross-provider stable coverage: GitHub Actions, Azure DevOps, GitLab CI, and Bitbucket Pipelines are now in the stable product path.
- More authority-confusion coverage from the release-candidate soak: helper resolution, mutable CI state, OIDC, container/Docker, remote script, publication, and provider-specific authority patterns.
- Publication context metadata in JSON and SARIF so findings can carry confidence, runtime preconditions, authority kind, attacker surface, and publication relevance without claiming “this is a vuln.”
- `graph_risk_summary` for corpus-scale reporting and ranking.
- Stable `suppression_key` output for reviewed waivers. `fingerprint` remains the precise dedup/baseline key; `suppression_key` is the operator-stable review key that survives harmless workflow edits.
- `suppression_key` support across JSON, SARIF, CloudEvents, and `.taudit-suppressions.yml`.
- A compact demo story from the corpus showing both views on one pipeline: authority propagation plus exploit-candidate path, with DOT and Graphviz PNG output.
- Release machinery hardening: local full CI drills, semver checks, crate package verification, cargo audit/deny, staged gitleaks, and full corpus smoke scans across the supported providers.

Why this matters:

Most CI/CD security review either inventories authority or searches for isolated smells.

taudit connects the two:

1. what authority exists;
2. where it flows;
3. which trust boundary receives it;
4. whether a deterministic review path exists from earlier mutable state to later credential-bearing execution.

That is the difference between “this workflow changes PATH” and “this workflow changes PATH before a later deploy action resolves a credential-bearing helper.”

How this helps developers:

- Review pipeline changes with context. Instead of reading a large workflow top to bottom, developers can see which step first introduces authority, where it crosses a trust boundary, and which later helper or action handles it.
- Fix the highest-leverage boundary first. The graph points at practical hardening moves: scope `permissions:`, move secrets out of job-level env, pin or absolutize helper paths, split deploy authority into a smaller job, and keep mutable setup steps away from credential-bearing execution.
- Avoid noisy “security says no” reviews. taudit distinguishes inventory from exploit-candidate paths, so teams can discuss a narrow ordering issue instead of debating whether every PATH mutation or every third-party action is automatically bad.
- Keep suppressions reviewable. `fingerprint` handles precise dedup. `suppression_key` gives teams a stable waiver identity for findings they have reviewed, so harmless workflow edits do not constantly break known decisions.
- Make CI/CD security visible to application engineers. The DOT, Mermaid, JSON, SARIF, and Graphviz outputs can go into PR comments, internal docs, SARIF dashboards, and architecture reviews.

How this helps teams lock down pipelines:

- Establish a baseline of where deploy, publish, registry, cloud, and repository-write authority actually flows.
- Add merge gates around new high-risk authority paths without blocking the whole backlog on legacy findings.
- Track progress over time with stable suppressions and graph summaries instead of spreadsheet-driven exception tracking.
- Give platform teams a shared language for remediation: authority source, trust boundary, mutable state, helper resolution, and sink.
- Separate product hardening from vulnerability disclosure. taudit’s default output is for downstream customers and internal platform teams; disclosure-only signals remain out of the customer path.
- Use the same model across GitHub Actions, Azure DevOps, GitLab CI, and Bitbucket Pipelines, which matters for organizations that do not have a single CI provider.

The output is intentionally conservative. taudit does not label corpus signals as vulnerabilities. It gives security engineers a narrow, evidence-backed review target.

Install:

```bash
cargo install taudit
```

Example:

```bash
taudit scan --platform github-actions .github/workflows/deploy.yml
taudit graph --platform github-actions --view authority --format dot .github/workflows/deploy.yml
taudit graph --platform github-actions --view exploit --format dot .github/workflows/deploy.yml
```

The stable release is meant for teams that want CI/CD authority propagation, reviewable exploit-candidate paths, and deterministic suppression workflows without turning every finding into a disclosure claim.
