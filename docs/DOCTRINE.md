# taudit -- product doctrine (one page)

## Wedge

**taudit** -- the pipeline authority scanner. Models how authority propagates through CI/CD pipelines, so you can prove least privilege. Not a scanner -- a privilege dataflow analyser.

taudit is one layer in a closed governance loop:
**taudit** (detect over-authority) --> **tsafe** (constrain secrets) --> **execution isolation runtime** (contain execution) --> runtime --> **taudit** (re-observe).

## North star

Every secret, identity, and token in a pipeline should be provably scoped to only the steps that need it, pinned to immutable code, and observable through its full propagation path.

## Failure classes (design with these first)

| Class | Direction |
|-------|-----------|
| Over-authority | Secret/identity accessible beyond its minimum required scope |
| Trust boundary crossing | Authority propagates from first-party to untrusted without isolation |
| Unpinned delegation | Execution delegated to mutable third-party code |
| Over-privileged identity | GITHUB_TOKEN or similar granted broader permissions than consumed |
| Unattributable authority | No path evidence connecting authority source to sink |

## Non-negotiable invariants

1. Graph-first: the authority graph is the product, not the findings.
2. Path evidence: every finding includes the full propagation path.
3. No I/O in core: `taudit-core` is a pure domain library.
4. Day-1 value without tsafe or any specific isolation runtime installed.
5. Remediation routes to the right tool: scope findings --> tsafe, isolation findings --> your execution isolation runtime.
6. SHA pinning is the minimum bar for third-party trust.

## Anti-goals

- Reimplementing gitleaks (secret pattern scanning)
- Reimplementing trivy (CVE scanning)
- Reimplementing checkov (IaC policy)
- Building theory around hop counts -- generic traversal with a safety cap
- Requiring network access or cloud APIs for core analysis

## Contract source of truth

JSON Schema under `contracts/schemas/` and examples under `contracts/examples/`. CI validates examples against schemas on every change.
