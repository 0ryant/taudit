# Contributing

Ecosystem CI / governance norms for this repo (and peers **tsafe**, **CellOS**): **[`standardise-ecosystem.md`](standardise-ecosystem.md)**.

## Development setup

`taudit` is a Rust workspace. Use the pinned toolchain configured by the repo.

## Local quality gate

**GitHub Actions is not available for this repository, so the local run *is* the
gate.** The canonical command is:

```bash
just local-ci
```

That executes the union of what `quality.yml`, `security.yml` and
`governance.yml` would run — 21 checks — and prints a PASS / FAIL / SKIP summary.

Two properties matter:

- **A missing tool skips one check instead of aborting the run.** The older
  stages call `require_cmd`, which exits on the first tool it cannot find, so a
  single absent linter reduced the whole gate to nothing. Skips here are counted,
  listed with the exact install command, and reported in the summary.
- **Skips are never silent.** `just local-ci-strict` fails on any skip. Use it
  to gate a release: a run that "passed" while skipping the security scanners is
  not a gate.

Install everything it needs, on Windows, macOS or Linux, without root:

```bash
bash scripts/install-local-ci-tools.sh
```

(The older `install-governance-tools.sh` and `install-ci-linters.sh` are
CI-image specific — they require Linux x86_64, apt and sudo.)

`gitleaks` and `trivy` ship as single per-platform binaries; install those from
their releases pages, or via `brew` / `choco` / `winget`.

### The narrower stages

`just quality-gate` remains the strict Rust-plus-governance subset:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo deny check licenses bans sources`
- `cargo audit`
- `gitleaks` (secrets scanning)
- `trivy` (filesystem vuln/misconfig/secret scan)
- `checkov` (GitHub Actions + secrets policy scan)
- `taudit` workflow scan + invariant verification
- **Golden paths** — after `cargo test`, runs [`scripts/golden-paths.sh`](scripts/golden-paths.sh) against `target/debug/taudit` (same flows as [docs/golden-paths.md](docs/golden-paths.md))
- **Starter `taudit verify` (advisory)** — why many findings on our own workflows do not fail the gate: [docs/contributing/dogfood-taudit-verify.md](docs/contributing/dogfood-taudit-verify.md)
- **Mutation coverage** — weekly / manual workflow [`.github/workflows/mutation-coverage.yml`](.github/workflows/mutation-coverage.yml) (not part of the blocking `quality` job; see workflow comment for rationale)

Hosted **`quality`** also runs **`scripts/install-ci-linters.sh`** (pinned **actionlint** + **yamllint**) before **`ci-governance`**. To reproduce that gate locally after you have Trivy, Checkov, and Gitleaks: on **Linux x86_64** run `bash scripts/install-ci-linters.sh`; on **macOS** use `brew install actionlint yamllint` instead (the install script targets the CI runner arch). Then `bash scripts/quality-gate.sh ci-governance`.

Quick Rust-only gate:

```bash
just check
```

Contract-focused check:

```bash
just contracts
```

## Common development tasks

```bash
just versions
just fix
just self-test
just golden-paths
just pre-commit-gate
just pre-push-gate
```

**Docs drift:** if you change CLI output that the golden-path script asserts on, run **`just golden-paths`** locally and update [docs/golden-paths.md](docs/golden-paths.md) if you add a new blessed flow.

Install local hooks:

```bash
just install-hooks
```

Optional runtime-integration smoke:

```bash
just runtime-smoke
```

## Pull requests

- Keep changes focused and minimal.
- Update docs when behavior or operator-facing output changes.
- If you change JSON schemas, examples, or machine-readable outputs, treat them as release-contract changes and update them together.
- Include tests for behavior changes when practical.

## Releases

taudit is closer to a **static analysis engine for authority propagation** than a casual utility CLI. **Detection semantics are part of the public API** for anyone who pins versions or gates CI.

**Canonical policy:** read **[`docs/release-strategy.md`](docs/release-strategy.md)** — two lanes (**stable** = crates.io trust, **edge** = GitHub velocity), **hard gates** before registry publish, **semver** that signals graph/detection change, and **changelog** rules (what changed in detection, more/fewer findings, FP/FN shifts).

**In short:** ship to **crates.io** when you have a **coherent, defensible** change set and contracts are clear — **at most ~one stable publish per week** as a *ceiling*, not a quota (**zero** ships in a quiet week is good). Put **fast iteration** on **GitHub** (pre-releases, commit tags, nightlies), not on the default registry. Security fixes may ship out of band; still document **detection impact** in `CHANGELOG.md`.

When you bump `version` in the crate manifests for a **stable** release, update `CHANGELOG.md`, align pinned `cargo install taudit --version …` strings in docs and examples, and push `vM.m.p` only when `main` is green. Keep install instructions and output examples aligned with shipped behaviour ([`docs/release-trust.md`](docs/release-trust.md) for verification of built artifacts).