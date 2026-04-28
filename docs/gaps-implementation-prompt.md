# taudit: Close the Four Competitive Gaps

Close four gaps that put taudit behind zizmor, trivy, gitleaks, and checkov at the marketing/trust level. Each section is an independent workstream; they can be done in parallel.

---

## Gap 1 — Snapshot Tests (finding-output regression gate)

**Problem:** taudit has no way to catch regressions in finding text, SARIF field values, rule IDs, or message formatting. zizmor has 431 `cargo-insta` assertions. Any message-copy change, severity reclassification, or fingerprint algorithm change in taudit is currently invisible to CI.

**Target:** ≥50 insta snapshots covering the breadth of rule outputs across GHA, ADO, and GitLab parsers by the end of this task. Floor is not negotiable — it needs to be material, not token.

**Implementation:**

1. Add `insta` to `[dev-dependencies]` in `crates/taudit-cli/Cargo.toml` (and in any parser crate that will have its own snapshot suite).

2. Create `crates/taudit-cli/tests/snapshots/` — this is where insta writes `.snap` files.

3. Write a snapshot test file at `crates/taudit-cli/tests/snapshot_gha.rs`. Pattern:
   ```rust
   use insta::assert_yaml_snapshot;
   // ... parse fixture, run rules, collect findings sorted by (rule_id, fingerprint)
   assert_yaml_snapshot!("gha_over_privileged_findings", findings_sorted);
   ```
   Sort findings by `(rule_id, fingerprint)` before snapshotting — stable ordering is required or snapshots will flap.

4. Cover at minimum:
   - `tests/fixtures/over-privileged.yml` → GHA full finding set (rule IDs, severities, titles, fingerprints)
   - `tests/fixtures/clean.yml` → GHA empty/minimal finding set
   - Two ADO fixture scenarios (one with `shared_self_hosted_pool_no_isolation`, one with `setvariable_issecret_false`)
   - One GitLab fixture
   - The JSON report output for a multi-finding scan (snapshot the rendered JSON, not just the struct)
   - The SARIF report output for a multi-finding scan (snapshot `.runs[0].results` array)
   - The terminal report output for a known finding (strip ANSI codes before snapshotting)

5. Add `insta` review step to CI in `quality.yml`:
   ```yaml
   - name: snapshot review
     run: cargo insta test --workspace --unreferenced reject
   ```
   `--unreferenced reject` catches deleted test cases that leave orphaned `.snap` files.

6. Commit the initial `.snap` files alongside the tests (they are the ground-truth). Add `crates/*/tests/snapshots/*.snap.new` to `.gitignore` (insta writes `.snap.new` during review).

**Acceptance:** `cargo insta test --workspace` exits 0. Count of `.snap` files ≥ 50. CI snapshot step present in `quality.yml`.

---

## Gap 2 — Multi-OS CI Matrix

**Problem:** taudit's `quality.yml` runs only on `ubuntu-latest`. trivy, gitleaks, and checkov all run on ubuntu + macos + windows. Path separator bugs, YAML parsing differences, and binary behavior on Windows are invisible to taudit's CI.

**Target:** Core test suite (`cargo test --workspace`) passing on all three OSes on every PR.

**Implementation:**

1. Extract a new job `test-matrix` in `quality.yml` that runs `cargo test --workspace` across the OS matrix. Do NOT put the full quality gate (gitleaks, trivy, checkov, taudit self-scan) on macOS/Windows — those tools don't have reliable cross-platform installers and would make CI fragile. The matrix expands only the Rust test suite.

   ```yaml
   test-matrix:
     name: "test (${{ matrix.os }})"
     runs-on: ${{ matrix.os }}
     strategy:
       matrix:
         os: [ubuntu-latest, macos-latest, windows-latest]
       fail-fast: false
     steps:
       - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
       - uses: dtolnay/rust-toolchain@98e1b82157cd469e843cb7f524c1313b4ad9492c # 1.88
       - uses: Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4 # v2.9.1
         with:
           key: ${{ matrix.os }}
       - name: test
         run: cargo test --workspace
   ```

2. Use `fail-fast: false` so a Windows failure doesn't cancel the macOS run.

3. The existing `quality` job (lint, governance gate, SARIF self-scan) stays on `ubuntu-latest` only — do not matrix it.

4. Fix any path issues that surface. Common sources: `PathBuf` construction using `/` separators hardcoded as strings, `tests/fixtures/` paths that assume Unix separators in `file!()` macros, temp dir creation using `/tmp/` literals.

**Acceptance:** All three `test-matrix` OS legs green on a clean branch. CI badge reflects the matrix. No existing `quality` job behavior changed.

---

## Gap 3 — SBOM + Provenance on Release

**Status (2026-04):** **Done** for the originally scoped SBOM + consumer-verifiable provenance path implemented in `.github/workflows/release.yml`.

| Item | Status |
| --- | --- |
| SPDX 2.3 + CycloneDX 1.5 SBOMs on each release | **Done** (`cargo-sbom`, `cargo-cyclonedx`, uploaded as release assets) |
| Build provenance consumers can verify | **Done** — **`actions/attest-build-provenance@v1`** (GitHub Artifact Attestations); verify downloaded files with **`gh attestation verify <path> --repo 0ryant/taudit`** |
| Documented blessed path | **Done** — [docs/release-trust.md#verifying-build-attestations-github](release-trust.md#verifying-build-attestations-github) and [README.md](../README.md#install) |

**Original problem statement (historical):** taudit releases had no SBOM and no provenance story comparable to other supply-chain tools.

**Optional follow-ups** (only if product/security asks — not part of “Gap 3 done”):

1. **`slsa-framework/slsa-github-generator`** — if a customer mandates **SLSA generic provenance** as a **downloadable** `.intoto.jsonl` next to assets, add the generator workflow **in addition** to (or after evaluating parity with) GitHub’s attestation store. This repo **does not** use the generator today; do not document it as shipped.

2. **`slsa-verifier verify-artifact`** — only relevant **if** you publish SLSA-style provenance files as release assets; the shipped verification path is **`gh attestation verify`** only.

3. **minisign** on release tarballs — see [release-trust.md](release-trust.md) “Future work”; offline verification without `gh`.

**Implementation notes (archived — superseded by current `release.yml`):**

<details>
<summary>Older design sketch (CycloneDX XML + slsa-github-generator)</summary>

### SBOM (CycloneDX)

1. Add `cargo-cyclonedx` to the release job.

   ```yaml
   - name: Generate SBOM (CycloneDX)
     run: |
       cargo install cargo-cyclonedx --locked
       cargo cyclonedx --format xml --spec-version 1.4 --output-file taudit-sbom.xml
   ```

2. Upload as a release asset.

### SLSA Provenance (alternative stack)

Use `slsa-framework/slsa-github-generator` only if you explicitly choose that path; see generator README for `workflow_call` and `base64-subjects` wiring.

</details>

**Acceptance (updated):** Release workflow exits 0; SBOMs appear on the GitHub Release; **`gh attestation verify`** succeeds on a downloaded archive and on each SBOM file attested in CI.

---

## Gap 4 — Fuzz Harnesses

**Problem:** taudit has no fuzz harnesses. Rust has first-class fuzzing support via `cargo-fuzz` (libFuzzer) and `cargo-mutants` (mutation coverage). The parsers — `taudit-parse-gha`, `taudit-parse-ado`, `taudit-parse-gitlab` — are the highest-value targets because they consume untrusted YAML from arbitrary repos.

**Target:** Three fuzz targets (one per parser) that can be run locally and in CI in a smoke-run mode (10s budget per target), plus `cargo-mutants` integrated into the CI quality gate.

### cargo-fuzz targets

1. Initialize fuzz support in the workspace:
   ```bash
   cargo install cargo-fuzz --locked
   # In the repo root:
   cargo fuzz init -p taudit-parse-gha
   ```
   This creates `fuzz/` under the crate.

2. Write three fuzz targets — one per parser crate:

   **`fuzz/fuzz_targets/parse_gha.rs`** (in `crates/taudit-parse-gha/fuzz/`):
   ```rust
   #![no_main]
   use libfuzzer_sys::fuzz_target;
   use taudit_core::ports::PipelineParser;
   use taudit_parse_gha::GhaParser;
   use taudit_core::graph::PipelineSource;

   fuzz_target!(|data: &[u8]| {
       if let Ok(yaml) = std::str::from_utf8(data) {
           let source = PipelineSource { file: "fuzz.yml".into(), repo: None, git_ref: None, commit_sha: None };
           let _ = GhaParser.parse(yaml, &source);
       }
   });
   ```

   Create equivalent targets for `taudit-parse-ado` and `taudit-parse-gitlab`.

3. Add a smoke-run CI step to `quality.yml` (runs each fuzz target for 10 seconds — not a full fuzzing campaign, but catches panics on startup and obvious crash inputs):
   ```yaml
   - name: fuzz smoke (parse_gha, parse_ado, parse_gitlab — 10s each)
     run: |
       cargo install cargo-fuzz --locked
       cargo fuzz run parse_gha -- -max_total_time=10
       cargo fuzz run parse_ado -- -max_total_time=10
       cargo fuzz run parse_gitlab -- -max_total_time=10
     working-directory: crates/taudit-parse-gha  # adjust per target
   ```
   Note: `cargo fuzz` requires the nightly toolchain. Add `cargo +nightly fuzz run ...` or pin the matrix step to use nightly for the fuzz job only.

4. Add a `corpus/` directory under each `fuzz/` directory with 3-5 seed inputs (real-world fixture files copied from `tests/fixtures/`). Good corpus seeds dramatically improve fuzz efficiency.

### cargo-mutants (mutation coverage)

1. Add a `cargo-mutants` step to `quality.yml` scoped to the rule engine (`taudit-core`):
   ```yaml
   - name: Install cargo-mutants
     run: cargo install cargo-mutants --locked

   - name: mutation coverage (taudit-core)
     run: cargo mutants -p taudit-core --timeout 60
   ```

2. `cargo-mutants` does not gate by default (exits 0 even with surviving mutants). Treat it as informational for now — the output surfaces which code paths have no test coverage. Promote to a hard gate (--error-on-caught-timeout or a mutant score threshold) once the baseline is known.

3. Add `mutants.out/` to `.gitignore`.

**Acceptance:** `cargo fuzz build` exits 0 for all three targets (requires nightly). CI fuzz smoke step runs 10s per target without panicking. `cargo mutants -p taudit-core` runs and produces a report. At least 3 seed corpus files per fuzz target.

---

## Cross-cutting notes

- All new CI steps must use pinned action SHAs (check taudit's existing `quality.yml` for the pattern).
- New `[dev-dependencies]` (`insta`, `libfuzzer-sys`) must be added to the correct crate's `Cargo.toml`, not the workspace root.
- Run `cargo deny check` after adding deps to verify the new crates are license-compatible.
- The existing 186 tests must continue to pass after all changes.
