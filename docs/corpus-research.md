# Large-directory scans and citing upstream workflows

This note is for **operators and doc authors** who run taudit over many pipeline files (mirrored corpora, org-wide sweeps) or who want to **point readers at real-world YAML** as examples.

## What a corpus scan is not

- **0 findings** does **not** mean “formally secure” or “audited clean.” It means the **current** built-in rule set, parser, and graph for that file did not emit a finding.
- **Fingerprinting** and baselines are keyed in part on the **on-disk file path** (see [finding-fingerprint.md](finding-fingerprint.md)). A workflow copied to a different path (e.g. a flat `org__repo__workflow.yml` mirror) will **not** produce the same fingerprint as the same content under `.github/workflows/…` in a real clone.
- **`taudit graph` completeness** is often `partial` for real repos (matrix jobs, composite actions, reusable workflows). See graph `completeness` and `completeness_gaps` in JSON output. Rules may be conservative or incomplete when the graph is partial.

## Aggregated output: JSON vs SARIF

When you scan a **directory** with `--format json` and a single `-o` file, the CLI **concatenates one JSON report per file** (not a single JSON array). For a **one-document** aggregate, use **`--format sarif`**, or post-process, or use **`--quiet`** for per-file counts.

SARIF results use a **file URI** in the primary location; **line/column regions** are not attached there today. Triage and dedup should rely on **`partialFingerprints`** (same value as JSON `fingerprint` / CloudEvents `tauditfindingfingerprint` — see [finding-fingerprint.md](finding-fingerprint.md)) and, where present, **grouping** via `findingGroupId` / [finding-output-enhancements.md](finding-output-enhancements.md).

## Citing public workflows in documentation

**License.** Upstream projects are **not** “public domain” unless they say so. They are distributed under **open-source licenses** (Apache-2.0, MIT, MPL-2.0, etc.). Prefer **linking** to the canonical file on the project’s default branch (or a **pinned commit** for stability). If you **quote** YAML, use **short snippets** and name the project and file path; follow the project’s license for redistribution of full files.

**Attribution.** A minimal pattern: *“Example from the public [project/repo] workflow (see upstream for license).”*

**Degenerate mirrors.** A file that is **entirely commented-out** YAML (or otherwise contains no live `on:` / `jobs:`) may parse as an **empty graph** with no findings. That is not a “secure workflow” showcase — it is a **no-op** for analysis. Do not present such files as security exemplars without saying they are disabled or empty in that snapshot.

## “Clean” (zero-finding) examples from research passes

In large GHA sweeps, only a **small** slice of files produce **no** default-rule findings; many are unremarkable minimal workflows, and some mirrors are **stubs** (see above). Use such examples only with **method** (taudit version, flags, path layout) and **license/attribution** context — not as a guarantee of organizational security posture.

## Related

- [baselines.md](baselines.md) — onboarding without fixing history first
- [finding-fingerprint.md](finding-fingerprint.md) — stable dedup and SARIF / GitHub baseline behavior
- [verify.md](verify.md) — `verify --strict` and parse-failure exit semantics when directories must not be silently skipped
