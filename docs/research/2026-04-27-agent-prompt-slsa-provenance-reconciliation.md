# Agent prompt: SLSA / provenance messaging reconciliation

Copy everything in the fenced block below to a coding agent (or run it yourself).

```
You are working in the taudit GitHub repository (Rust CLI, GitHub Actions release workflow).

## Goal

Align **all user-facing and historical claims** about “SLSA 3”, “SLSA L3”, and **release provenance** with what **actually ships** in `.github/workflows/release.yml`, and document **one** primary consumer verification path.

## Ground truth (verify before editing)

1. Read `.github/workflows/release.yml` — confirm how release archives and SBOMs are attested (today: `actions/attest-build-provenance@v1`, OIDC `id-token: write`, `attestations: write`).
2. Confirm there is **no** `slsa-framework/slsa-github-generator` workflow in repo (grep).
3. Read `README.md` (badge + Install), `CHANGELOG.md` (v1.0.1 “SLSA” bullet), `docs/release-trust.md`, `docs/gaps-implementation-prompt.md` (Gap 3).

## Required edits

1. **README.md**
   - The [![SLSA 3](...)]) badge must not over-claim. Either:
     - Link the badge to **GitHub’s artifact attestation documentation** or to `docs/release-trust.md#verifying-build-attestations-github`, **and**
     - Add a short, honest line: we use **GitHub Artifact Attestations** / `actions/attest-build-provenance`; verification is **`gh attestation verify`**; we are **not** claiming independent “SLSA certified” audit unless you add evidence.
   - Keep the existing `gh attestation verify …` example; ensure it matches GitHub CLI semantics (download asset first, then verify path).

2. **CHANGELOG.md**
   - In the **v1.0.1** section, replace or annotate the bullet that says **SLSA L3** via **`slsa-github-generator`** / **`slsa-verifier`**. Prefer: factual description of **GitHub attest-build-provenance** + **`gh attestation verify`**, plus a one-line **errata** if you rewrite history vs what was published at release time.

3. **docs/release-trust.md**
   - Add a section **“Verifying build attestations (GitHub)”** with `gh attestation verify` for a downloaded archive **and** note SBOMs are attested the same way if applicable.
   - Fix the sentence that says releases do **not** include “cryptographically signed” artifacts if attestations **are** cryptographic — clarify: **minisign** (or similar) on release **assets** is future work; **GitHub attestations** are separate and already in use.

4. **docs/gaps-implementation-prompt.md** (Gap 3 — SBOM + Provenance)
   - Mark what is **done** vs **optional follow-up** (e.g. `slsa-verifier`-compatible `.intoto.jsonl` as release assets only if a customer requires it).
   - Update “Acceptance” to match **implemented** verification (`gh attestation verify`), not only `slsa-verifier verify-artifact`.

## Optional (if time)

- Grep the repo for `slsa-verifier`, `slsa-github-generator`, “SLSA L3” and fix stray references.
- If the maintainers want stricter SLSA Build Track alignment, open a follow-up issue: adopt **slsa-github-generator** generic provenance **in addition to** or **instead of** current attestations — **do not** do that in this task unless explicitly asked.

## Acceptance

- No remaining doc claims **`slsa-github-generator`** unless it exists in workflow.
- **One** blessed verify command path documented in README + release-trust.
- `just check` or at least `cargo fmt --check` on touched files if you edit Rust (prefer no Rust edits for this task).

## Loop finish format (report back)

1. **What landed** — file list + summary.
2. **Show & tell** — exact commands to verify an attested release asset.
3. **What’s next** — optional hardening (minisign, slsa-github-generator, OpenSSF badge programs).
4. **Progress %** — messaging accuracy for this slice = 100%.
```
