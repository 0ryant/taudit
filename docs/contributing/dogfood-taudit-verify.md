# Dogfood: `taudit verify` on this repo’s workflows

Running [`taudit verify`](../verify.md) with `--policy` set to [`invariants/starter/`](../../invariants/starter/) against this repo’s [`.github/workflows/`](../../.github/workflows/) is **expected** to surface many findings. They are usually **advisory** here, not a signal that the release or quality workflows are “wrong” in isolation.

**Why:** The starter set is a **strict, copy-and-edit template library** (see [`invariants/starter/README.md`](../../invariants/starter/README.md)): rules such as “no unpinned third-party images anywhere,” PR-triggered broad identities, write-capable identities on PR paths, and OIDC-preference checks are tuned for **conservative org defaults**, not for every OSS maintainer workflow. This repository’s own CI intentionally uses patterns those rules flag (e.g. real third-party actions, PR-driven gates, token models that differ from a locked-down enterprise bundle).

**What the gate does:** [`scripts/quality-gate.sh`](../../scripts/quality-gate.sh) runs that verify pass after `taudit scan` and **does not fail** the stage on verify exit 1; it logs a short advisory line (aligned with the non-blocking `taudit verify` step in `.github/workflows/quality.yml`). Treat that as **informational dogfood** until a policy bundle is chosen that matches how this repo wants to enforce itself.

**Maintainer options:** Narrow or replace the policy under `invariants/` (subset of starter + repo-specific rules), adopt [`docs/baselines.md`](../baselines.md) / [`docs/suppressions.md`](../suppressions.md) for stable waivers or “new finding only” gating, or keep the current **advisory-on-pre-push** behavior and only tighten when the team agrees on an internal policy file.
