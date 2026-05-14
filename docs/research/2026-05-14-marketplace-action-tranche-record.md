# Marketplace Action Tranche Record

Date: 2026-05-14
Branch: `codex/marketplace-action-tranche`
Supervisor stop time: 2026-05-15 02:37 BST

## Goal

Drive the full GitHub Marketplace action section toward code-complete using
parallel agents. The action contract is
[`docs/integrations/github-marketplace-action-contract.md`](../integrations/github-marketplace-action-contract.md).

## Criteria

- CHK[1]: Dedicated `taudit-action` repo scaffold exists.
- CHK[2]: Root `action.yml` exposes the v1 typed input/output contract.
- CHK[3]: Wrapper builds argv arrays and does not use shell-string execution.
- CHK[4]: `verify` preserves exit codes and policy/builtin/baseline/suppression
  semantics.
- CHK[5]: Tests cover input validation, argv mapping, no `extra-args`, and
  injection resistance.
- CHK[6]: README explains verify, scan bootstrap, graph output, baselines,
  suppressions, SARIF, permissions, pinning, and security model.
- CHK[7]: Local verification runs and remaining external publish gates are
  explicit.

## Agent Lanes

- Worker A: implementation scaffold and runtime wrapper.
- Worker B: contract/unit tests and fixtures.
- Worker C: Marketplace README and examples.
- Reviewer D: read-only security/release review.

## Decisions

- DEC[1]: Create a dedicated public repo at
  `https://github.com/0ryant/taudit-action`; this product repo remains the
  contract/source-of-truth for the action surface.
- DEC[2]: Use Node with no runtime dependencies where possible to keep the
  Marketplace wrapper auditable.

## Evidence

- Observed current product CLI version: `crates/taudit-cli/Cargo.toml`
  declares `1.1.2`.
- Observed release asset naming in `docs/release-trust.md` and
  `packaging/homebrew/taudit.rb`.
- Observed old nested composite action contains unsafe shell interpolation and
  raw `extra-args`; it is not reused.
- Created `/Users/rytilcock/prj/taudit-action` and committed initial action
  implementation at `8b53b1d Initial taudit marketplace action`.
- Created public GitHub repository `0ryant/taudit-action` and pushed `main`.
- `npm test` in `/Users/rytilcock/prj/taudit-action`: 13/13 contract tests pass.
- `npm run check` in `/Users/rytilcock/prj/taudit-action`: Node syntax checks pass.
- `actionlint /Users/rytilcock/prj/taudit-action/examples/*.yml`: pass.
- `cargo test -p taudit --test cli_contract verify_ -- --nocapture`: 10/10 pass.
- `TAUDIT_ADO_PAT=... target/debug/taudit scan ... --ado-org ... --ado-project ...`:
  ADO PAT presence is detected without leaking the PAT into JSON output.
- `git diff --check`: pass.

## Residual Risk

- GitHub Marketplace publication itself may require external GitHub account/org
  state: public repo, Developer Agreement, release UI, and hosted smoke.
- `yamllint` is unavailable locally.
- Hosted-runner smoke and real release-asset download verification were not run
  in this local tranche.
