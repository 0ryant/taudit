# Suppression, Baseline, And Exit Matrix

Status: L5-07 evidence lane.

## Scope

This lane adds black-box CLI coverage for the ADR 0018 adoption corridor:
`scan`, `verify`, per-pipeline baselines, severity thresholds, and explicit
waivers. The lane does not change production behavior.

Changed test surface:

- `crates/taudit-cli/tests/suppression_baseline_exit_matrix.rs`

No fixture files were added. The test creates all policy, baseline, and
suppression state in per-test temp directories and reuses
`tests/fixtures/propagation-leaky.yml`.

## Matrix

| Case | Command surface | Expected result |
|---|---|---|
| Threshold scan | `taudit scan --severity-threshold high` | Exit 0; stderr points operators to `taudit verify`. |
| Legacy JSON baseline | `taudit scan --baseline <prior-json>` | Exit 0; matching findings are removed from JSON output. |
| Unsuppressed verify | `taudit verify --policy <high-policy>` | Exit 1; custom high violation gates. |
| Downgrade waiver plus threshold | `taudit verify --suppressions <file> --severity-threshold high` | Exit 0; matched high finding downgrades below the threshold. |
| Tag-only waiver plus threshold | `taudit verify --suppression-mode tag-only --severity-threshold high` | Exit 1; tag-only is metadata-only for verify gating. |
| Critical waiver without expiry | `taudit verify --policy <critical-policy> --suppressions <missing-expiry>` | Exit 2; critical waivers must expire. |
| Baseline init | `taudit baseline init --root <dir>` | Exit 0; one per-pipeline baseline is written. |
| Baseline-aware verify | `taudit verify --baseline-root <dir>` | Exit 0; pre-existing custom finding is suppressed. |
| Gate-on-all verify | `taudit verify --baseline-root <dir> --gate-on-all` | Exit 1; baseline suppression is bypassed. |
| Baseline diff | `taudit baseline diff --root <dir>` | Exit 0; reports `0 NEW` and pre-existing findings. |

## Boundaries

The test intentionally drives the real CLI binary rather than internal helper
functions. This keeps the evidence tied to operator-observable behavior:
process exit codes, stdout summaries, and stderr warnings.

The matrix avoids global repo state by setting an isolated current directory
for each command and passing explicit policy, suppression, and baseline paths.
That prevents existing local `.taudit` material or concurrent worker changes
from masking the contract under test.

## Residual Risk

This lane does not prove SARIF, CloudEvents, or terminal projection of
suppression metadata. It also does not exercise critical baseline accept
waivers; this matrix focuses on the CLI exit corridor and the suppression
file hard stop for critical waivers without `expires_at`.

## Next Dependency Unblocked

ADR 0018 can cite one focused CLI test target as evidence that the adoption
flow has machine-checked behavior for informational scans, verify gating,
baseline adoption, and waiver interaction with severity thresholds.
