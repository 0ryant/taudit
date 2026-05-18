# v1.2.0-rc.1 Helper Downgrade And Suppression Matrix

Status: L4 matrix input for the later helper-authority rule rewrite. This
document does not claim every row is implemented. It separates observed current
behavior from the intended downgrade/suppression contract.

Lane links: [Authority-timed evidence](workstreams/authority-timed-evidence.md)
requires helper-resolution findings to avoid broad PATH lint. [Output ceiling
matrix](output-ceiling-matrix.md) requires public output to distinguish helper
resolution, authority transport, authority origin, confidence, and evidence
strength without implying observed exploitability.

## Evidence Inspected

| Evidence | What it contributes |
| --- | --- |
| `docs/adr/0005-authority-edge-classifier-and-witness-handoff.md` | Defines helper-resolution classes, downgrade/suppressor rules, caller-provided-only penalty, and the rule that taudit must not treat every PATH mutation as a finding. |
| `docs/adr/0006-exploit-path-view-and-ruleset.md` | Defines the exploit-path rule scope and the required source-channel, authority, helper-resolution, transport, and downgrade dimensions. |
| `schemas/exploit-graph.v1.json` | Exposes the public helper-resolution, authority-transport, and authority-origin enums for the exploit-path projection. |
| `crates/taudit-core/src/exploit_path.rs` | Current exploit-path implementation. It suppresses catalog entries with `suppress: true` or a downgrade/suppress helper resolution before emitting a path. |
| `crates/taudit-core/src/rules.rs` | Current built-in helper-authority rules and tests. Toolcache helpers are skipped, but explicit ambient `setup-gcloud` mode is still treated as path-rule enabling in this older rules layer. |
| `docs/rules/gha_toolcache_absolute_path_downgrade.md` | Current precision-guard documentation for trusted toolcache absolute helper execution. |
| `docs/rules/later_secret_materialized_after_path_mutation.md` | Current rule documentation stating PATH mutation alone is insufficient. |

## Current Behavior Summary

- Observed: `exploit_path.rs` classifies helper resolution as
  `bare_command`, `shell_string`, `toolkit_which`, `absolute_path`,
  `toolcache_path`, `action_owned_path`, `user_supplied_absolute_path`,
  `ambient_path_by_explicit_mode`, or `unknown`.
- Observed: only `bare_command`, `shell_string`, and `toolkit_which` are
  path-selected helper resolutions in the exploit-path projection.
- Observed: `absolute_path`, `toolcache_path`, `action_owned_path`,
  `user_supplied_absolute_path`, and `ambient_path_by_explicit_mode` are treated
  as downgrade/suppress resolutions in `exploit_path.rs`.
- Observed: current `rules.rs` helper profiles skip `toolcache_absolute`
  helpers for helper-path rules.
- Observed: current `rules.rs` has positive and negative unit coverage for
  several helper-path rules, including toolcache suppression and path/authority
  requirements.
- Observed: current `rules.rs` now has a focused path-only regression test:
  `gha_path_mutation_alone_does_not_fire_helper_authority_rules`.

## Matrix

| Shape | Required classifier evidence | L4 target treatment | Current behavior | Missing or follow-up proof |
| --- | --- | --- | --- | --- |
| PATH mutation alone | Earlier same-job write to `GITHUB_PATH`, with no later helper action/step and no later authority materialization. | Suppress. It is not a helper-authority finding. | `rules.rs` rules require a later known action/helper and/or authority. Focused unit coverage now asserts path-only silence across the current helper-authority family. | Add exploit-graph fixture with `path_count: 0` once L4 owns canonical event-builder tests. |
| Trusted absolute path | Later helper is invoked through a trusted absolute path not derived from workspace, temp, event payload, mutable env, or caller-controlled input. | Suppress helper-PATH findings. Keep unrelated lower-layer findings, such as dynamic-linker env poisoning, separate if their own evidence exists. | `exploit_path.rs` has `absolute_path` as a downgrade/suppress resolution. No observed catalog entry or fixture currently proves the row end to end. | Add a source-anchored absolute-path catalog fixture and negative rule/export test. |
| Trusted toolcache path | Later helper is installed/resolved from a trusted runner toolcache or action-managed toolcache absolute path. | Suppress helper-PATH findings; optionally retain a non-emitted precision-guard explanation. | `exploit_path.rs` includes GoReleaser as `toolcache_path` with `suppress: true`. `rules.rs` skips `toolcache_absolute` profiles, and `gha_toolcache_action_does_not_fire_helper_path_rules` covers the legacy helper rules. | Add exploit-graph JSON fixture proving toolcache suppression yields no path and does not leak as a default finding. |
| Action-owned path | Later helper is invoked from an action-owned install or package path that prior workflow state cannot rewrite. | Suppress or confidence-downgrade helper-PATH findings. Do not suppress if the actual helper path is workspace/temp/event-controlled despite the action boundary. | `exploit_path.rs` has `action_owned_path` as a downgrade/suppress resolution. Current `rules.rs` remediations reference action-owned paths, but no observed generic action-owned suppressor fixture exists. | Add action-owned-path catalog metadata plus a negative fixture. Include a counter-fixture where the path is action-named but workspace-controlled and must not suppress. |
| User-supplied absolute path | Caller provides an absolute helper path through action input or env. | Downgrade only when the path is proven trusted; otherwise classify as unknown or path-confusion risk. Do not treat absolute syntax alone as trust. | `exploit_path.rs` currently lists `user_supplied_absolute_path` as downgrade/suppress. No observed rules-layer fixture distinguishes trusted from caller-controlled absolute paths. | L4 needs a trust predicate for user-supplied absolute paths before this can be promoted from enum support to implementation claim. |
| Explicit ambient mode | Action explicitly opts into using the system or ambient helper, such as `skip_install`-style modes. | Downgrade or suppress by mode. If authority still reaches a mutable PATH-selected helper, emit only with explicit evidence and confidence-limited copy. | Divergence observed: `exploit_path.rs` models `google-github-actions/setup-gcloud` with `ambient_path_by_explicit_mode` behind `skip_install` and suppresses it; current `rules.rs` uses `skip_install=true` as the condition for its path rule. | L4 rewrite must choose the normalized behavior and update either rules or docs/tests. Add positive/negative fixtures for explicit ambient mode with and without authority transport. |
| Caller-provided-only forwarding | A caller-provided token/secret is forwarded to an expected generic CLI wrapper, without action-minted, generated, derived, OIDC, or observed sink evidence. | Downgrade rather than promote to the strongest helper-authority claim. Public output must identify `caller_provided_secret` separately from action-minted/generated authority. | `exploit_path.rs` exposes `caller_provided_secret` and uses it for Docker login authority, but no origin-based downgrade/suppressor is implemented. Current `rules.rs` still emits stdin/env/argv findings when the other path and authority predicates match. | Add table-driven tests that prove caller-provided-only cases get downgraded, while action-minted/generated/OIDC cases retain stronger severity/confidence. |
| Unknown helper resolution | Later authority exists, but helper resolution cannot be classified as path-selected or trusted. | Confidence-limit. Do not silently promote; do not suppress as trusted. | `unknown` exists in the exploit schema and enum. No observed current catalog entry exercises it. | Add unknown-resolution fixture after L4 event model names confidence fields. |

## Rule Rewrite Inputs

The L4 rewrite should evaluate these gates in order:

1. Scope gate: GitHub Actions same-job ordering unless another platform/event
   model is explicitly added.
2. Prior mutable channel gate: a concrete mutable channel, currently
   `GITHUB_PATH`, with ordering before the helper action/step.
3. Helper-resolution gate: path-selected helper resolutions emit only for
   `bare_command`, `shell_string`, or `toolkit_which`.
4. Suppressor gate: trusted `absolute_path`, `toolcache_path`,
   `action_owned_path`, trusted `user_supplied_absolute_path`, and explicit
   ambient modes must downgrade or suppress before severity is assigned.
5. Authority gate: later authority materialization plus transport is required;
   action name, PATH mutation, or helper name alone is insufficient.
6. Origin gate: caller-provided-only forwarding is weaker than action-minted,
   generated, derived, or OIDC authority and should lower severity/confidence
   unless additional evidence raises it.
7. Output gate: public findings may say static/inferred helper-authority path,
   never observed sink, hosted witness, disclosure route, or CVE without
   explicit gated evidence.

## Test Targets For L4

| Target | Expected result |
| --- | --- |
| PATH mutation only | No helper-authority finding and exploit `path_count: 0`. |
| Generic helper use only | No helper-authority finding without prior mutable channel and authority transport. |
| Trusted absolute helper path | Suppressed helper-PATH finding; no public exploit path. |
| Toolcache absolute helper path | Suppressed helper-PATH finding; precision guard may remain doc-only. |
| Action-owned helper path | Suppressed when path is action-owned and not workflow-writable; not suppressed when workspace/temp-controlled. |
| Explicit ambient helper mode | Downgraded/suppressed according to normalized L4 decision, with current `rules.rs` divergence resolved. |
| Caller-provided-only forwarding | Lower severity/confidence than action-minted or generated authority; origin remains visible as `caller_provided_secret`. |
| Action-minted or generated credential | Positive helper-authority path when prior mutation, path-selected helper, transport, and ordering are present. |
| Observed sink absent | No `ObservedSink`, no observed count, and no observed wording without explicit witness input. |

## Downstream Dependency Unblocked

This matrix gives the later L4 rule rewrite an explicit false-positive control
contract and gives L5 output work the distinction it needs for public helper
resolution, authority transport, authority origin, confidence, and suppressed or
downgraded cases.
