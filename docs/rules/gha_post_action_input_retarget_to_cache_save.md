# gha_post_action_input_retarget_to_cache_save

Flags `actions/cache` restore/save boundaries when a later same-job step mutates
ambient cache path, key, or `INPUT_`-style environment state.

This is a post-action retargeting lead. It is useful for corpus triage and
hardening, not a standalone vulnerability claim.

## Remediation

Keep cache path and key inputs immutable after restore, avoid later `GITHUB_ENV`
writes to `INPUT_*` or cache variables, or split cache restore/save behavior
across explicit job boundaries.
