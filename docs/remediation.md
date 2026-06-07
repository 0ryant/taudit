# `taudit remediate` — Safe Pipeline Hardening With Rollback

`taudit remediate` adds a conservative, auditable hardening workflow to taudit.

The command group is designed for low break risk:

- Read-only by default (`suggest`, `diff`)
- Conservative transforms only in v1
- Automatic backups under `.taudit/backups/`
- Post-apply validation
- Auto-restore on validation failure
- Explicit rollback by backup id

## Synopsis

```text
taudit remediate suggest [PATH...] [--format text|json]
taudit remediate diff [PATH...] [--format text|json]
taudit remediate --unstable apply [PATH...] --policy <FILE_OR_DIR>
                     [--format text|json]
                     [--min-confidence <0..1>]
                     [--allow-risky]
                     [--force]
                     [--backup-root <DIR>]
taudit remediate --unstable rollback --backup-id <ID> [--backup-root <DIR>] [--force]
taudit remediate list-backups [--backup-root <DIR>] [--format text|json]
```

## v1 Transform Policy

v1 intentionally limits scope to low-risk, high-confidence rewrites.

Currently implemented transform:

- `gha_add_workflow_permissions_readonly`
  - Condition: GitHub Actions workflow has top-level `on:` and no top-level `permissions:`
  - Action: prepend:

```yaml
permissions:
  contents: read
```

This reduces default token scope without changing the workflow execution graph.

Read-only guidance also covers findings that are too context-sensitive to patch
automatically:

- `gha_review_broad_workflow_permissions`
  - Condition: GitHub Actions workflow declares workflow-level write authority.
  - Action: report guidance only. Reducing permissions can break release,
    deploy, or package-publish jobs without maintainer intent.
- `gha_review_unpinned_action_refs`
  - Condition: GitHub Actions workflow uses third-party actions with mutable
    refs such as tags or branches.
  - Action: report guidance only. Pinning requires resolving and reviewing the
    intended upstream commit SHA; taudit does not guess pins.

`suggest` emits both patchable and review-only guidance. `diff` emits patches
only for transforms with `patch_available: true`, then prints review-only
guidance separately. `apply` ignores review-only guidance.

## Safety Model

### Read-only operations

- `suggest` and `diff` never write files.

### Apply flow

`taudit remediate --unstable apply` performs:

1. Build candidate patch plan.
2. Filter by risk/confidence:
   - default: low-risk only, confidence >= `0.90`
   - `--allow-risky` enables medium/high-risk transforms
3. Refuse dirty-file apply in git repos unless `--force` is set.
4. Write backups and manifest into `.taudit/backups/<backup-id>/`.
5. Apply rewrites.
6. Validate:
   - YAML parse check on rewritten files
   - `taudit verify --policy <...>` re-run on rewritten files
7. On validation failure:
   - auto-restore originals
   - exit `1`

### Rollback flow

`taudit remediate --unstable rollback --backup-id <ID>`:

1. Loads backup manifest.
2. Verifies each target file hash matches expected post-apply hash.
3. Refuses restore on hash mismatch unless `--force`.
4. Restores original snapshots.

## Backup Layout

Default root: `.taudit` (override with `--backup-root`).

```text
.taudit/
  backups/
    index.json
    <backup-id>/
      manifest.json
      original/
      rewritten/
      patches/
```

### `manifest.json`

Captures:

- `backup_id`
- `created_at`
- `taudit_version`
- `transform_ids`
- per-file:
  - `path`
  - `pre_apply_hash`
  - `post_apply_hash`
  - `original_snapshot`
  - `rewritten_snapshot`
  - `forward_patch`
  - `reverse_patch`
- validation:
  - `parse_ok`
  - `verify_exit_code`
  - `verify_stdout`
  - `verify_stderr`
  - `restored_on_failure`

## Exit Codes

`remediate` commands follow the same high-level contract as `verify`:

- `0` success / no-op success
- `1` validation/policy failure in apply path
- `2` usage or structural error

## Operational Guidance

### Safe rollout

1. Run `suggest` and `diff` in CI report-only mode first.
2. Apply on a small canary repo set.
3. Keep `--allow-risky` off initially.
4. Gate merges on post-apply `verify` success.

### Recovery playbook

1. List backups:

```bash
taudit remediate list-backups
```

2. Roll back specific operation:

```bash
taudit remediate --unstable rollback --backup-id <id>
```

3. If local edits intentionally changed the file after apply, re-run with `--force`.

## Out of Scope for v1

- High-risk semantic rewrites by default
- Platform-specific deep refactors
- Automatic policy authoring
- Bulk auto-merge orchestration
- Guessing full commit SHAs for unpinned third-party actions
- Automatically reducing broad permissions when required scopes are ambiguous
