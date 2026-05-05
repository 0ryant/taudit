# GHA Toolcache Absolute Path Downgrade

**Rule ID:** `gha_toolcache_absolute_path_downgrade`
**Severity:** Info
**Category:** Precision
**Tags:** security, precision, github-actions

## Detection

This is a precision guard, not an emitted finding in normal scans. It documents actions that install helpers into the runner toolcache and invoke absolute paths, so helper-PATH rules do not over-fire.

Current negative coverage includes `goreleaser/goreleaser-action` for the main GoReleaser binary path.

## Risk

None by itself. The guard exists to avoid treating action-owned absolute helper execution as mutable PATH resolution.

## Remediation

No remediation required for this guard. Use it as a model: install sensitive helpers into trusted toolcache locations and invoke absolute paths.
