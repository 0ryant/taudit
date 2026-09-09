# gha_remote_script_in_authority_job

Flags mutable remote script execution (`curl|bash`, `wget|sh`, mutable
`deno run`, and similar patterns) when the job also holds privileged authority.

This is the authority-bearing subset of remote script execution leads.

## Remediation

Pin remote scripts to immutable commits or releases, verify checksums before
execution, or run remote installers only in authority-free jobs.

## What counts as a mutable URL

A fetched script is treated as mutable unless its URL pins itself to bytes the
publisher cannot silently change. Three things count as pinned:

- a full commit SHA or digest in the path (40 or 64 hex characters),
- an explicit `refs/tags/` ref,
- a version-bearing path segment, such as `/v1.2.3/` or `/1.2.3/`.

Everything else is mutable, including bare vendor install endpoints like
`https://sh.rustup.rs`, `https://get.docker.com` and
`https://install.python-poetry.org`. Those carry no version at all, so the
publisher can change the executed bytes at any time, and one compromise reaches
every pipeline that trusts them.

Before taudit 1.4, only branch-pinned URLs such as
`raw.githubusercontent.com/<owner>/<repo>/main/install.sh` were flagged, so the
vendor-endpoint shape (by far the more common one in real pipelines) was missed
on every platform.
