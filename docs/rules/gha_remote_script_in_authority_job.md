# gha_remote_script_in_authority_job

Flags mutable remote script execution (`curl|bash`, `wget|sh`, mutable
`deno run`, and similar patterns) when the job also holds privileged authority.

This is the authority-bearing subset of remote script execution leads.

## Remediation

Pin remote scripts to immutable commits or releases, verify checksums before
execution, or run remote installers only in authority-free jobs.
