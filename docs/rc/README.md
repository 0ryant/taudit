# Release Candidate Planning

This directory holds planning and control documents for taudit prerelease work.
It is not shipped-feature documentation by itself. A file here can describe an
RC target, an execution lane, a blocker, or a gate before the corresponding code
has merged.

Current RC track:

- [v1.2.0](v1.2.0/README.md) - `v1.2.0-rc.1: Authority Evidence Platform`

Release candidate work must stay semver-honest:

- planning docs may describe pending scope;
- operator docs must describe merged behavior only;
- every detection, schema, output, fingerprint, suppression, or CLI behavior
  change needs a changelog detection delta before tagging;
- stable promotion follows `docs/RELEASE_GATES.md`.
