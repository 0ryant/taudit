# taudit Threat Model

This document records the security boundaries and trust assumptions for taudit's
externally-facing or write-capable subsystems. It is a required pre-condition for
the v1.0.0 release and must be updated whenever a subsystem's boundary changes.

---

## 1. `taudit update` — version check HTTP call

### What it does

After `taudit scan` and `taudit verify` complete, taudit spawns a background
thread that sends one HTTPS GET request to `https://crates.io/api/v1/crates/taudit`
and prints a one-line notice to stderr if a newer version is available.

The call is suppressed entirely when:

- `TAUDIT_NO_UPDATE_CHECK=1` is set in the environment, or
- `CI=true` is set in the environment (all major CI platforms set this).

The subcommand `taudit update` triggers the same call synchronously.

### Trust assumptions

| Component | Trusted? | Notes |
|---|---|---|
| `crates.io` TLS certificate | Yes | Verified by the OS/rustls trust store |
| `crates.io` JSON response | Partially | Only `crate.newest_version` is read; the string is compared but never executed |
| Network path (DNS, routers) | No | Attacker on the network can interfere — see threats below |

### Threats and mitigations

**T1 — DNS hijacking / redirect to attacker-controlled server**

*Impact*: Attacker returns a crafted JSON body; taudit reads `newest_version` from it.
*Current mitigation*: TLS verification is enforced by `ureq` (rustls); a rogue server
without a valid certificate for `crates.io` cannot complete the TLS handshake.
*Residual risk*: If the OS trust store is compromised or a rogue CA is installed, a
MITM can forge the response. Mitigated by `TAUDIT_NO_UPDATE_CHECK=1` in locked-down environments.

**T2 — Version string injection via crafted response**

*Impact*: If the version string were passed to a shell or rendered unsanitised, a
malicious response could trigger command injection.
*Current mitigation*: The version string is only used in an `eprintln!` format string
with `{}` (not `{:?}` or any shell invocation). It is never executed.
*Residual risk*: None identified. The comparison is pure string equality; the output
is a static message that embeds the version string in a human-readable line.

**T3 — Network availability / denial of service**

*Impact*: If crates.io is unreachable, taudit scan/verify could stall.
*Current mitigation*: The HTTP call has a 3-second timeout. On timeout or any error,
`check_latest_version()` returns `None` silently; the scan result is unaffected.
CI runs are suppressed entirely (`CI=true`).

**T4 — Supply-chain substitution of `crates.io` package**

*Impact*: If an attacker uploads a package named `taudit` with a higher version,
taudit would print an upgrade nudge pointing users to a malicious release.
*Current mitigation*: The message prints only the version string; it does not construct
a URL or run any download command. The user must independently run `cargo install taudit`
to upgrade. crates.io's crate ownership model prevents substitution by non-owners.

### Acceptance

The HTTP subsystem is read-only, timeout-bounded, CI-suppressed, and never executes
any data from the network. Risk is accepted at current mitigations.

---

## 2. YAML deserialization attack surface

### What it does

taudit parses two distinct categories of YAML input:

1. **Pipeline files** (`*.yml` / `*.yaml`) — the subject of the scan.
   Parsed by `serde_yaml` in each platform parser (`taudit-parse-gha`,
   `taudit-parse-ado`, `taudit-parse-gitlab`).

2. **Configuration files** — operator-controlled inputs:
   - `.tauditignore` — ignore rules (`ignore:` list)
   - `.taudit-suppressions.yml` — per-finding waivers with audit trail
   - Authority Invariant YAML files (`--invariants-dir`) — custom rules

### Trust assumptions

| Input | Source trust | Notes |
|---|---|---|
| Pipeline files | Untrusted | Attacker controls the CI YAML being scanned |
| `.tauditignore` | Operator (trusted) | Lives in the repo; committer has push access |
| `.taudit-suppressions.yml` | Operator (trusted) | Same — deliberate waiver file |
| Invariant YAML files | Operator (trusted) | Provided via `--invariants-dir` |

### Threats and mitigations

**T5 — Billion-laughs / deeply-nested YAML in pipeline file**

*Impact*: A crafted pipeline file could cause `serde_yaml` to consume unbounded
memory or CPU during parsing, stalling or crashing the scan.
*Current mitigation*: `serde_yaml` 0.9 uses `libyaml` underneath, which does not
expand YAML aliases by default in the Rust binding; the deserializer reads into a
`serde_yaml::Value` tree with no recursion into anchors. Deeply nested input
increases allocation but does not multiply (no alias expansion).
*Residual risk*: Pathological nesting can still consume memory proportional to depth.
The dense-graph safety guard (`--force-scan-dense` required above 50 000 nodes /
5x edge ratio) bounds the downstream BFS cost; the parse-time risk is lower.
A future hardening step could add a byte-count limit on individual YAML files.

**T6 — Malicious invariant YAML injecting shell commands**

*Impact*: If invariant YAML were evaluated as code, an attacker who controls
`--invariants-dir` could inject shell commands.
*Current mitigation*: Invariant YAML files are deserialized into a typed Rust struct
(`AuthorityInvariant`) via `serde`. No field is passed to a shell. The symlink-traversal
guard (`--invariants-allow-external-symlinks` defaults to false) prevents an attacker
from pointing the invariants directory at a symlink that escapes the repo tree.
*Residual risk*: None identified for the current invariant schema fields.

**T7 — Path traversal in suppression or invariant file paths**

*Impact*: If a path field in a config file were used to construct filesystem paths
without sanitisation, an attacker could read or write outside the intended directory.
*Current mitigation*: Suppression files reference findings by category/fingerprint,
not filesystem paths. Invariant files reference source/sink node types. Neither
constructs arbitrary filesystem paths from YAML values.

### Acceptance

Pipeline YAML is untrusted input and is parsed defensively into typed structures with
no code evaluation. Configuration YAML is operator-trusted and is also deserialized
into typed structs. Risk is accepted at current mitigations.

---

## 3. `remediate apply` — disk-write and process-invocation boundaries

### What it does

`taudit remediate apply` is a write-path command that:

1. Reads pipeline files from disk.
2. Detects candidate remediations via `detect_suggestions()`.
3. Applies text transforms in memory.
4. Writes the modified files back to disk.
5. Writes a backup bundle to `.taudit/backups/<backup-id>/`.
6. Invokes `taudit verify` as a subprocess to validate the rewrite.
7. If validation fails, restores original files from the backup.

The command is gated behind `--unstable` until the remediation engine stabilises.

### Trust assumptions

| Component | Trusted? | Notes |
|---|---|---|
| Input pipeline files | Operator (trusted) | Paths are supplied by the invoking user |
| `--policy` path | Operator (trusted) | Supplied by the invoking user |
| `--backup-root` path | Operator (trusted) | Defaults to `.taudit/` in CWD |
| Subprocess (`taudit verify`) | Self | Invoked as the current executable via `std::env::current_exe()` |

### Threats and mitigations

**T8 — Path traversal in backup storage**

*Impact*: A crafted pipeline file path or backup ID could escape the `.taudit/backups/`
directory and write files to arbitrary filesystem locations.
*Mitigations*:
- `storage_rel_path()` strips all `..`, `.`, and root components from file paths
  before constructing backup snapshot paths (see `remediate.rs:807`).
- `is_valid_backup_id()` rejects any backup ID containing `..`, `/`, or `\` and
  enforces a 128-character maximum length (see `remediate.rs:835`).
- Backup IDs are allocated by taudit itself (timestamp + PID + nanosecond suffix);
  they are never derived from user-controlled input.

**T9 — Subprocess injection via `--policy` path**

*Impact*: If the policy path were passed to a shell, a crafted path could inject
shell commands.
*Current mitigation*: `run_verify_subprocess()` constructs the subprocess command
with `std::process::Command::new(exe)` and passes each argument as a separate
`cmd.arg()` call — never via a shell. There is no `sh -c` invocation.

**T10 — Symlink attack on backup directory**

*Impact*: If `.taudit/backups/` were replaced with a symlink to a sensitive directory,
backup writes could overwrite files outside the repo.
*Current mitigation*: `allocate_backup_id()` calls `fs::create_dir_all(&backups_dir)`
before writing. On most OS configurations, `create_dir_all` will follow existing
symlinks; this is a known gap.
*Residual risk*: An attacker with write access to the working directory could pre-place
a symlink. This requires the same level of access as the user running taudit, so the
threat is equivalent to the user directly having write access to the symlink target.
Accepted as a local-privilege-parity risk.

**T11 — Uncommitted-edits guard bypass**

`cmd_apply` calls `ensure_no_uncommitted_edits()` before writing, which runs
`git status --porcelain` per file. If `--force` is passed, this check is skipped.
The `--force` flag is intentional and documented; it is the operator's responsibility.

**T12 — Current-executable resolution (`std::env::current_exe`)**

*Impact*: If the taudit binary were replaced between process start and subprocess
invocation, the subprocess could run a different binary.
*Current mitigation*: `current_exe()` resolves the path at call time, which is after
the command-line has been parsed. On Linux, `/proc/self/exe` follows the original
binary even after replacement. On macOS/Windows, the path is resolved from the
process launch. TOCTOU here is equivalent to the risk of the binary itself being replaced,
which is outside taudit's threat boundary.

### Acceptance

The write-path operations are gated behind `--unstable` during the stabilisation
period. The identified residual risks (T10 symlink, T12 TOCTOU) require pre-existing
write access to the working directory and are accepted as local-privilege-parity risks.

---

## Out of scope

- Privilege escalation: taudit never requests elevated privileges.
- Network listeners: taudit never binds a port or socket.
- Credential storage: taudit reads no secrets and writes none. The version-check
  call carries only the `User-Agent` header (tool name and version).
- Multi-tenant use: taudit is a single-user CLI. Running it in a shared environment
  where other users control input files is outside the intended deployment model.

---

*Last updated: 2026-04-26. Review when any of the following change:*
*the HTTP client, YAML parser, write-path commands, subprocess invocations, or backup schema.*
