//! # `taudit-core` — workspace-internal authority graph + rules engine
//!
//! ## Architecture
//!
//! `taudit-core` is the workspace-internal **engine**: graph mutation,
//! BFS propagation, rule evaluation, baselines, suppressions, ignore-pattern
//! handling, and the cross-sink helpers (`compute_fingerprint`,
//! `compute_finding_group_id`, `rule_id_for`) that JSON / SARIF /
//! CloudEvents sinks call directly.
//!
//! The **stable wire types** (everything that crosses the JSON / SARIF /
//! CloudEvents boundary — `Finding`, `FindingCategory`, `Severity`,
//! `Recommendation`, `FindingSource`, `FixEffort`, `FindingExtras`,
//! `NodeKind`, `EdgeKind`, `TrustZone`, `AuthorityCompleteness`,
//! `IdentityScope`, `GapKind`, `Node`, `Edge`, `PipelineSource`,
//! `ParamSpec`, `AuthorityEdgeSummary`, `PropagationPath`, `NodeId`,
//! `EdgeId`, every `META_*` metadata-key constant) live in the
//! [`taudit-api`](https://crates.io/crates/taudit-api) crate.
//!
//! Each module here re-exports the wire types it used to own so
//! existing in-tree imports (`use taudit_core::finding::Finding`,
//! `use taudit_core::graph::NodeKind`, …) keep compiling unchanged.
//!
//! ## API stability
//!
//! `taudit-core` is a **workspace-internal library**, NOT a stable public
//! API. External consumers (`tsign`, `axiom`, custom automation, SIEMs,
//! third-party tooling) should depend on `taudit-api` directly (for the
//! Rust contract) or consume the JSON / SARIF / CloudEvents output
//! contracts (for cross-language integration). Both are versioned and
//! treated as load-bearing:
//!
//!   * `taudit-api` `0.x` — the Rust wire-type contract. While at `0.x`
//!     additive changes can ship in any minor; breaking changes require
//!     a `0.{N+1}` minor bump and a CHANGELOG migration note. At `1.0`
//!     this lifts to standard semver.
//!   * `contracts/schemas/taudit-report.schema.json` — JSON output
//!   * `schemas/finding.v1.json` — single finding object
//!   * `schemas/baseline.v1.json` — baseline file format
//!   * `contracts/schemas/taudit-cloudevent-finding-v1.schema.json` —
//!     CloudEvents extension attributes
//!   * SARIF 2.1.0 — `partialFingerprints` keys are stable
//!
//! Symbols marked `#[doc(hidden)]` here are required to be `pub` for
//! inter-crate visibility within this workspace (sink crates call
//! `compute_fingerprint`, `compute_finding_group_id`, `rule_id_for`,
//! `downgrade_severity` directly), but their signatures may change between
//! minor `taudit` versions without a SemVer bump on `taudit-core`. Treat
//! them as `pub(crate-tree)`, not `pub`.
//!
//! See ADR 0001 (graph as product) and the v1.1.0 release notes for the
//! full rationale behind this split.

pub mod baselines;
pub mod custom_rules;
pub mod error;
pub mod evidence;
pub mod exploit_path;
pub mod finding;
pub mod graph;
pub mod ignore;
pub mod map;
pub mod ports;
pub mod propagation;
pub mod rules;
pub mod summary;
pub mod suppressions;

// ── Defense-in-depth caps for adversarial config files ────────────────
//
// taudit ingests YAML from PRs (pipeline files, custom-rule files,
// suppressions, .tauditignore). Without caps, a hostile contributor can
// allocate hundreds of MiB by submitting a single file and DoS the CI
// runner before any rule logic runs. The caps below bound that surface.
//
// They are deliberately *constants*, not flags: every realistic CI YAML
// is well under these limits, and a flag would just be another lever
// for an attacker who has already convinced you to merge their PR. If
// a legitimate use case for a larger file emerges we can revisit; for
// now the council prefers a hard ceiling.

/// Maximum size in bytes of any single pipeline / config / invariant YAML
/// taudit will read.
///
/// Files above this size are rejected with a clear error before any
/// allocation for `serde_yaml`. 2 MiB is well above the largest realistic
/// CI YAML; the largest legitimate workflow in the existing
/// `corpus/` is under 100 KiB.
pub const MAX_INPUT_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Read `path` to a `String`, but refuse files larger than
/// [`MAX_INPUT_FILE_BYTES`].
///
/// Why this exists: a 50 MiB hostile YAML allocates ~150 MiB peak inside
/// `serde_yaml` (triple-parse + a `serde_yaml::Value` for every node).
/// Capping at the filesystem boundary keeps that allocation pre-empted —
/// we never even hand the bytes to the YAML parser.
///
/// `metadata` follows symlinks; that is fine *here* because callers that
/// need an explicit symlink fence call [`read_capped_with_symlink_fence`]
/// instead, which canonicalises before calling this.
///
/// Returned [`io::Error`]s use `InvalidData` for the size-cap rejection so
/// callers can distinguish IO failure from cap rejection if they want.
pub fn read_capped(path: &std::path::Path) -> std::io::Result<String> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_INPUT_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "taudit refuses files larger than {} bytes ({} MiB). {} is {} bytes. \
                 If you have a legitimate use case for a larger file, please file an issue.",
                MAX_INPUT_FILE_BYTES,
                MAX_INPUT_FILE_BYTES / (1024 * 1024),
                path.display(),
                meta.len(),
            ),
        ));
    }
    std::fs::read_to_string(path)
}

/// Read `path` to a `String`, but only if it is either (a) not a symlink
/// or (b) a symlink whose canonical target is a descendant of
/// `cwd_canonical`. Also enforces [`MAX_INPUT_FILE_BYTES`].
///
/// Used for ambient config files that live at the repo root and that an
/// adversarial PR could plant as a symlink — `.taudit-suppressions.yml`
/// and `.tauditignore`. A symlink to `/etc/passwd` plus a YAML parse
/// failure was previously a content-leak channel via stderr; this helper
/// closes that.
///
/// `cwd_canonical` should be `std::env::current_dir()?.canonicalize()?`.
/// Pass it in (rather than computing it here) so callers can canonicalise
/// once per scan and so tests can fence against a temporary working
/// directory.
///
/// On macOS, both `cwd_canonical` and the symlink target resolve through
/// `/private/tmp` so the descendant check stays correct under the OS's
/// hidden symlink-prefix.
pub fn read_capped_with_symlink_fence(
    path: &std::path::Path,
    cwd_canonical: &std::path::Path,
) -> std::io::Result<String> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        // canonicalize follows the chain; a broken symlink errors here,
        // which is the right answer (we are not going to read it).
        let target = std::fs::canonicalize(path)?;
        if !target.starts_with(cwd_canonical) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to read symlinked {} pointing to {} outside the working directory",
                    path.display(),
                    target.display(),
                ),
            ));
        }
    }
    read_capped(path)
}
