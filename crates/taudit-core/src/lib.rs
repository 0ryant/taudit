//! # `taudit-core` — workspace-internal authority graph + rules engine
//!
//! ## API stability
//!
//! `taudit-core` is a **workspace-internal library**, NOT a stable public
//! API. External consumers (`tsign`, `axiom`, custom automation, SIEMs,
//! third-party tooling) should consume the JSON / SARIF / CloudEvents
//! output contracts instead. Those contracts are versioned, schema-pinned,
//! and treated as load-bearing.
//!
//! Symbols marked `#[doc(hidden)]` are required to be `pub` for
//! inter-crate visibility within this workspace (sink crates call
//! `compute_fingerprint`, `compute_finding_group_id`, `rule_id_for`,
//! `downgrade_severity` directly), but their signatures may change between
//! minor `taudit` versions without a SemVer bump on `taudit-core`. Treat
//! them as `pub(crate-tree)`, not `pub`.
//!
//! Stable surfaces for external consumption:
//!   * `contracts/schemas/taudit-report.schema.json` — JSON output
//!   * `schemas/finding.v1.json` — single finding object
//!   * `schemas/baseline.v1.json` — baseline file format
//!   * `contracts/schemas/taudit-cloudevent-finding-v1.schema.json` —
//!     CloudEvents extension attributes
//!   * SARIF 2.1.0 — `partialFingerprints` keys are stable
//!
//! See ADR 0001 (graph as product) and the v1.1.0 release notes for the
//! full rationale behind this split.

pub mod baselines;
pub mod custom_rules;
pub mod error;
pub mod finding;
pub mod graph;
pub mod ignore;
pub mod map;
pub mod ports;
pub mod propagation;
pub mod rules;
pub mod summary;
pub mod suppressions;
