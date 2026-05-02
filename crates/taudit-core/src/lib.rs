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
pub mod finding;
pub mod graph;
pub mod ignore;
pub mod map;
pub mod ports;
pub mod propagation;
pub mod rules;
pub mod summary;
pub mod suppressions;
