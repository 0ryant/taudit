//! Per-pipeline baseline files (`.taudit/baselines/<hash>.json`).
//!
//! A *baseline* is a snapshot of the findings present on a pipeline at the
//! moment it was first onboarded into taudit. Subsequent scans diff against
//! the baseline so reviewers see only NEW findings; pre-existing findings are
//! summarised. Baselines are the v0.10 mechanism for adopting taudit on
//! existing repos without forcing upfront triage of historical findings.
//!
//! ## Load-bearing decisions (per design council, 2026-04-26)
//!
//! 1. **Layout: one file per pipeline keyed by content hash.** A monolithic
//!    `.taudit/baseline.json` would merge-conflict on every PR. Per-pipeline
//!    files (`.taudit/baselines/<sha256>.json`) keep blast radius small.
//! 2. **Fingerprints reuse `Finding::compute_fingerprint` exactly.** Inventing
//!    a second hashing scheme is a foot-gun — SARIF, JSON, CloudEvents and
//!    baselines must agree on what "same finding" means. The shared test
//!    `baseline_fingerprint_matches_sarif_fingerprint` enforces this.
//! 3. **Critical findings always exit 1** unless the entry carries
//!    `severity_override: critical` AND a `reason` AND `expires_at <= 90d`.
//!    This is the security analyst's non-negotiable: any waiver mechanism
//!    creates a path for risk to be accepted, so critical waivers must be
//!    conscious, time-bounded and re-reviewed.
//! 4. **OSS-friendly default.** No `.taudit/` directory means today's
//!    behaviour. Baselines are strictly opt-in.
//!
//! See `docs/baselines.md` for the full workflow and security guarantees.

use crate::finding::{compute_fingerprint, Finding, Severity};
use crate::graph::{
    AuthorityGraph, EdgeKind, NodeKind, META_GITLAB_EXTENDS, META_GITLAB_INCLUDES, META_NEEDS,
    META_REPOSITORIES,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Maximum lifetime allowed for a critical-severity waiver. Council's
/// load-bearing constraint: a critical may only bypass exit-1 if its waiver
/// expires within this window. Longer expirations are rejected at validation
/// time (and pruned at diff time).
pub const MAX_CRITICAL_WAIVER_DAYS: i64 = 90;

/// Minimum length (UTF-8 chars) of the `reason` string on a waiver. Empty,
/// `wip`, `todo`, `fix later` strings train the wrong muscle memory; force
/// a sentence's worth of justification.
pub const MIN_REASON_LENGTH: usize = 10;

/// Schema version emitted by `init` and accepted by `load`. Additive 1.x.y
/// changes are non-breaking; 2.0.0 means breaking changes.
pub const BASELINE_SCHEMA_VERSION: &str = "1.1.0";

/// Errors returned by baseline I/O and validation.
#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    #[error("failed to read baseline {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write baseline {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse baseline {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize baseline: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("baseline schema version {found:?} not supported (expected major 1.x.y)")]
    UnsupportedVersion { found: String },
    #[error("waiver reason must be at least {min} characters (got {got})")]
    ReasonTooShort { min: usize, got: usize },
    #[error("critical-severity override requires expires_at <= {days}d from accepted_at")]
    CriticalWaiverTooLong { days: i64 },
    #[error("critical-severity override requires expires_at to be set")]
    CriticalWaiverNoExpiry,
    #[error("critical-severity override requires a reason")]
    CriticalWaiverNoReason,
}

/// One entry in a baseline. Keyed on `fingerprint` (16-hex SHA-256 truncation
/// computed by [`compute_fingerprint`](crate::finding::compute_fingerprint)).
///
/// Two waiver shapes:
///
/// * **Plain pre-existing finding.** `reason_waived`, `severity_override`,
///   `expires_at` all `None`. The finding existed at `init` time; it is
///   reported as "pre-existing" rather than a regression. Critical findings
///   in this shape STILL fail exit-1.
/// * **Explicit waiver.** `reason_waived` populated. If the original
///   severity was Critical, `severity_override: "critical"` and
///   `expires_at <= accepted_at + 90d` are mandatory; otherwise the waiver
///   is rejected at load time and the critical falls through to exit 1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaselineFinding {
    /// 16-hex SHA-256 fingerprint matching the SARIF/JSON/CloudEvents value.
    pub fingerprint: String,
    /// Snake-case rule id (custom rule id if present, else
    /// `FindingCategory` snake_case form).
    pub rule_id: String,
    /// Severity captured at `init` time. Used for the critical-bypass check.
    pub severity: Severity,
    /// When this entry was first added to the baseline (`init` or `accept`).
    pub first_seen_at: DateTime<Utc>,
    /// Free-form justification. Required on `accept` (>=10 chars). `None`
    /// when the entry was bulk-added by `init`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason_waived: Option<String>,
    /// Acknowledges that the original severity was Critical and the waiver
    /// is intentional. Council's hard rule: any critical bypass must declare
    /// itself with this field; missing == critical falls through to exit 1.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub severity_override: Option<Severity>,
    /// Hard deadline. Mandatory for `severity_override: critical`. After
    /// this timestamp the waiver is treated as expired (logs a warning and
    /// the underlying finding counts toward exit-1 again).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<DateTime<Utc>>,
}

impl BaselineFinding {
    /// True iff this entry waives a critical via the explicit-override
    /// shape (severity_override + reason + expires_at <= 90d).
    pub fn is_valid_critical_waiver(&self, now: DateTime<Utc>) -> bool {
        if self.severity_override != Some(Severity::Critical) {
            return false;
        }
        let Some(expires_at) = self.expires_at else {
            return false;
        };
        if expires_at <= now {
            return false;
        }
        if (expires_at - self.first_seen_at) > Duration::days(MAX_CRITICAL_WAIVER_DAYS) {
            return false;
        }
        matches!(self.reason_waived.as_deref(), Some(r) if r.chars().count() >= MIN_REASON_LENGTH)
    }

    /// True iff this waiver carries an `expires_at` that has already passed.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at {
            Some(t) => t <= now,
            None => false,
        }
    }
}

/// Tool/version provenance captured at `init`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapturedWith {
    pub taudit_version: String,
    /// Free-form description of the rule set at capture time
    /// (e.g. `"32-builtin"`, `"32-builtin+5-custom"`).
    pub rules_version: String,
}

/// One baseline file = one pipeline. Keyed by `pipeline_content_hash` so
/// renames preserve state and merge conflicts only touch the affected file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Baseline {
    pub schema_version: String,
    pub pipeline_path: String,
    /// `sha256:<hex>` of the pipeline file's bytes at `init` time.
    pub pipeline_content_hash: String,
    /// Optional additive hardening signal captured at `init` time.
    ///
    /// Hashes parser-emitted dependency-like material (include/template/
    /// repository declarations and delegation edges) so suppression can be
    /// disabled if that material drifts even when the baseline file still
    /// exists. Absent on legacy baseline files written before v1.1.0.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pipeline_identity_material_hash: Option<String>,
    pub captured_at: DateTime<Utc>,
    pub captured_by: String,
    pub captured_with: CapturedWith,
    /// Sorted by `fingerprint` ASC for stable git diffs.
    pub baseline_findings: Vec<BaselineFinding>,
}

impl Baseline {
    /// Load and parse a baseline from disk. Returns `Ok(None)` if `path`
    /// does not exist (the OSS-friendly default — absent baseline is fine).
    pub fn load(path: &Path) -> Result<Option<Self>, BaselineError> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path).map_err(|source| BaselineError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let baseline: Baseline =
            serde_json::from_slice(&bytes).map_err(|source| BaselineError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        if !baseline.schema_version.starts_with("1.") {
            return Err(BaselineError::UnsupportedVersion {
                found: baseline.schema_version,
            });
        }
        Ok(Some(baseline))
    }

    /// Write `self` to `path` as pretty JSON with stable key ordering and
    /// fingerprint-sorted entries. Creates parent directories as needed.
    pub fn save(&self, path: &Path) -> Result<(), BaselineError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| BaselineError::Write {
                path: path.to_path_buf(),
                source,
            })?;
        }
        let mut sorted = self.clone();
        sorted
            .baseline_findings
            .sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        let mut bytes = serde_json::to_vec_pretty(&sorted)?;
        bytes.push(b'\n');
        std::fs::write(path, bytes).map_err(|source| BaselineError::Write {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }

    /// Produce a fresh baseline from `current_findings` against `graph`.
    /// Each entry is a plain pre-existing finding (no waiver fields set).
    /// `pipeline_path` should be the pipeline's filesystem path as the user
    /// sees it; `content` is the raw bytes used to derive the content hash.
    #[allow(clippy::too_many_arguments)]
    pub fn from_findings(
        pipeline_path: &str,
        content: &str,
        graph: &AuthorityGraph,
        findings: &[Finding],
        captured_by: &str,
        taudit_version: &str,
        rules_version: &str,
        now: DateTime<Utc>,
    ) -> Self {
        let mut baseline_findings: Vec<BaselineFinding> = findings
            .iter()
            .map(|f| BaselineFinding {
                fingerprint: compute_fingerprint(f, graph),
                rule_id: rule_id_for(f),
                severity: f.severity,
                first_seen_at: now,
                reason_waived: None,
                severity_override: None,
                expires_at: None,
            })
            .collect();
        // Dedup on fingerprint (template instances collapse into one entry).
        baseline_findings.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        baseline_findings.dedup_by(|a, b| a.fingerprint == b.fingerprint);

        Baseline {
            schema_version: BASELINE_SCHEMA_VERSION.to_string(),
            pipeline_path: pipeline_path.to_string(),
            pipeline_content_hash: compute_pipeline_hash(content),
            pipeline_identity_material_hash: Some(compute_pipeline_identity_material_hash(graph)),
            captured_at: now,
            captured_by: captured_by.to_string(),
            captured_with: CapturedWith {
                taudit_version: taudit_version.to_string(),
                rules_version: rules_version.to_string(),
            },
            baseline_findings,
        }
    }

    /// Append a single waiver entry. Validates `reason` length and the
    /// critical-waiver constraints. Returns the inserted/updated entry.
    /// If an entry with the same fingerprint already exists, it is replaced
    /// (idempotent re-acceptance with a refreshed reason / expiry).
    #[allow(clippy::too_many_arguments)]
    pub fn accept(
        &mut self,
        fingerprint: &str,
        rule_id: &str,
        severity: Severity,
        reason: &str,
        severity_override: Option<Severity>,
        expires_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<&BaselineFinding, BaselineError> {
        let reason_chars = reason.chars().count();
        if reason_chars < MIN_REASON_LENGTH {
            return Err(BaselineError::ReasonTooShort {
                min: MIN_REASON_LENGTH,
                got: reason_chars,
            });
        }
        if severity_override == Some(Severity::Critical) {
            let Some(exp) = expires_at else {
                return Err(BaselineError::CriticalWaiverNoExpiry);
            };
            if (exp - now) > Duration::days(MAX_CRITICAL_WAIVER_DAYS) {
                return Err(BaselineError::CriticalWaiverTooLong {
                    days: MAX_CRITICAL_WAIVER_DAYS,
                });
            }
        }
        let entry = BaselineFinding {
            fingerprint: fingerprint.to_string(),
            rule_id: rule_id.to_string(),
            severity,
            first_seen_at: now,
            reason_waived: Some(reason.to_string()),
            severity_override,
            expires_at,
        };
        // Replace existing entry with the same fingerprint, else append.
        if let Some(slot) = self
            .baseline_findings
            .iter_mut()
            .find(|e| e.fingerprint == entry.fingerprint)
        {
            *slot = entry;
        } else {
            self.baseline_findings.push(entry);
        }
        self.baseline_findings
            .sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        Ok(self
            .baseline_findings
            .iter()
            .find(|e| e.fingerprint == fingerprint)
            .expect("just inserted"))
    }

    /// Returns true when the captured identity material matches the current
    /// parsed graph. Legacy baselines that predate this field are considered
    /// compatible to preserve backward compatibility.
    pub fn identity_material_matches(&self, graph: &AuthorityGraph) -> bool {
        match self.pipeline_identity_material_hash.as_deref() {
            Some(expected) => expected == compute_pipeline_identity_material_hash(graph),
            None => true,
        }
    }
}

/// Result of diffing a fresh scan against a baseline. All three buckets
/// are independently consumable by `verify`'s exit-code logic.
#[derive(Debug, Clone)]
pub struct BaselineDiff {
    /// Findings present in the current scan whose fingerprint is NOT in
    /// the baseline. These are regressions and drive the verify exit code.
    pub new: Vec<Finding>,
    /// Baseline entries whose fingerprint is NOT present in the current
    /// scan — the underlying issue was fixed (or refactored away). Useful
    /// for the `taudit baseline diff` summary.
    pub fixed: Vec<BaselineFinding>,
    /// Findings present in BOTH the current scan and the baseline. Reported
    /// for visibility but do not drive exit-1 unless they are critical-
    /// without-valid-waiver (see [`Self::critical_without_valid_waiver`]).
    pub preexisting: Vec<Finding>,
    /// Subset of preexisting baseline entries that carry `reason_waived`.
    /// Drives the "X waived, Y unwaived" summary.
    pub waived_count: usize,
}

impl BaselineDiff {
    /// Critical findings in `preexisting` whose baseline entry does NOT
    /// carry a valid critical waiver. These ALWAYS count toward exit 1 —
    /// the council's load-bearing constraint that critical waivers must be
    /// explicit, time-bounded, and re-reviewed.
    pub fn critical_without_valid_waiver(
        &self,
        baseline: &Baseline,
        graph: &AuthorityGraph,
        now: DateTime<Utc>,
    ) -> Vec<Finding> {
        self.preexisting
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .filter(|f| {
                let fp = compute_fingerprint(f, graph);
                match baseline
                    .baseline_findings
                    .iter()
                    .find(|e| e.fingerprint == fp)
                {
                    Some(entry) => !entry.is_valid_critical_waiver(now),
                    None => true, // shouldn't happen — preexisting means present in baseline
                }
            })
            .cloned()
            .collect()
    }
}

/// Diff `current_findings` against `baseline` using the SARIF-equivalent
/// fingerprint computed from `graph`. Entry point for `verify` and the
/// `taudit baseline diff` subcommand.
pub fn diff(
    current_findings: &[Finding],
    baseline: &Baseline,
    graph: &AuthorityGraph,
) -> BaselineDiff {
    use std::collections::{HashMap, HashSet};

    let baseline_index: HashMap<&str, &BaselineFinding> = baseline
        .baseline_findings
        .iter()
        .map(|e| (e.fingerprint.as_str(), e))
        .collect();

    let mut new = Vec::new();
    let mut preexisting = Vec::new();
    let mut seen_fingerprints: HashSet<String> = HashSet::new();
    let mut waived_count = 0usize;

    for finding in current_findings {
        let fp = compute_fingerprint(finding, graph);
        seen_fingerprints.insert(fp.clone());
        match baseline_index.get(fp.as_str()) {
            Some(entry) => {
                if entry.reason_waived.is_some() {
                    waived_count += 1;
                }
                preexisting.push(finding.clone());
            }
            None => new.push(finding.clone()),
        }
    }

    let fixed: Vec<BaselineFinding> = baseline
        .baseline_findings
        .iter()
        .filter(|e| !seen_fingerprints.contains(&e.fingerprint))
        .cloned()
        .collect();

    BaselineDiff {
        new,
        fixed,
        preexisting,
        waived_count,
    }
}

/// SHA-256 of `content` formatted as `sha256:<64-hex>`. The `sha256:`
/// prefix mirrors OCI / git object naming so logs and dashboards can
/// strip the algorithm tag uniformly.
pub fn compute_pipeline_hash(content: &str) -> String {
    let digest = Sha256::digest(content.as_bytes());
    format_digest(digest)
}

/// SHA-256 over dependency-like parser material (include/template/repository
/// declarations and delegation edges), formatted as `sha256:<64-hex>`.
///
/// This is intentionally additive to `pipeline_content_hash`: content hash
/// still keys baseline files for backward compatibility, while this material
/// hash is used to detect include/template drift and disable suppression when
/// the parser-visible dependency shape changes.
pub fn compute_pipeline_identity_material_hash(graph: &AuthorityGraph) -> String {
    let mut metadata: BTreeMap<String, String> = BTreeMap::new();
    for key in [META_REPOSITORIES, META_GITLAB_INCLUDES] {
        if let Some(value) = graph.metadata.get(key) {
            metadata.insert(key.to_string(), value.clone());
        }
    }

    let mut delegations: Vec<String> = graph
        .edges
        .iter()
        .filter(|e| e.kind == EdgeKind::DelegatesTo)
        .filter_map(|e| {
            let from = graph.node(e.from)?;
            let to = graph.node(e.to)?;
            Some(format!(
                "{}:{}->{}:{}:{:?}",
                from.id, from.name, to.id, to.name, to.trust_zone
            ))
        })
        .collect();
    delegations.sort();

    let mut step_dependency_metadata: Vec<String> = graph
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::Step)
        .flat_map(|n| {
            [META_NEEDS, META_GITLAB_EXTENDS]
                .iter()
                .filter_map(move |k| {
                    n.metadata
                        .get(*k)
                        .map(|v| format!("{}:{}={}", n.name, k, v))
                })
        })
        .collect();
    step_dependency_metadata.sort();

    let canonical = serde_json::json!({
        "metadata": metadata,
        "delegates_to": delegations,
        "step_dependency_metadata": step_dependency_metadata,
    });

    let bytes = serde_json::to_vec(&canonical).expect("identity material must serialize");
    let digest = Sha256::digest(bytes);
    format_digest(digest)
}

fn format_digest(digest: impl AsRef<[u8]>) -> String {
    let mut hex = String::with_capacity(64);
    for byte in digest.as_ref() {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    format!("sha256:{hex}")
}

/// Default location for per-pipeline baselines, given the working directory.
/// Returns `<root>/.taudit/baselines/`.
pub fn baselines_dir(root: &Path) -> PathBuf {
    root.join(".taudit").join("baselines")
}

/// Filename for one pipeline's baseline. The `sha256:` prefix is stripped
/// so the file is portable on filesystems that disallow `:` (Windows NTFS).
pub fn baseline_filename_for(pipeline_content_hash: &str) -> String {
    let hex = pipeline_content_hash
        .strip_prefix("sha256:")
        .unwrap_or(pipeline_content_hash);
    format!("{hex}.json")
}

/// Convenience: full `<root>/.taudit/baselines/<hex>.json` path for the
/// given content hash.
pub fn baseline_path_for(root: &Path, pipeline_content_hash: &str) -> PathBuf {
    baselines_dir(root).join(baseline_filename_for(pipeline_content_hash))
}

/// Public alias of [`compute_fingerprint`] — re-exported here so the baseline
/// module is the single import point for "what is the fingerprint of this
/// finding for baseline purposes". The shared test
/// `baseline_fingerprint_matches_sarif_fingerprint` asserts these are
/// byte-equal forever.
pub fn compute_finding_fingerprint(finding: &Finding, graph: &AuthorityGraph) -> String {
    compute_fingerprint(finding, graph)
}

/// Snake-case rule id for `f`. Mirrors the same logic the SARIF reporter
/// uses (custom rule id from `[id] message` prefix wins over category).
fn rule_id_for(f: &Finding) -> String {
    if let Some(id) = f.message.strip_prefix('[') {
        if let Some(end) = id.find(']') {
            let candidate = &id[..end];
            if !candidate.is_empty() {
                return candidate.to_string();
            }
        }
    }
    serde_json::to_value(f.category)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{FindingCategory, FindingExtras, FindingSource, Recommendation};
    use crate::graph::{AuthorityGraph, NodeKind, PipelineSource, TrustZone};

    fn source(file: &str) -> PipelineSource {
        PipelineSource {
            file: file.to_string(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        }
    }

    fn make_graph(file: &str) -> (AuthorityGraph, crate::graph::NodeId) {
        let mut g = AuthorityGraph::new(source(file));
        let s = g.add_node(NodeKind::Secret, "AWS_KEY", TrustZone::FirstParty);
        (g, s)
    }

    fn make_finding(
        category: FindingCategory,
        severity: Severity,
        msg: &str,
        nodes: Vec<crate::graph::NodeId>,
    ) -> Finding {
        Finding {
            severity,
            category,
            path: None,
            nodes_involved: nodes,
            message: msg.to_string(),
            recommendation: Recommendation::Manual {
                action: "fix".to_string(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-04-26T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    /// COUNCIL-MANDATED SHARED TEST: baseline fingerprint and SARIF
    /// fingerprint MUST be byte-equal. If this ever fails, suppression
    /// across SARIF/JSON/CloudEvents/baseline silently drifts. Non-
    /// negotiable per the council design doc, Section C, item 5.
    #[test]
    fn baseline_fingerprint_matches_sarif_fingerprint() {
        let (graph, s) = make_graph(".github/workflows/release.yml");
        let f = make_finding(
            FindingCategory::AuthorityPropagation,
            Severity::High,
            "AWS_KEY reaches third party",
            vec![s],
        );
        let baseline_fp = compute_finding_fingerprint(&f, &graph);
        let sarif_fp = compute_fingerprint(&f, &graph);
        assert_eq!(
            baseline_fp, sarif_fp,
            "baseline and SARIF fingerprints MUST be byte-equal — do not introduce a second fingerprint scheme"
        );
    }

    #[test]
    fn pipeline_hash_is_deterministic_and_prefixed() {
        let h = compute_pipeline_hash("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n");
        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), 7 + 64);
        let h2 = compute_pipeline_hash("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n");
        assert_eq!(h, h2, "same content -> same hash");
        let h3 = compute_pipeline_hash("on: push\n");
        assert_ne!(h, h3);
    }

    #[test]
    fn identity_material_hash_changes_when_dependency_metadata_changes() {
        let (mut g1, _) = make_graph("ci.yml");
        g1.metadata.insert(
            META_REPOSITORIES.to_string(),
            r#"[{"alias":"templates","used":true}]"#.to_string(),
        );

        let (mut g2, _) = make_graph("ci.yml");
        g2.metadata.insert(
            META_REPOSITORIES.to_string(),
            r#"[{"alias":"templates","used":false}]"#.to_string(),
        );

        let h1 = compute_pipeline_identity_material_hash(&g1);
        let h2 = compute_pipeline_identity_material_hash(&g2);
        assert_ne!(
            h1, h2,
            "repository/include metadata drift must change identity material"
        );
    }

    #[test]
    fn identity_material_hash_changes_when_template_delegation_changes() {
        let mut g1 = AuthorityGraph::new(source("ci.yml"));
        let s1 = g1.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        let t1 = g1.add_node(
            NodeKind::Image,
            "templates/release.yml",
            TrustZone::FirstParty,
        );
        g1.add_edge(s1, t1, EdgeKind::DelegatesTo);

        let mut g2 = AuthorityGraph::new(source("ci.yml"));
        let s2 = g2.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        let t2 = g2.add_node(
            NodeKind::Image,
            "templates/release-v2.yml",
            TrustZone::FirstParty,
        );
        g2.add_edge(s2, t2, EdgeKind::DelegatesTo);

        let h1 = compute_pipeline_identity_material_hash(&g1);
        let h2 = compute_pipeline_identity_material_hash(&g2);
        assert_ne!(
            h1, h2,
            "template delegation target drift must change identity material"
        );
    }

    #[test]
    fn init_captures_current_findings() {
        let (graph, s) = make_graph("ci.yml");
        let f1 = make_finding(
            FindingCategory::UnpinnedAction,
            Severity::High,
            "actions/checkout@v4 unpinned",
            vec![s],
        );
        let f2 = make_finding(
            FindingCategory::AuthorityPropagation,
            Severity::Critical,
            "AWS_KEY reaches untrusted",
            vec![s],
        );
        let baseline = Baseline::from_findings(
            "ci.yml",
            "on: push\n",
            &graph,
            &[f1, f2],
            "ryan@example.com",
            "0.10.0",
            "32-builtin",
            now(),
        );
        assert_eq!(baseline.baseline_findings.len(), 2);
        assert_eq!(baseline.captured_by, "ryan@example.com");
        assert_eq!(baseline.captured_with.taudit_version, "0.10.0");
        assert!(
            baseline.pipeline_identity_material_hash.is_some(),
            "new captures should persist identity material hash"
        );
        // Sorted by fingerprint
        let fps: Vec<&str> = baseline
            .baseline_findings
            .iter()
            .map(|e| e.fingerprint.as_str())
            .collect();
        let mut sorted = fps.clone();
        sorted.sort();
        assert_eq!(fps, sorted, "entries must be fingerprint-sorted");
        // No waiver fields on init
        for entry in &baseline.baseline_findings {
            assert!(entry.reason_waived.is_none());
            assert!(entry.severity_override.is_none());
            assert!(entry.expires_at.is_none());
        }
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempdir();
        let (graph, s) = make_graph("ci.yml");
        let f = make_finding(
            FindingCategory::UnpinnedAction,
            Severity::High,
            "actions/checkout@v4 unpinned",
            vec![s],
        );
        let baseline = Baseline::from_findings(
            "ci.yml",
            "x",
            &graph,
            &[f],
            "ryan",
            "0.10.0",
            "32-builtin",
            now(),
        );
        let path = dir.join("b.json");
        baseline.save(&path).expect("save");
        let loaded = Baseline::load(&path).expect("load").expect("present");
        assert_eq!(baseline, loaded);
    }

    #[test]
    fn load_returns_none_when_absent() {
        let dir = tempdir();
        let path = dir.join("does-not-exist.json");
        assert!(Baseline::load(&path).expect("ok").is_none());
    }

    #[test]
    fn legacy_baseline_without_identity_material_remains_compatible() {
        let baseline = empty_baseline();
        let (graph, _) = make_graph("ci.yml");
        assert!(
            baseline.identity_material_matches(&graph),
            "legacy baseline must remain compatible"
        );
    }

    #[test]
    fn accept_rejects_short_reason() {
        let mut baseline = empty_baseline();
        let err = baseline
            .accept(
                "abcd1234abcd1234",
                "unpinned_action",
                Severity::High,
                "wip",
                None,
                None,
                now(),
            )
            .unwrap_err();
        assert!(matches!(err, BaselineError::ReasonTooShort { .. }));
    }

    #[test]
    fn accept_critical_without_expires_is_rejected() {
        let mut baseline = empty_baseline();
        let err = baseline
            .accept(
                "deadbeefdeadbeef",
                "trigger_context_mismatch",
                Severity::Critical,
                "Threat-modeled exception per ABC-123",
                Some(Severity::Critical),
                None, // no expiry
                now(),
            )
            .unwrap_err();
        assert!(matches!(err, BaselineError::CriticalWaiverNoExpiry));
    }

    #[test]
    fn accept_critical_with_expiry_beyond_90d_is_rejected() {
        let mut baseline = empty_baseline();
        let too_long = now() + Duration::days(100);
        let err = baseline
            .accept(
                "deadbeefdeadbeef",
                "trigger_context_mismatch",
                Severity::Critical,
                "Threat-modeled exception per ABC-123",
                Some(Severity::Critical),
                Some(too_long),
                now(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            BaselineError::CriticalWaiverTooLong { days: 90 }
        ));
    }

    #[test]
    fn accept_critical_with_valid_expiry_succeeds() {
        let mut baseline = empty_baseline();
        let exp = now() + Duration::days(60);
        baseline
            .accept(
                "deadbeefdeadbeef",
                "trigger_context_mismatch",
                Severity::Critical,
                "Threat-modeled exception per ABC-123",
                Some(Severity::Critical),
                Some(exp),
                now(),
            )
            .expect("valid critical waiver");
        let entry = &baseline.baseline_findings[0];
        assert!(entry.is_valid_critical_waiver(now()));
        // After the expiry, the waiver no longer protects.
        assert!(!entry.is_valid_critical_waiver(exp + Duration::seconds(1)));
    }

    #[test]
    fn diff_classifies_new_fixed_preexisting() {
        let (graph, s) = make_graph("ci.yml");
        let f_old = make_finding(
            FindingCategory::UnpinnedAction,
            Severity::High,
            "actions/checkout@v4 unpinned",
            vec![s],
        );
        let f_unchanged = make_finding(
            FindingCategory::AuthorityPropagation,
            Severity::High,
            "AWS_KEY reaches untrusted",
            vec![s],
        );
        let baseline = Baseline::from_findings(
            "ci.yml",
            "x",
            &graph,
            &[f_old.clone(), f_unchanged.clone()],
            "ryan",
            "0.10.0",
            "32-builtin",
            now(),
        );
        // Current scan: keep `unchanged`, drop `old`, add `new`.
        let f_new = make_finding(
            FindingCategory::OverPrivilegedIdentity,
            Severity::Medium,
            "GITHUB_TOKEN over-privileged",
            vec![s],
        );
        let current = vec![f_unchanged.clone(), f_new.clone()];
        let diff = diff(&current, &baseline, &graph);
        assert_eq!(diff.new.len(), 1, "f_new is new");
        assert_eq!(diff.fixed.len(), 1, "f_old was fixed");
        assert_eq!(diff.preexisting.len(), 1, "f_unchanged preexisting");
        assert_eq!(diff.waived_count, 0, "no waivers yet");
    }

    #[test]
    fn critical_preexisting_without_waiver_blocks_exit_zero() {
        let (graph, s) = make_graph("ci.yml");
        let crit = make_finding(
            FindingCategory::AuthorityPropagation,
            Severity::Critical,
            "AWS_KEY reaches untrusted",
            vec![s],
        );
        let baseline = Baseline::from_findings(
            "ci.yml",
            "x",
            &graph,
            std::slice::from_ref(&crit),
            "ryan",
            "0.10.0",
            "32-builtin",
            now(),
        );
        let diff = diff(&[crit], &baseline, &graph);
        assert_eq!(diff.preexisting.len(), 1);
        // Plain pre-existing entry — no severity_override, no waiver — must
        // STILL force a critical to count toward exit 1.
        let blockers = diff.critical_without_valid_waiver(&baseline, &graph, now());
        assert_eq!(
            blockers.len(),
            1,
            "critical without explicit waiver must always block"
        );
    }

    #[test]
    fn critical_with_explicit_waiver_does_not_block() {
        let (graph, s) = make_graph("ci.yml");
        let crit = make_finding(
            FindingCategory::AuthorityPropagation,
            Severity::Critical,
            "AWS_KEY reaches untrusted",
            vec![s],
        );
        let mut baseline = Baseline::from_findings(
            "ci.yml",
            "x",
            &graph,
            std::slice::from_ref(&crit),
            "ryan",
            "0.10.0",
            "32-builtin",
            now(),
        );
        // Promote the entry to a valid critical waiver.
        let fp = compute_fingerprint(&crit, &graph);
        baseline
            .accept(
                &fp,
                "authority_propagation",
                Severity::Critical,
                "Threat-modeled; documented exception ABC-123",
                Some(Severity::Critical),
                Some(now() + Duration::days(60)),
                now(),
            )
            .expect("valid waiver");
        let diff = diff(&[crit], &baseline, &graph);
        let blockers = diff.critical_without_valid_waiver(&baseline, &graph, now());
        assert_eq!(blockers.len(), 0, "valid waiver bypasses exit 1");
    }

    #[test]
    fn expired_critical_waiver_no_longer_protects() {
        let (graph, s) = make_graph("ci.yml");
        let crit = make_finding(
            FindingCategory::AuthorityPropagation,
            Severity::Critical,
            "AWS_KEY reaches untrusted",
            vec![s],
        );
        let mut baseline = Baseline::from_findings(
            "ci.yml",
            "x",
            &graph,
            std::slice::from_ref(&crit),
            "ryan",
            "0.10.0",
            "32-builtin",
            now(),
        );
        let fp = compute_fingerprint(&crit, &graph);
        let exp = now() + Duration::days(30);
        baseline
            .accept(
                &fp,
                "authority_propagation",
                Severity::Critical,
                "Threat-modeled; documented exception ABC-123",
                Some(Severity::Critical),
                Some(exp),
                now(),
            )
            .expect("valid waiver");
        // Time passes past the expiry — the waiver no longer protects.
        let later = exp + Duration::days(1);
        let diff = diff(&[crit], &baseline, &graph);
        let blockers = diff.critical_without_valid_waiver(&baseline, &graph, later);
        assert_eq!(blockers.len(), 1, "expired waiver must not protect");
    }

    #[test]
    fn baselines_dir_and_filename_layout() {
        let root = std::path::Path::new("/tmp/repo");
        let dir = baselines_dir(root);
        assert_eq!(dir, std::path::PathBuf::from("/tmp/repo/.taudit/baselines"));
        let f = baseline_filename_for("sha256:abcdef0123");
        assert_eq!(f, "abcdef0123.json");
        let p = baseline_path_for(root, "sha256:abcdef0123");
        assert_eq!(
            p,
            std::path::PathBuf::from("/tmp/repo/.taudit/baselines/abcdef0123.json")
        );
    }

    #[test]
    fn unsupported_schema_version_rejected() {
        let dir = tempdir();
        let path = dir.join("b.json");
        let body = r#"{"schema_version":"2.0.0","pipeline_path":"x","pipeline_content_hash":"sha256:x","captured_at":"2026-04-26T12:00:00Z","captured_by":"r","captured_with":{"taudit_version":"0.10.0","rules_version":"32-builtin"},"baseline_findings":[]}"#;
        std::fs::write(&path, body).unwrap();
        let err = Baseline::load(&path).unwrap_err();
        assert!(matches!(err, BaselineError::UnsupportedVersion { .. }));
    }

    // ── Test helpers ─────────────────────────────────────

    fn empty_baseline() -> Baseline {
        Baseline {
            schema_version: BASELINE_SCHEMA_VERSION.to_string(),
            pipeline_path: "ci.yml".to_string(),
            pipeline_content_hash: compute_pipeline_hash("x"),
            pipeline_identity_material_hash: None,
            captured_at: now(),
            captured_by: "ryan".to_string(),
            captured_with: CapturedWith {
                taudit_version: "0.10.0".to_string(),
                rules_version: "32-builtin".to_string(),
            },
            baseline_findings: Vec::new(),
        }
    }

    /// Per-process tempdir helper. Avoids pulling in the `tempfile` crate
    /// just for tests — we control the cleanup ourselves.
    fn tempdir() -> std::path::PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("taudit-baselines-test-{pid}-{nanos}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
