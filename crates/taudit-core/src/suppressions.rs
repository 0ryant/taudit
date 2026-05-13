//! `.taudit-suppressions.yml` — per-finding waivers with audit trail.
//!
//! ## Why
//!
//! Adopters need a way to formally acknowledge specific findings as
//! accepted-risks without forking taudit's rules. Today they have:
//!
//!   * `.tauditignore` — file-level, by finding category. Whole class of
//!     findings disappears in a single file. Coarse.
//!   * `--severity-threshold` — severity floor. Cuts noise but is a global,
//!     not per-finding, decision.
//!   * Starter invariants — positive policy. Says what's required, not
//!     what's accepted.
//!
//! What's missing: per-finding waivers with audit trail. That's what
//! this module implements.
//!
//! ## Format
//!
//! YAML at the repo root (`.taudit-suppressions.yml`) or under
//! `.taudit/suppressions.yml`. Each entry waives one finding by precise
//! `fingerprint` or operator-stable `suppression_key`, and carries the
//! operator who accepted it, the reason, and an optional expiry:
//!
//! ```yaml
//! suppressions:
//!   - fingerprint: "5edb30f4db3b5fa3d7fe7289374b7155"
//!     rule_id: "untrusted_with_authority"
//!     reason: "Internal-only action; threat-modeled and accepted by security team."
//!     accepted_by: "ryan@example.com"
//!     accepted_at: "2026-04-26"
//!     expires_at: "2026-07-26"  # optional; required for critical waivers
//!
//!   - suppression_key: "sk1_f0a4a77a6dd134615108063795fd9fb0"
//!     rule_id: "over_privileged_identity"
//!     reason: "Reviewed stable waiver."
//!     accepted_by: "platform@example.com"
//!     accepted_at: "2026-05-13"
//!     expires_at: "2026-08-11"
//! ```
//!
//! ## Behaviour
//!
//! For each finding, if its `fingerprint` or `suppression_key` matches an
//! active suppression:
//!
//!   * **Downgrade mode (default):** severity drops by one tier
//!     (`Critical -> High -> Medium -> Low -> Info`). The full finding
//!     still appears so audit trail is preserved.
//!   * **Suppress mode:** `extras.suppressed = true` is set; severity
//!     does not change. Consumers can filter on the boolean.
//!
//! In both modes, `extras.original_severity` records the rule-emitted
//! severity, and `extras.suppression_reason` records the operator's
//! justification.
//!
//! ## Hard rules
//!
//! 1. **Critical findings cannot be fully suppressed without `expires_at`.**
//!    A waiver for a Critical finding that lacks `expires_at` is rejected
//!    at load time — the loader returns an error, and `taudit scan` /
//!    `taudit verify` exits non-zero.
//!
//! 2. **Expired waivers do not apply.** When `expires_at` is in the past
//!    relative to the current date, the waiver is skipped and a warning
//!    is emitted: `WARNING: suppression for fingerprint <X> expired on
//!    <date>; finding restored to original severity`.

use serde::{Deserialize, Serialize};

use crate::finding::{downgrade_severity, Finding};

const MAX_CONFIG_BYTES: u64 = 2 * 1024 * 1024;
const CURRENT_FINGERPRINT_HEX_LEN: usize = 32;

/// Mode controlling how the suppression applicator modifies a matched
/// finding. `Downgrade` (default) drops severity one tier; `Suppress`
/// flips a boolean and leaves severity untouched.
///
/// Configurable per `taudit scan`/`taudit verify` invocation via the
/// `--suppression-mode` CLI flag (or per-entry `mode:` if a future
/// version makes this finer-grained).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionMode {
    /// Drop severity by one tier (Critical -> High -> ... -> Info).
    /// Default — preserves visibility while reducing the noise.
    #[default]
    Downgrade,
    /// Set `extras.suppressed = true` and leave severity unchanged.
    /// Consumers filter on the boolean. Highest visibility option.
    Suppress,
}

/// One YAML entry under `suppressions:`. Schema is stable — additions
/// are non-breaking, removals require a major taudit version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    /// 32-char hex precise finding fingerprint. Matches JSON
    /// `findings[].fingerprint`, SARIF
    /// `partialFingerprints[primaryLocationLineHash]`, and CloudEvents
    /// `tauditfindingfingerprint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,

    /// Versioned operator-stable waiver key (`sk1_` plus 32 hex chars). Matches JSON
    /// `findings[].suppression_key`, SARIF `properties.suppressionKey`, and
    /// CloudEvents `tauditsuppressionkey`. Use this when a reviewed waiver
    /// should survive harmless surrounding workflow edits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppression_key: Option<String>,

    /// Snake-case rule id (or custom rule id) being waived. Used for
    /// human-readable display and to surface mismatched waivers when a
    /// fingerprint resolves to a different rule than the operator
    /// expected.
    pub rule_id: String,

    /// Operator-supplied justification. Required — a waiver without a
    /// reason is a documentation gap that defeats the audit trail.
    pub reason: String,

    /// Identity of the person who accepted the risk (email, GitHub
    /// handle, employee id — whatever the org uses).
    pub accepted_by: String,

    /// Date the waiver was created. Used by `taudit suppressions review`
    /// to flag waivers older than 90 days for re-review.
    pub accepted_at: String,

    /// Optional expiry date. **Required** when the waived finding is
    /// Critical — see the "Hard rules" section in the module docs.
    /// When absent, the waiver never expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Top-level configuration loaded from `.taudit-suppressions.yml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SuppressionConfig {
    #[serde(default)]
    pub suppressions: Vec<Suppression>,
}

impl Suppression {
    fn display_locator(&self) -> String {
        if let Some(fp) = self.fingerprint.as_deref() {
            format!("fingerprint {fp}")
        } else if let Some(key) = self.suppression_key.as_deref() {
            format!("suppression_key {key}")
        } else {
            "empty locator".to_string()
        }
    }

    fn match_token(&self) -> String {
        if let Some(fp) = self.fingerprint.as_deref() {
            format!("fingerprint:{fp}")
        } else if let Some(key) = self.suppression_key.as_deref() {
            format!("suppression_key:{key}")
        } else {
            format!("empty:{}:{}", self.rule_id, self.accepted_at)
        }
    }
}

/// Errors raised by the loader. `Parse` is the YAML-syntax case;
/// `MissingExpiryForCritical` is the hard-rule violation.
///
/// `Parse` deliberately omits the underlying `serde_yaml::Error`'s message
/// from the user-facing `Display` impl. That message can include a
/// fragment of the parsed content, and a hostile contributor who plants
/// `.taudit-suppressions.yml` as a symlink to e.g. `/etc/hostname`
/// would otherwise leak that content into CI logs via the failed parse.
/// The full error is still available via `source()` if a caller wants
/// it for trace-level logging.
#[derive(Debug, thiserror::Error)]
pub enum SuppressionError {
    #[error("failed to read suppression file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path} as YAML")]
    Parse {
        path: String,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("refusing to read suppression file symlink {path}")]
    Symlink { path: String },
    #[error("suppression file {path} exceeds {max_bytes} byte limit ({actual_bytes} bytes)")]
    TooLarge {
        path: String,
        max_bytes: u64,
        actual_bytes: u64,
    },
    #[error(
        "suppression for {locator} (rule {rule_id}) waives a critical finding but has no expires_at — critical waivers must expire"
    )]
    MissingExpiryForCritical { locator: String, rule_id: String },
}

/// Status surfaced by `taudit suppressions list` / `review` for each
/// loaded entry. Computed against the current date at call time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionStatus {
    /// `expires_at` is absent or in the future, and the entry was
    /// accepted within the last 90 days.
    Active,
    /// `expires_at` is in the future but within 30 days.
    ExpiringSoon,
    /// `expires_at` is in the past.
    Expired,
    /// No `expires_at` and `accepted_at` is older than 90 days. The
    /// suppression still applies, but `taudit suppressions review`
    /// flags it for human re-evaluation.
    StaleForReview,
}

impl SuppressionConfig {
    /// Load and parse a `.taudit-suppressions.yml` file. Returns an
    /// empty config when the file does not exist (the common case for
    /// unconfigured repos).
    ///
    /// Critical-without-expiry validation runs against `findings_to_check`
    /// when supplied so the loader can fail fast on a misconfiguration
    /// against a known critical fingerprint. Pass `&[]` to skip that
    /// check (useful for the `suppressions list/review` subcommands
    /// which inspect waivers without a scan in flight).
    pub fn load_from_path(path: &std::path::Path) -> Result<Self, SuppressionError> {
        let content = read_config_file(path)?;
        if content.is_empty() && !path.exists() {
            return Ok(Self::default());
        }
        let cfg: SuppressionConfig =
            serde_yaml::from_str(&content).map_err(|e| SuppressionError::Parse {
                path: path.display().to_string(),
                source: e,
            })?;
        Ok(cfg)
    }

    /// Look up the canonical suppression file for `repo_root`. Returns
    /// the first of `<root>/.taudit-suppressions.yml` and
    /// `<root>/.taudit/suppressions.yml` that exists, or `None`.
    pub fn discover(repo_root: &std::path::Path) -> Option<std::path::PathBuf> {
        let primary = repo_root.join(".taudit-suppressions.yml");
        if primary.exists() {
            return Some(primary);
        }
        let fallback = repo_root.join(".taudit/suppressions.yml");
        if fallback.exists() {
            return Some(fallback);
        }
        None
    }

    /// Validate that critical-finding waivers carry `expires_at`.
    /// Call after loading and after computing each finding's
    /// fingerprint so the check has full context.
    ///
    /// `critical_fingerprints` is the set of fingerprints of findings
    /// the current scan considers Critical. A waiver entry that
    /// matches one of those AND lacks `expires_at` produces an error
    /// per the hard rule in module docs.
    pub fn validate_critical_waivers<'a, I, J>(
        &self,
        critical_fingerprints: I,
        critical_suppression_keys: J,
    ) -> Result<(), Vec<SuppressionError>>
    where
        I: IntoIterator<Item = &'a str>,
        J: IntoIterator<Item = &'a str>,
    {
        let critical_fingerprint_set: std::collections::HashSet<&str> =
            critical_fingerprints.into_iter().collect();
        let critical_key_set: std::collections::HashSet<&str> =
            critical_suppression_keys.into_iter().collect();
        let mut errors = Vec::new();
        for entry in &self.suppressions {
            let matches_critical = entry
                .fingerprint
                .as_deref()
                .is_some_and(|fp| critical_fingerprint_set.contains(fp))
                || entry
                    .suppression_key
                    .as_deref()
                    .is_some_and(|key| critical_key_set.contains(key));
            if entry.expires_at.is_none() && matches_critical {
                errors.push(SuppressionError::MissingExpiryForCritical {
                    locator: entry.display_locator(),
                    rule_id: entry.rule_id.clone(),
                });
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Apply suppressions to a list of findings. Returns the modified
    /// findings AND a list of human-readable warnings (one per expired
    /// waiver that would otherwise have applied, etc.).
    ///
    /// Mutation contract:
    ///   * `Downgrade` mode: matched finding's `severity` drops one
    ///     tier; `extras.original_severity` records the prior tier;
    ///     `extras.suppression_reason` records the operator reason.
    ///   * `Suppress` mode: matched finding's `extras.suppressed = true`,
    ///     `extras.suppression_reason` set, severity untouched.
    ///   * Expired waivers do not apply but emit a warning.
    pub fn apply(
        &self,
        findings: Vec<Finding>,
        mode: SuppressionMode,
        fingerprints: &[String],
        suppression_keys: &[String],
        today: chrono::NaiveDate,
    ) -> (Vec<Finding>, Vec<String>, std::collections::HashSet<String>) {
        // Index suppressions by both precise fingerprint and stable
        // suppression key for O(1) lookup. If duplicates exist, the first
        // wins — keep loader order so behaviour is predictable.
        let mut by_fp: std::collections::HashMap<&str, &Suppression> =
            std::collections::HashMap::with_capacity(self.suppressions.len());
        let mut by_key: std::collections::HashMap<&str, &Suppression> =
            std::collections::HashMap::with_capacity(self.suppressions.len());
        for entry in &self.suppressions {
            if let Some(fp) = entry.fingerprint.as_deref() {
                by_fp.entry(fp).or_insert(entry);
            }
            if let Some(key) = entry.suppression_key.as_deref() {
                by_key.entry(key).or_insert(entry);
            }
        }

        let mut warnings = Vec::new();
        let mut out: Vec<Finding> = Vec::with_capacity(findings.len());
        let mut matched: std::collections::HashSet<String> = std::collections::HashSet::new();

        for (i, mut finding) in findings.into_iter().enumerate() {
            let fp = fingerprints.get(i).map(String::as_str);
            let key = suppression_keys.get(i).map(String::as_str);
            let entry = fp
                .and_then(|f| by_fp.get(f).copied())
                .or_else(|| key.and_then(|k| by_key.get(k).copied()));
            let Some(entry) = entry else {
                out.push(finding);
                continue;
            };
            matched.insert(entry.match_token());

            // Expired? Emit a warning, do not apply.
            if let Some(ref expiry) = entry.expires_at {
                if let Ok(expiry_date) = chrono::NaiveDate::parse_from_str(expiry, "%Y-%m-%d") {
                    if expiry_date < today {
                        warnings.push(format!(
                            "WARNING: suppression for {} expired on {}; finding restored to original severity",
                            entry.display_locator(),
                            expiry,
                        ));
                        out.push(finding);
                        continue;
                    }
                } else {
                    warnings.push(format!(
                        "WARNING: suppression for {} has unparseable expires_at '{}' (expected YYYY-MM-DD); ignoring entry",
                        entry.display_locator(),
                        expiry,
                    ));
                    out.push(finding);
                    continue;
                }
            }

            // Apply.
            let original = finding.severity;
            match mode {
                SuppressionMode::Downgrade => {
                    finding.severity = downgrade_severity(finding.severity);
                }
                SuppressionMode::Suppress => {
                    finding.extras.suppressed = true;
                }
            }
            // Record the pre-application severity exactly once. Both
            // modes participate: Downgrade because severity changed,
            // Suppress because consumers want the "what would this have
            // been" value alongside the suppressed flag.
            if finding.extras.original_severity.is_none()
                && (finding.severity != original || mode == SuppressionMode::Suppress)
            {
                finding.extras.original_severity = Some(original);
            }
            finding.extras.suppression_reason = Some(entry.reason.clone());
            out.push(finding);
        }

        (out, warnings, matched)
    }

    /// Warnings for suppression entries that matched nothing in the current
    /// run. Silent no-op waivers are operationally dangerous because they look
    /// configured but do not affect the gate.
    pub fn unmatched_warnings(
        &self,
        matched_suppressions: &std::collections::HashSet<String>,
    ) -> Vec<String> {
        let mut warnings = Vec::new();
        for entry in &self.suppressions {
            if matched_suppressions.contains(&entry.match_token()) {
                continue;
            }

            let mut warning = format!(
                "warning: suppression for {} (rule {}) matched no finding in this run",
                entry.display_locator(),
                entry.rule_id
            );

            if let Some(fingerprint) = entry.fingerprint.as_deref() {
                if fingerprint.len() != CURRENT_FINGERPRINT_HEX_LEN {
                    warning.push_str(&format!(
                        " — fingerprint length {} hex chars is unexpected for this build (expected {})",
                        fingerprint.len(),
                        CURRENT_FINGERPRINT_HEX_LEN
                    ));
                }
            }

            warnings.push(warning);
        }
        warnings
    }

    /// Compute the runtime status of a single suppression entry.
    /// Used by `taudit suppressions list` / `review`.
    pub fn status_of(entry: &Suppression, today: chrono::NaiveDate) -> SuppressionStatus {
        if let Some(ref expiry) = entry.expires_at {
            if let Ok(expiry_date) = chrono::NaiveDate::parse_from_str(expiry, "%Y-%m-%d") {
                if expiry_date < today {
                    return SuppressionStatus::Expired;
                }
                let days_left = (expiry_date - today).num_days();
                if days_left <= 30 {
                    return SuppressionStatus::ExpiringSoon;
                }
                return SuppressionStatus::Active;
            }
        }
        // No expiry: check stale-for-review.
        if let Ok(accepted_date) = chrono::NaiveDate::parse_from_str(&entry.accepted_at, "%Y-%m-%d")
        {
            let age_days = (today - accepted_date).num_days();
            if age_days >= 90 {
                return SuppressionStatus::StaleForReview;
            }
        }
        SuppressionStatus::Active
    }
}

fn read_config_file(path: &std::path::Path) -> Result<String, SuppressionError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => {
            return Err(SuppressionError::Io {
                path: path.display().to_string(),
                source: e,
            })
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(SuppressionError::Symlink {
            path: path.display().to_string(),
        });
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(SuppressionError::TooLarge {
            path: path.display().to_string(),
            max_bytes: MAX_CONFIG_BYTES,
            actual_bytes: metadata.len(),
        });
    }
    let content = std::fs::read_to_string(path).map_err(|e| SuppressionError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    if content.len() as u64 > MAX_CONFIG_BYTES {
        return Err(SuppressionError::TooLarge {
            path: path.display().to_string(),
            max_bytes: MAX_CONFIG_BYTES,
            actual_bytes: content.len() as u64,
        });
    }
    Ok(content)
}

impl SuppressionStatus {
    /// One-word label suitable for tabular output.
    pub fn label(self) -> &'static str {
        match self {
            SuppressionStatus::Active => "active",
            SuppressionStatus::ExpiringSoon => "expiring-soon",
            SuppressionStatus::Expired => "expired",
            SuppressionStatus::StaleForReview => "stale-for-review",
        }
    }
}

/// Format and write a suppression entry as a YAML document fragment
/// suitable for appending to `.taudit-suppressions.yml`. Used by
/// `taudit suppressions add`.
pub fn render_entry_yaml(entry: &Suppression) -> String {
    let mut out = String::new();
    if let Some(ref fingerprint) = entry.fingerprint {
        out.push_str(&format!("  - fingerprint: \"{fingerprint}\"\n"));
        if let Some(ref suppression_key) = entry.suppression_key {
            out.push_str(&format!("    suppression_key: \"{suppression_key}\"\n"));
        }
    } else if let Some(ref suppression_key) = entry.suppression_key {
        out.push_str(&format!("  - suppression_key: \"{suppression_key}\"\n"));
    } else {
        out.push_str("  -\n");
    }
    out.push_str(&format!("    rule_id: \"{}\"\n", entry.rule_id));
    out.push_str(&format!(
        "    reason: \"{}\"\n",
        entry.reason.replace('"', "\\\"")
    ));
    out.push_str(&format!("    accepted_by: \"{}\"\n", entry.accepted_by));
    out.push_str(&format!("    accepted_at: \"{}\"\n", entry.accepted_at));
    if let Some(ref expiry) = entry.expires_at {
        out.push_str(&format!("    expires_at: \"{expiry}\"\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{
        Finding, FindingCategory, FindingExtras, FindingSource, Recommendation, Severity,
    };
    use chrono::NaiveDate;

    fn finding(severity: Severity, message: &str) -> Finding {
        Finding {
            severity,
            category: FindingCategory::UnpinnedAction,
            path: None,
            nodes_involved: vec![],
            message: message.into(),
            recommendation: Recommendation::Manual {
                action: "fix".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        }
    }

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 4, 26).unwrap()
    }

    #[test]
    fn loader_returns_empty_when_file_missing() {
        let cfg = SuppressionConfig::load_from_path(std::path::Path::new(
            "/nonexistent/path/to/.taudit-suppressions.yml",
        ))
        .expect("missing file should be Ok(empty)");
        assert!(cfg.suppressions.is_empty());
    }

    #[test]
    fn loader_parses_canonical_yaml() {
        let yaml = r#"
suppressions:
  - fingerprint: "5edb30f4db3b5fa3d7fe7289374b7155"
    rule_id: "untrusted_with_authority"
    reason: "Internal-only action; threat-modeled and accepted by security team."
    accepted_by: "ryan@example.com"
    accepted_at: "2026-04-26"
    expires_at: "2026-07-26"
  - fingerprint: "a3c8d9e1f2b4c5d6a3c8d9e1f2b4c5d6"
    rule_id: "long_lived_credential"
    reason: "External SaaS does not support OIDC yet; rotation policy in place."
    accepted_by: "ryan@example.com"
    accepted_at: "2026-04-26"
"#;
        let dir = tempdir();
        let path = dir.join(".taudit-suppressions.yml");
        std::fs::write(&path, yaml).unwrap();
        let cfg = SuppressionConfig::load_from_path(&path).expect("parse OK");
        assert_eq!(cfg.suppressions.len(), 2);
        assert_eq!(
            cfg.suppressions[0].fingerprint.as_deref(),
            Some("5edb30f4db3b5fa3d7fe7289374b7155")
        );
        assert_eq!(
            cfg.suppressions[0].expires_at.as_deref(),
            Some("2026-07-26")
        );
        assert!(cfg.suppressions[1].expires_at.is_none());
    }

    #[test]
    fn discover_finds_root_then_dot_taudit() {
        let dir = tempdir();
        // Neither present.
        assert!(SuppressionConfig::discover(&dir).is_none());
        // Just .taudit/suppressions.yml present.
        std::fs::create_dir_all(dir.join(".taudit")).unwrap();
        std::fs::write(dir.join(".taudit/suppressions.yml"), "suppressions: []").unwrap();
        assert_eq!(
            SuppressionConfig::discover(&dir).unwrap(),
            dir.join(".taudit/suppressions.yml")
        );
        // Root file takes precedence.
        std::fs::write(dir.join(".taudit-suppressions.yml"), "suppressions: []").unwrap();
        assert_eq!(
            SuppressionConfig::discover(&dir).unwrap(),
            dir.join(".taudit-suppressions.yml")
        );
    }

    #[test]
    fn downgrade_mode_drops_severity_one_tier_and_records_original() {
        let entry = Suppression {
            fingerprint: Some("deadbeef00000000".into()),
            suppression_key: None,
            rule_id: "unpinned_action".into(),
            reason: "internal action; risk owned by platform team".into(),
            accepted_by: "alice@example.com".into(),
            accepted_at: "2026-04-26".into(),
            expires_at: None,
        };
        let cfg = SuppressionConfig {
            suppressions: vec![entry],
        };

        let f = finding(Severity::High, "msg");
        let fingerprints = vec!["deadbeef00000000".to_string()];
        let suppression_keys = Vec::new();
        let (out, warnings, matched) = cfg.apply(
            vec![f],
            SuppressionMode::Downgrade,
            &fingerprints,
            &suppression_keys,
            today(),
        );
        assert!(warnings.is_empty());
        assert!(matched.contains("fingerprint:deadbeef00000000"));
        assert_eq!(out[0].severity, Severity::Medium);
        assert_eq!(out[0].extras.original_severity, Some(Severity::High));
        assert_eq!(
            out[0].extras.suppression_reason.as_deref(),
            Some("internal action; risk owned by platform team")
        );
        assert!(!out[0].extras.suppressed);
    }

    #[test]
    fn suppress_mode_sets_flag_and_does_not_change_severity() {
        let cfg = SuppressionConfig {
            suppressions: vec![Suppression {
                fingerprint: Some("deadbeef00000000".into()),
                suppression_key: None,
                rule_id: "unpinned_action".into(),
                reason: "fork-only build; never publishes".into(),
                accepted_by: "alice@example.com".into(),
                accepted_at: "2026-04-26".into(),
                expires_at: Some("2027-04-26".into()),
            }],
        };
        let f = finding(Severity::High, "msg");
        let fingerprints = vec!["deadbeef00000000".to_string()];
        let suppression_keys = Vec::new();
        let (out, _w, matched) = cfg.apply(
            vec![f],
            SuppressionMode::Suppress,
            &fingerprints,
            &suppression_keys,
            today(),
        );
        assert_eq!(out[0].severity, Severity::High);
        assert!(matched.contains("fingerprint:deadbeef00000000"));
        assert!(out[0].extras.suppressed);
        assert_eq!(out[0].extras.original_severity, Some(Severity::High));
    }

    #[test]
    fn suppression_key_matches_when_fingerprint_changes() {
        let cfg = SuppressionConfig {
            suppressions: vec![Suppression {
                fingerprint: None,
                suppression_key: Some("sk1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
                rule_id: "unpinned_action".into(),
                reason: "reviewed stable waiver".into(),
                accepted_by: "alice@example.com".into(),
                accepted_at: "2026-04-26".into(),
                expires_at: Some("2027-04-26".into()),
            }],
        };
        let f = finding(Severity::High, "msg");
        let fingerprints = vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()];
        let suppression_keys = vec!["sk1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()];
        let (out, warnings, matched) = cfg.apply(
            vec![f],
            SuppressionMode::Downgrade,
            &fingerprints,
            &suppression_keys,
            today(),
        );

        assert!(warnings.is_empty());
        assert!(matched.contains("suppression_key:sk1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert_eq!(out[0].severity, Severity::Medium);
    }

    #[test]
    fn expired_waiver_does_not_apply_and_emits_warning() {
        let cfg = SuppressionConfig {
            suppressions: vec![Suppression {
                fingerprint: Some("deadbeef00000000".into()),
                suppression_key: None,
                rule_id: "unpinned_action".into(),
                reason: "needs to rotate".into(),
                accepted_by: "alice@example.com".into(),
                accepted_at: "2026-01-01".into(),
                expires_at: Some("2026-03-01".into()),
            }],
        };
        let f = finding(Severity::High, "msg");
        let fingerprints = vec!["deadbeef00000000".to_string()];
        let suppression_keys = Vec::new();
        let (out, warnings, matched) = cfg.apply(
            vec![f],
            SuppressionMode::Downgrade,
            &fingerprints,
            &suppression_keys,
            today(),
        );
        // Severity unchanged.
        assert_eq!(out[0].severity, Severity::High);
        assert!(matched.contains("fingerprint:deadbeef00000000"));
        // Warning surfaced.
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].contains("expired on 2026-03-01"),
            "unexpected warning: {}",
            warnings[0]
        );
    }

    #[test]
    fn critical_without_expiry_is_rejected_at_validation() {
        let cfg = SuppressionConfig {
            suppressions: vec![Suppression {
                fingerprint: Some("cafebabecafebabe".into()),
                suppression_key: None,
                rule_id: "untrusted_with_authority".into(),
                reason: "no expiry on critical — should be rejected".into(),
                accepted_by: "alice@example.com".into(),
                accepted_at: "2026-04-26".into(),
                expires_at: None,
            }],
        };
        let critical = ["cafebabecafebabe"];
        let result = cfg.validate_critical_waivers(critical.iter().copied(), std::iter::empty());
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        match &errors[0] {
            SuppressionError::MissingExpiryForCritical { locator, .. } => {
                assert_eq!(locator, "fingerprint cafebabecafebabe");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn critical_with_expiry_passes_validation() {
        let cfg = SuppressionConfig {
            suppressions: vec![Suppression {
                fingerprint: Some("cafebabecafebabe".into()),
                suppression_key: None,
                rule_id: "untrusted_with_authority".into(),
                reason: "approved by security; rotates with quarterly review".into(),
                accepted_by: "alice@example.com".into(),
                accepted_at: "2026-04-26".into(),
                expires_at: Some("2026-07-26".into()),
            }],
        };
        let critical = ["cafebabecafebabe"];
        cfg.validate_critical_waivers(critical.iter().copied(), std::iter::empty())
            .expect("expiring waiver should pass");
    }

    #[test]
    fn critical_suppression_key_without_expiry_is_rejected() {
        let cfg = SuppressionConfig {
            suppressions: vec![Suppression {
                fingerprint: None,
                suppression_key: Some("sk1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()),
                rule_id: "untrusted_with_authority".into(),
                reason: "no expiry on critical — should be rejected".into(),
                accepted_by: "alice@example.com".into(),
                accepted_at: "2026-04-26".into(),
                expires_at: None,
            }],
        };
        let critical_keys = ["sk1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"];
        let result =
            cfg.validate_critical_waivers(std::iter::empty(), critical_keys.iter().copied());
        assert!(result.is_err());
        match &result.unwrap_err()[0] {
            SuppressionError::MissingExpiryForCritical { locator, .. } => {
                assert_eq!(
                    locator,
                    "suppression_key sk1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn unmatched_warning_reports_orphaned_suppression() {
        let cfg = SuppressionConfig {
            suppressions: vec![Suppression {
                fingerprint: Some("deadbeef00000000".into()),
                suppression_key: None,
                rule_id: "unpinned_action".into(),
                reason: "orphaned".into(),
                accepted_by: "alice@example.com".into(),
                accepted_at: "2026-04-26".into(),
                expires_at: Some("2026-07-26".into()),
            }],
        };

        let warnings = cfg.unmatched_warnings(&std::collections::HashSet::new());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("matched no finding"));
    }

    #[test]
    fn unmatched_warning_hints_on_unexpected_fingerprint_length() {
        let cfg = SuppressionConfig {
            suppressions: vec![Suppression {
                fingerprint: Some("deadbeefdeadbeef".into()),
                suppression_key: None,
                rule_id: "unpinned_action".into(),
                reason: "wrong length".into(),
                accepted_by: "alice@example.com".into(),
                accepted_at: "2026-04-26".into(),
                expires_at: Some("2026-07-26".into()),
            }],
        };

        let warnings = cfg.unmatched_warnings(&std::collections::HashSet::new());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("unexpected for this build"));
    }

    #[test]
    fn status_active_for_recent_no_expiry() {
        let entry = Suppression {
            fingerprint: Some("x".into()),
            suppression_key: None,
            rule_id: "y".into(),
            reason: "z".into(),
            accepted_by: "a".into(),
            accepted_at: "2026-04-01".into(),
            expires_at: None,
        };
        assert_eq!(
            SuppressionConfig::status_of(&entry, today()),
            SuppressionStatus::Active
        );
    }

    #[test]
    fn status_stale_for_review_after_90_days_no_expiry() {
        let entry = Suppression {
            fingerprint: Some("x".into()),
            suppression_key: None,
            rule_id: "y".into(),
            reason: "z".into(),
            accepted_by: "a".into(),
            accepted_at: "2025-12-01".into(),
            expires_at: None,
        };
        assert_eq!(
            SuppressionConfig::status_of(&entry, today()),
            SuppressionStatus::StaleForReview
        );
    }

    #[test]
    fn status_expiring_soon_within_30_days() {
        let entry = Suppression {
            fingerprint: Some("x".into()),
            suppression_key: None,
            rule_id: "y".into(),
            reason: "z".into(),
            accepted_by: "a".into(),
            accepted_at: "2026-04-01".into(),
            expires_at: Some("2026-05-15".into()), // 19 days from 2026-04-26
        };
        assert_eq!(
            SuppressionConfig::status_of(&entry, today()),
            SuppressionStatus::ExpiringSoon
        );
    }

    #[test]
    fn status_expired_after_expiry_date() {
        let entry = Suppression {
            fingerprint: Some("x".into()),
            suppression_key: None,
            rule_id: "y".into(),
            reason: "z".into(),
            accepted_by: "a".into(),
            accepted_at: "2025-01-01".into(),
            expires_at: Some("2026-01-01".into()),
        };
        assert_eq!(
            SuppressionConfig::status_of(&entry, today()),
            SuppressionStatus::Expired
        );
    }

    #[test]
    fn render_entry_yaml_round_trips() {
        let entry = Suppression {
            fingerprint: Some("5edb30f4db3b5fa3d7fe7289374b7155".into()),
            suppression_key: None,
            rule_id: "untrusted_with_authority".into(),
            reason: "internal action; risk accepted".into(),
            accepted_by: "alice@example.com".into(),
            accepted_at: "2026-04-26".into(),
            expires_at: Some("2026-07-26".into()),
        };
        let body = render_entry_yaml(&entry);
        let wrapped = format!("suppressions:\n{body}");
        let cfg: SuppressionConfig = serde_yaml::from_str(&wrapped).expect("round-trip parse");
        assert_eq!(cfg.suppressions.len(), 1);
        assert_eq!(cfg.suppressions[0].fingerprint, entry.fingerprint);
        assert_eq!(cfg.suppressions[0].rule_id, entry.rule_id);
        assert_eq!(cfg.suppressions[0].reason, entry.reason);
        assert_eq!(cfg.suppressions[0].expires_at, entry.expires_at);
    }

    /// Per-test scratch directory under the OS temp dir. Avoids the
    /// `tempfile` dependency for a single use site.
    fn tempdir() -> std::path::PathBuf {
        let unique = format!(
            "suppressions-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
