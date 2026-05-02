use serde::Deserialize;

use crate::finding::{Finding, FindingCategory};

const MAX_CONFIG_BYTES: u64 = 2 * 1024 * 1024;

/// A single ignore rule. Matches findings by category and optionally by
/// pipeline source file path.
#[derive(Debug, Clone, Deserialize)]
pub struct IgnoreRule {
    /// Required: finding category to match (snake_case, e.g. "unpinned_action").
    pub category: FindingCategory,
    /// Optional: glob pattern for the pipeline source file path.
    /// If absent, the rule matches all files.
    #[serde(default)]
    pub path: Option<String>,
    /// Optional: human-readable reason for suppression (documentation only).
    #[serde(default)]
    pub reason: Option<String>,
}

/// Top-level ignore configuration, loaded from `.tauditignore`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct IgnoreConfig {
    #[serde(default)]
    pub ignore: Vec<IgnoreRule>,
}

#[derive(Debug, thiserror::Error)]
pub enum IgnoreError {
    #[error("failed to read ignore file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse ignore file {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("refusing to read ignore file symlink {path}")]
    Symlink { path: String },
    #[error("ignore file {path} exceeds {max_bytes} byte limit ({actual_bytes} bytes)")]
    TooLarge {
        path: String,
        max_bytes: u64,
        actual_bytes: u64,
    },
}

/// Result of applying ignore rules to a set of findings.
pub struct IgnoreResult {
    /// Findings that passed through (not ignored).
    pub findings: Vec<Finding>,
    /// Number of findings that were suppressed.
    pub suppressed_count: usize,
}

impl IgnoreConfig {
    pub fn load_from_path(path: &std::path::Path) -> Result<Self, IgnoreError> {
        let content = read_config_file(path)?;
        if content.is_empty() && !path.exists() {
            return Ok(Self::default());
        }
        serde_yaml::from_str(&content).map_err(|source| IgnoreError::Parse {
            path: path.display().to_string(),
            source,
        })
    }

    /// Apply ignore rules to a set of findings, given the source file path.
    /// Returns findings that were NOT matched by any ignore rule, plus a
    /// count of how many were suppressed.
    pub fn apply(&self, findings: Vec<Finding>, source_file: &str) -> IgnoreResult {
        if self.ignore.is_empty() {
            return IgnoreResult {
                findings,
                suppressed_count: 0,
            };
        }

        let mut kept = Vec::new();
        let mut suppressed = 0;

        for finding in findings {
            if self.matches(&finding, source_file) {
                suppressed += 1;
            } else {
                kept.push(finding);
            }
        }

        IgnoreResult {
            findings: kept,
            suppressed_count: suppressed,
        }
    }

    /// Check if any ignore rule matches this finding.
    fn matches(&self, finding: &Finding, source_file: &str) -> bool {
        self.ignore
            .iter()
            .any(|rule| rule.matches(finding, source_file))
    }
}

fn read_config_file(path: &std::path::Path) -> Result<String, IgnoreError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => {
            return Err(IgnoreError::Io {
                path: path.display().to_string(),
                source: e,
            })
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(IgnoreError::Symlink {
            path: path.display().to_string(),
        });
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(IgnoreError::TooLarge {
            path: path.display().to_string(),
            max_bytes: MAX_CONFIG_BYTES,
            actual_bytes: metadata.len(),
        });
    }
    let content = std::fs::read_to_string(path).map_err(|source| IgnoreError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if content.len() as u64 > MAX_CONFIG_BYTES {
        return Err(IgnoreError::TooLarge {
            path: path.display().to_string(),
            max_bytes: MAX_CONFIG_BYTES,
            actual_bytes: content.len() as u64,
        });
    }
    Ok(content)
}

impl IgnoreRule {
    /// Check if this rule matches a specific finding and source file.
    fn matches(&self, finding: &Finding, source_file: &str) -> bool {
        // Category must match
        if self.category != finding.category {
            return false;
        }

        // If path pattern is specified, it must match the source file
        if let Some(ref pattern) = self.path {
            return glob_match(pattern, source_file);
        }

        // Category-only rule matches all files
        true
    }
}

/// Match a glob pattern against a file path.
/// Supports `*` (match any sequence of characters) and `**` (same, but
/// `**` in the middle of a pattern naturally matches path separators too).
/// Exported so the CLI can apply the same logic for `--exclude` patterns.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Split pattern by '*' and check if all parts appear in order
    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.len() == 1 {
        // No wildcards — exact match
        return pattern == text;
    }

    let mut pos = 0;

    // First part must match at start (if non-empty)
    if !parts[0].is_empty() {
        if !text.starts_with(parts[0]) {
            return false;
        }
        pos = parts[0].len();
    }

    // Last part must match at end (if non-empty)
    let last = parts[parts.len() - 1];
    let end_bound = if !last.is_empty() {
        if !text.ends_with(last) {
            return false;
        }
        text.len() - last.len()
    } else {
        text.len()
    };

    // Middle parts must appear in order between start and end
    for part in &parts[1..parts.len() - 1] {
        if part.is_empty() {
            continue;
        }
        if let Some(found) = text[pos..end_bound].find(part) {
            pos += found + part.len();
        } else {
            return false;
        }
    }

    pos <= end_bound
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{FindingExtras, FindingSource, Recommendation, Severity};

    fn finding(category: FindingCategory) -> Finding {
        Finding {
            severity: Severity::High,
            category,
            path: None,
            nodes_involved: vec![0],
            message: "test".into(),
            recommendation: Recommendation::Manual {
                action: "fix".into(),
            },
            source: FindingSource::BuiltIn,
            extras: FindingExtras::default(),
        }
    }

    #[test]
    fn category_only_rule_matches_all_files() {
        let config = IgnoreConfig {
            ignore: vec![IgnoreRule {
                category: FindingCategory::UnpinnedAction,
                path: None,
                reason: Some("accepted".into()),
            }],
        };

        let findings = vec![
            finding(FindingCategory::UnpinnedAction),
            finding(FindingCategory::AuthorityPropagation),
        ];

        let result = config.apply(findings, ".github/workflows/ci.yml");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.suppressed_count, 1);
        assert_eq!(
            result.findings[0].category,
            FindingCategory::AuthorityPropagation
        );
    }

    #[test]
    fn path_glob_filters_to_specific_file() {
        let config = IgnoreConfig {
            ignore: vec![IgnoreRule {
                category: FindingCategory::UnpinnedAction,
                path: Some(".github/workflows/legacy.yml".into()),
                reason: None,
            }],
        };

        // Should match legacy.yml
        let result_legacy = config.apply(
            vec![finding(FindingCategory::UnpinnedAction)],
            ".github/workflows/legacy.yml",
        );
        assert_eq!(result_legacy.findings.len(), 0);
        assert_eq!(result_legacy.suppressed_count, 1);

        // Should NOT match ci.yml
        let result_ci = config.apply(
            vec![finding(FindingCategory::UnpinnedAction)],
            ".github/workflows/ci.yml",
        );
        assert_eq!(result_ci.findings.len(), 1);
        assert_eq!(result_ci.suppressed_count, 0);
    }

    #[test]
    fn path_glob_with_wildcard() {
        let config = IgnoreConfig {
            ignore: vec![IgnoreRule {
                category: FindingCategory::OverPrivilegedIdentity,
                path: Some("*.yml".into()),
                reason: None,
            }],
        };

        let result = config.apply(
            vec![finding(FindingCategory::OverPrivilegedIdentity)],
            ".github/workflows/ci.yml",
        );
        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.suppressed_count, 1);
    }

    #[test]
    fn unmatched_findings_pass_through() {
        let config = IgnoreConfig {
            ignore: vec![IgnoreRule {
                category: FindingCategory::FloatingImage,
                path: None,
                reason: None,
            }],
        };

        let findings = vec![
            finding(FindingCategory::UnpinnedAction),
            finding(FindingCategory::AuthorityPropagation),
            finding(FindingCategory::OverPrivilegedIdentity),
        ];

        let result = config.apply(findings, "ci.yml");
        assert_eq!(result.findings.len(), 3, "no findings should be suppressed");
        assert_eq!(result.suppressed_count, 0);
    }

    #[test]
    fn empty_config_passes_everything() {
        let config = IgnoreConfig::default();
        let findings = vec![
            finding(FindingCategory::UnpinnedAction),
            finding(FindingCategory::AuthorityPropagation),
        ];

        let result = config.apply(findings, "ci.yml");
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.suppressed_count, 0);
    }

    #[test]
    fn multiple_rules_compose() {
        let config = IgnoreConfig {
            ignore: vec![
                IgnoreRule {
                    category: FindingCategory::UnpinnedAction,
                    path: None,
                    reason: None,
                },
                IgnoreRule {
                    category: FindingCategory::LongLivedCredential,
                    path: Some("*legacy*".into()),
                    reason: Some("migrating".into()),
                },
            ],
        };

        let findings = vec![
            finding(FindingCategory::UnpinnedAction),
            finding(FindingCategory::LongLivedCredential),
            finding(FindingCategory::AuthorityPropagation),
        ];

        // legacy file: both rules apply
        let result = config.apply(findings, ".github/workflows/legacy-deploy.yml");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.suppressed_count, 2);
        assert_eq!(
            result.findings[0].category,
            FindingCategory::AuthorityPropagation
        );
    }

    // ── glob_match unit tests ──────────────────────────────

    #[test]
    fn glob_exact_match() {
        assert!(glob_match("foo.yml", "foo.yml"));
        assert!(!glob_match("foo.yml", "bar.yml"));
    }

    #[test]
    fn glob_star_suffix() {
        assert!(glob_match("*.yml", "ci.yml"));
        assert!(glob_match("*.yml", ".github/workflows/ci.yml"));
        assert!(!glob_match("*.yml", "ci.yaml"));
    }

    #[test]
    fn glob_star_prefix() {
        assert!(glob_match("ci.*", "ci.yml"));
        assert!(glob_match("ci.*", "ci.yaml"));
        assert!(!glob_match("ci.*", "deploy.yml"));
    }

    #[test]
    fn glob_star_middle() {
        assert!(glob_match(".github/*/ci.yml", ".github/workflows/ci.yml"));
        assert!(!glob_match(".github/*/ci.yml", ".github/ci.yml"));
    }

    #[test]
    fn glob_wildcard_all() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }
}
