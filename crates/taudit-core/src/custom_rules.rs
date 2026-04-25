use crate::finding::{Finding, FindingCategory, Recommendation, Severity};
use crate::graph::{AuthorityGraph, NodeKind, TrustZone};
use crate::propagation::PropagationPath;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// A user-defined rule loaded from YAML. Fires when source, sink, and path
/// predicates all match a propagation path produced by the engine.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomRule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub severity: Severity,
    pub category: FindingCategory,
    #[serde(rename = "match", default)]
    pub match_spec: MatchSpec,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MatchSpec {
    #[serde(default)]
    pub source: NodeMatcher,
    #[serde(default)]
    pub sink: NodeMatcher,
    #[serde(default)]
    pub path: PathMatcher,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NodeMatcher {
    #[serde(default)]
    pub node_type: Option<NodeKind>,
    #[serde(default)]
    pub trust_zone: Option<TrustZone>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PathMatcher {
    #[serde(default)]
    pub crosses_to: Vec<TrustZone>,
}

#[derive(Debug)]
pub enum CustomRuleError {
    FileRead(PathBuf, io::Error),
    YamlParse(PathBuf, serde_yaml::Error),
}

impl fmt::Display for CustomRuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CustomRuleError::FileRead(path, err) => {
                write!(
                    f,
                    "failed to read custom rule file {}: {err}",
                    path.display()
                )
            }
            CustomRuleError::YamlParse(path, err) => {
                write!(
                    f,
                    "failed to parse custom rule file {}: {err}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for CustomRuleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CustomRuleError::FileRead(_, err) => Some(err),
            CustomRuleError::YamlParse(_, err) => Some(err),
        }
    }
}

/// Load all `*.yml` and `*.yaml` files from `dir`. Files are read in sorted
/// order for deterministic output. Returns a list of all errors alongside
/// successfully parsed rules — callers decide whether to fail fast or continue.
pub fn load_rules_dir(dir: &Path) -> Result<Vec<CustomRule>, Vec<CustomRuleError>> {
    let mut entries: Vec<PathBuf> = Vec::new();
    let read_dir = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(err) => return Err(vec![CustomRuleError::FileRead(dir.to_path_buf(), err)]),
    };

    for entry in read_dir.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        match path.extension().and_then(|e| e.to_str()) {
            Some("yml") | Some("yaml") => entries.push(path),
            _ => {}
        }
    }
    entries.sort();

    let mut rules = Vec::new();
    let mut errors = Vec::new();
    for path in entries {
        match fs::read_to_string(&path) {
            Ok(content) => match serde_yaml::from_str::<CustomRule>(&content) {
                Ok(rule) => rules.push(rule),
                Err(err) => errors.push(CustomRuleError::YamlParse(path, err)),
            },
            Err(err) => errors.push(CustomRuleError::FileRead(path, err)),
        }
    }

    if errors.is_empty() {
        Ok(rules)
    } else {
        Err(errors)
    }
}

impl NodeMatcher {
    fn matches(&self, node: &crate::graph::Node) -> bool {
        if let Some(kind) = self.node_type {
            if node.kind != kind {
                return false;
            }
        }
        if let Some(zone) = self.trust_zone {
            if node.trust_zone != zone {
                return false;
            }
        }
        for (key, expected) in &self.metadata {
            match node.metadata.get(key) {
                Some(actual) if actual == expected => {}
                _ => return false,
            }
        }
        true
    }
}

impl PathMatcher {
    fn matches(&self, path: &PropagationPath) -> bool {
        if self.crosses_to.is_empty() {
            return true;
        }
        match path.boundary_crossing {
            Some((_, to_zone)) => self.crosses_to.contains(&to_zone),
            None => false,
        }
    }
}

/// Evaluate every (rule, path) pair. A finding is produced when the rule's
/// source, sink, and path predicates all match. Findings carry the rule id in
/// the message so operators can trace back to the originating YAML.
pub fn evaluate_custom_rules(
    graph: &AuthorityGraph,
    paths: &[PropagationPath],
    rules: &[CustomRule],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in rules {
        for path in paths {
            let source_node = match graph.node(path.source) {
                Some(n) => n,
                None => continue,
            };
            let sink_node = match graph.node(path.sink) {
                Some(n) => n,
                None => continue,
            };

            if !rule.match_spec.source.matches(source_node) {
                continue;
            }
            if !rule.match_spec.sink.matches(sink_node) {
                continue;
            }
            if !rule.match_spec.path.matches(path) {
                continue;
            }

            findings.push(Finding {
                severity: rule.severity,
                category: rule.category,
                nodes_involved: vec![path.source, path.sink],
                message: format!(
                    "[{}] {}: {} -> {}",
                    rule.id, rule.name, source_node.name, sink_node.name
                ),
                recommendation: Recommendation::Manual {
                    action: if rule.description.is_empty() {
                        format!("Review custom rule '{}'", rule.id)
                    } else {
                        rule.description.clone()
                    },
                },
                path: Some(path.clone()),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{AuthorityGraph, EdgeKind, PipelineSource};
    use crate::propagation::{propagation_analysis, DEFAULT_MAX_HOPS};

    fn source() -> PipelineSource {
        PipelineSource {
            file: "test.yml".into(),
            repo: None,
            git_ref: None,
        }
    }

    fn build_graph_with_paths() -> (AuthorityGraph, Vec<PropagationPath>) {
        let mut g = AuthorityGraph::new(source());
        let secret = g.add_node(NodeKind::Secret, "API_KEY", TrustZone::FirstParty);
        let trusted = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        let untrusted = g.add_node(NodeKind::Step, "third-party", TrustZone::Untrusted);

        g.add_edge(trusted, secret, EdgeKind::HasAccessTo);
        g.add_edge(trusted, untrusted, EdgeKind::DelegatesTo);

        let paths = propagation_analysis(&g, DEFAULT_MAX_HOPS);
        (g, paths)
    }

    #[test]
    fn custom_rule_fires_on_matching_path() {
        let (graph, paths) = build_graph_with_paths();

        let rule = CustomRule {
            id: "secret_to_untrusted".into(),
            name: "Secret reaching untrusted step".into(),
            description: "Custom policy".into(),
            severity: Severity::Critical,
            category: FindingCategory::AuthorityPropagation,
            match_spec: MatchSpec {
                source: NodeMatcher {
                    node_type: None,
                    trust_zone: Some(TrustZone::FirstParty),
                    metadata: HashMap::new(),
                },
                sink: NodeMatcher {
                    node_type: None,
                    trust_zone: Some(TrustZone::Untrusted),
                    metadata: HashMap::new(),
                },
                path: PathMatcher::default(),
            },
        };

        let findings = evaluate_custom_rules(&graph, &paths, &[rule]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].message.contains("secret_to_untrusted"));
    }

    #[test]
    fn custom_rule_does_not_fire_when_predicates_miss() {
        let (graph, paths) = build_graph_with_paths();

        let rule = CustomRule {
            id: "miss".into(),
            name: "Untrusted source".into(),
            description: String::new(),
            severity: Severity::Critical,
            category: FindingCategory::AuthorityPropagation,
            match_spec: MatchSpec {
                source: NodeMatcher {
                    node_type: None,
                    trust_zone: Some(TrustZone::Untrusted),
                    metadata: HashMap::new(),
                },
                sink: NodeMatcher::default(),
                path: PathMatcher::default(),
            },
        };

        let findings = evaluate_custom_rules(&graph, &paths, &[rule]);
        assert!(findings.is_empty());
    }

    #[test]
    fn yaml_round_trip_loads_full_rule() {
        let yaml = r#"
id: my_secret_to_untrusted
name: Secret reaching untrusted step
description: "Custom policy: secrets must not reach untrusted steps"
severity: critical
category: authority_propagation
match:
  source:
    node_type: secret
    trust_zone: first_party
  sink:
    node_type: step
    trust_zone: untrusted
  path:
    crosses_to: [untrusted]
"#;
        let rule: CustomRule = serde_yaml::from_str(yaml).expect("yaml must parse");
        assert_eq!(rule.id, "my_secret_to_untrusted");
        assert_eq!(rule.severity, Severity::Critical);
        assert_eq!(rule.match_spec.source.node_type, Some(NodeKind::Secret));
        assert_eq!(rule.match_spec.sink.trust_zone, Some(TrustZone::Untrusted));
        assert_eq!(rule.match_spec.path.crosses_to, vec![TrustZone::Untrusted]);
    }

    #[test]
    fn metadata_predicate_must_match_all_keys() {
        let mut g = AuthorityGraph::new(source());
        let mut meta = HashMap::new();
        meta.insert("kind".to_string(), "deploy".to_string());
        let secret =
            g.add_node_with_metadata(NodeKind::Secret, "TOKEN", TrustZone::FirstParty, meta);
        let sink = g.add_node(NodeKind::Step, "remote", TrustZone::Untrusted);
        let step = g.add_node(NodeKind::Step, "use", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);
        g.add_edge(step, sink, EdgeKind::DelegatesTo);

        let paths = propagation_analysis(&g, DEFAULT_MAX_HOPS);

        let mut want = HashMap::new();
        want.insert("kind".to_string(), "deploy".to_string());
        let hit = CustomRule {
            id: "hit".into(),
            name: "n".into(),
            description: String::new(),
            severity: Severity::High,
            category: FindingCategory::AuthorityPropagation,
            match_spec: MatchSpec {
                source: NodeMatcher {
                    node_type: Some(NodeKind::Secret),
                    trust_zone: None,
                    metadata: want.clone(),
                },
                sink: NodeMatcher::default(),
                path: PathMatcher::default(),
            },
        };
        assert_eq!(evaluate_custom_rules(&g, &paths, &[hit]).len(), 1);

        let mut wrong = HashMap::new();
        wrong.insert("kind".to_string(), "build".to_string());
        let miss = CustomRule {
            id: "miss".into(),
            name: "n".into(),
            description: String::new(),
            severity: Severity::High,
            category: FindingCategory::AuthorityPropagation,
            match_spec: MatchSpec {
                source: NodeMatcher {
                    node_type: Some(NodeKind::Secret),
                    trust_zone: None,
                    metadata: wrong,
                },
                sink: NodeMatcher::default(),
                path: PathMatcher::default(),
            },
        };
        assert!(evaluate_custom_rules(&g, &paths, &[miss]).is_empty());
    }

    #[test]
    fn load_rules_dir_reads_yml_and_yaml() {
        let tmp = std::env::temp_dir().join(format!("taudit-custom-rules-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        let yml_path = tmp.join("a.yml");
        let yaml_path = tmp.join("b.yaml");
        let other_path = tmp.join("c.txt");

        fs::write(
            &yml_path,
            "id: a\nname: a\nseverity: high\ncategory: authority_propagation\n",
        )
        .unwrap();
        fs::write(
            &yaml_path,
            "id: b\nname: b\nseverity: medium\ncategory: unpinned_action\n",
        )
        .unwrap();
        fs::write(&other_path, "ignored").unwrap();

        let rules = load_rules_dir(&tmp).expect("load must succeed");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "a");
        assert_eq!(rules[1].id, "b");

        // cleanup
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn load_rules_dir_reports_yaml_errors_with_path() {
        let tmp =
            std::env::temp_dir().join(format!("taudit-custom-rules-bad-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        let bad = tmp.join("bad.yml");
        fs::write(&bad, "id: x\nseverity: not-a-real-severity\n").unwrap();

        let errs = load_rules_dir(&tmp).expect_err("should fail");
        assert_eq!(errs.len(), 1);
        let msg = errs[0].to_string();
        assert!(msg.contains("bad.yml"), "error must mention path: {msg}");

        let _ = fs::remove_dir_all(&tmp);
    }
}
