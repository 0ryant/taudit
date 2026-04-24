use crate::finding::{Finding, FindingCategory, Recommendation, Severity};
use crate::graph::{
    is_docker_digest_pinned, is_sha_pinned, AuthorityCompleteness, AuthorityGraph, EdgeKind,
    IdentityScope, NodeKind, TrustZone, META_CLI_FLAG_EXPOSED, META_CONTAINER, META_DIGEST,
    META_IDENTITY_SCOPE, META_PERMISSIONS,
};
use crate::propagation;

fn cap_severity(severity: Severity, max_severity: Severity) -> Severity {
    if severity < max_severity {
        max_severity
    } else {
        severity
    }
}

fn apply_confidence_cap(graph: &AuthorityGraph, findings: &mut [Finding]) {
    if graph.completeness != AuthorityCompleteness::Partial {
        return;
    }

    for finding in findings {
        finding.severity = cap_severity(finding.severity, Severity::High);
    }
}

/// MVP Rule 1: Authority (secret/identity) propagated across a trust boundary.
///
/// Severity graduation (tuned from real-world signal on 10 production workflows):
/// - Untrusted sink: Critical (real risk — unpinned code with authority)
/// - SHA-pinned ThirdParty sink: High (immutable code, but still cross-boundary)
/// - SHA-pinned sink + constrained identity: Medium (lowest-risk form — read-only
///   token to immutable third-party code, e.g. `contents:read` → `actions/checkout@sha`)
pub fn authority_propagation(graph: &AuthorityGraph, max_hops: usize) -> Vec<Finding> {
    let paths = propagation::propagation_analysis(graph, max_hops);

    paths
        .into_iter()
        .filter(|p| p.crossed_boundary)
        .map(|path| {
            let source_name = graph
                .node(path.source)
                .map(|n| n.name.as_str())
                .unwrap_or("?");
            let sink_name = graph
                .node(path.sink)
                .map(|n| n.name.as_str())
                .unwrap_or("?");

            // Graduate severity based on sink trust + source scope
            let sink_is_pinned = graph
                .node(path.sink)
                .map(|n| {
                    n.trust_zone == TrustZone::ThirdParty && n.metadata.contains_key(META_DIGEST)
                })
                .unwrap_or(false);

            let source_is_constrained = graph
                .node(path.source)
                .and_then(|n| n.metadata.get(META_IDENTITY_SCOPE))
                .map(|s| s == "constrained")
                .unwrap_or(false);

            let severity = if sink_is_pinned && source_is_constrained {
                Severity::Medium
            } else if sink_is_pinned {
                Severity::High
            } else {
                Severity::Critical
            };

            Finding {
                severity,
                category: FindingCategory::AuthorityPropagation,
                nodes_involved: vec![path.source, path.sink],
                message: format!("{source_name} propagated to {sink_name} across trust boundary"),
                recommendation: Recommendation::TsafeRemediation {
                    command: "tsafe exec --ns <scoped-namespace> -- <command>".to_string(),
                    explanation: format!("Scope {source_name} to only the steps that need it"),
                },
                path: Some(path),
            }
        })
        .collect()
}

/// MVP Rule 2: Identity scope broader than actual usage.
///
/// Uses `IdentityScope` classification from the precision layer. Broad and
/// Unknown scopes are flagged — Unknown is treated as risky because if we
/// can't determine the scope, we shouldn't assume it's safe.
pub fn over_privileged_identity(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for identity in graph.nodes_of_kind(NodeKind::Identity) {
        let granted_scope = identity
            .metadata
            .get(META_PERMISSIONS)
            .cloned()
            .unwrap_or_default();

        // Use IdentityScope from metadata if set by parser, otherwise classify from permissions
        let scope = identity
            .metadata
            .get(META_IDENTITY_SCOPE)
            .and_then(|s| match s.as_str() {
                "broad" => Some(IdentityScope::Broad),
                "constrained" => Some(IdentityScope::Constrained),
                "unknown" => Some(IdentityScope::Unknown),
                _ => None,
            })
            .unwrap_or_else(|| IdentityScope::from_permissions(&granted_scope));

        // Broad or Unknown scope — flag it. Unknown is treated as risky.
        let (should_flag, severity) = match scope {
            IdentityScope::Broad => (true, Severity::High),
            IdentityScope::Unknown => (true, Severity::Medium),
            IdentityScope::Constrained => (false, Severity::Info),
        };

        if !should_flag {
            continue;
        }

        let accessor_steps: Vec<_> = graph
            .edges_to(identity.id)
            .filter(|e| e.kind == EdgeKind::HasAccessTo)
            .filter_map(|e| graph.node(e.from))
            .collect();

        if !accessor_steps.is_empty() {
            let scope_label = match scope {
                IdentityScope::Broad => "broad",
                IdentityScope::Unknown => "unknown (treat as risky)",
                IdentityScope::Constrained => "constrained",
            };

            findings.push(Finding {
                severity,
                category: FindingCategory::OverPrivilegedIdentity,
                path: None,
                nodes_involved: std::iter::once(identity.id)
                    .chain(accessor_steps.iter().map(|n| n.id))
                    .collect(),
                message: format!(
                    "{} has {} scope (permissions: '{}') — likely broader than needed",
                    identity.name, scope_label, granted_scope
                ),
                recommendation: Recommendation::ReducePermissions {
                    current: granted_scope.clone(),
                    minimum: "{ contents: read }".into(),
                },
            });
        }
    }

    findings
}

/// MVP Rule 3: Third-party action/image without SHA pin.
///
/// Deduplicates by action reference — the same action used in multiple jobs
/// produces multiple Image nodes but should only be flagged once.
pub fn unpinned_action(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for image in graph.nodes_of_kind(NodeKind::Image) {
        if image.trust_zone == TrustZone::FirstParty {
            continue;
        }

        // Container images are handled by floating_image — skip here to avoid
        // double-flagging the same node as both UnpinnedAction and FloatingImage.
        if image.metadata.get(META_CONTAINER).map(|v| v == "true").unwrap_or(false) {
            continue;
        }

        // Deduplicate: same action reference flagged once
        if !seen.insert(&image.name) {
            continue;
        }

        let has_digest = image.metadata.contains_key(META_DIGEST);

        if !has_digest && !is_sha_pinned(&image.name) {
            findings.push(Finding {
                severity: Severity::Medium,
                category: FindingCategory::UnpinnedAction,
                path: None,
                nodes_involved: vec![image.id],
                message: format!("{} is not pinned to a SHA digest", image.name),
                recommendation: Recommendation::PinAction {
                    current: image.name.clone(),
                    pinned: format!(
                        "{}@<sha256-digest>",
                        image.name.split('@').next().unwrap_or(&image.name)
                    ),
                },
            });
        }
    }

    findings
}

/// MVP Rule 4: Untrusted step has direct access to secret/identity.
pub fn untrusted_with_authority(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for step in graph.nodes_in_zone(TrustZone::Untrusted) {
        if step.kind != NodeKind::Step {
            continue;
        }

        // Check if this untrusted step directly accesses any authority source
        for edge in graph.edges_from(step.id) {
            if edge.kind != EdgeKind::HasAccessTo {
                continue;
            }

            if let Some(target) = graph.node(edge.to) {
                if matches!(target.kind, NodeKind::Secret | NodeKind::Identity) {
                    let cli_flag_exposed = target
                        .metadata
                        .get(META_CLI_FLAG_EXPOSED)
                        .map(|v| v == "true")
                        .unwrap_or(false);

                    let recommendation = if target.kind == NodeKind::Secret {
                        if cli_flag_exposed {
                            Recommendation::Manual {
                                action: format!(
                                    "Move '{}' from -var flag to TF_VAR_{} env var — \
                                     -var values appear in pipeline logs and Terraform plan output",
                                    target.name, target.name
                                ),
                            }
                        } else {
                            Recommendation::CellosRemediation {
                                reason: format!(
                                    "Untrusted step '{}' has direct access to secret '{}'",
                                    step.name, target.name
                                ),
                                spec_hint: format!(
                                    "cellos run --network deny-all --broker env:{}",
                                    target.name
                                ),
                            }
                        }
                    } else {
                        Recommendation::ReducePermissions {
                            current: target
                                .metadata
                                .get(META_PERMISSIONS)
                                .cloned()
                                .unwrap_or_else(|| "unknown".into()),
                            minimum: "minimal required scope".into(),
                        }
                    };

                    let log_exposure_note = if cli_flag_exposed {
                        " (passed as -var flag — value visible in pipeline logs)"
                    } else {
                        ""
                    };

                    findings.push(Finding {
                        severity: Severity::Critical,
                        category: FindingCategory::UntrustedWithAuthority,
                        path: None,
                        nodes_involved: vec![step.id, target.id],
                        message: format!(
                            "Untrusted step '{}' has direct access to {} '{}'{}",
                            step.name,
                            if target.kind == NodeKind::Secret {
                                "secret"
                            } else {
                                "identity"
                            },
                            target.name,
                            log_exposure_note,
                        ),
                        recommendation,
                    });
                }
            }
        }
    }

    findings
}

/// MVP Rule 5: Artifact produced by privileged step consumed across trust boundary.
pub fn artifact_boundary_crossing(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for artifact in graph.nodes_of_kind(NodeKind::Artifact) {
        // Find producer(s)
        let producers: Vec<_> = graph
            .edges_to(artifact.id)
            .filter(|e| e.kind == EdgeKind::Produces)
            .filter_map(|e| graph.node(e.from))
            .collect();

        // Find consumer(s) — Consumes edges go artifact -> step
        let consumers: Vec<_> = graph
            .edges_from(artifact.id)
            .filter(|e| e.kind == EdgeKind::Consumes)
            .filter_map(|e| graph.node(e.to))
            .collect();

        for producer in &producers {
            // Only care if the producer is privileged (has access to secrets/identities)
            let producer_has_authority = graph.edges_from(producer.id).any(|e| {
                e.kind == EdgeKind::HasAccessTo
                    && graph
                        .node(e.to)
                        .map(|n| matches!(n.kind, NodeKind::Secret | NodeKind::Identity))
                        .unwrap_or(false)
            });

            if !producer_has_authority {
                continue;
            }

            for consumer in &consumers {
                if consumer.trust_zone.is_lower_than(&producer.trust_zone) {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: FindingCategory::ArtifactBoundaryCrossing,
                        path: None,
                        nodes_involved: vec![producer.id, artifact.id, consumer.id],
                        message: format!(
                            "Artifact '{}' produced by privileged step '{}' consumed by '{}' ({:?} -> {:?})",
                            artifact.name,
                            producer.name,
                            consumer.name,
                            producer.trust_zone,
                            consumer.trust_zone
                        ),
                        recommendation: Recommendation::TsafeRemediation {
                            command: format!(
                                "tsafe exec --ns {} -- <build-command>",
                                producer.name
                            ),
                            explanation: format!(
                                "Scope secrets to '{}' only; artifact '{}' should not carry authority",
                                producer.name, artifact.name
                            ),
                        },
                    });
                }
            }
        }
    }

    findings
}

/// Stretch Rule 9: Secret name matches known long-lived/static credential pattern.
///
/// Heuristic: secrets named like AWS keys, API keys, passwords, or private keys
/// are likely static credentials that should be replaced with OIDC federation.
pub fn long_lived_credential(graph: &AuthorityGraph) -> Vec<Finding> {
    const STATIC_PATTERNS: &[&str] = &[
        "AWS_ACCESS_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "_API_KEY",
        "_APIKEY",
        "_PASSWORD",
        "_PASSWD",
        "_PRIVATE_KEY",
        "_SECRET_KEY",
        "_SERVICE_ACCOUNT",
        "_SIGNING_KEY",
    ];

    let mut findings = Vec::new();

    for secret in graph.nodes_of_kind(NodeKind::Secret) {
        let upper = secret.name.to_uppercase();
        let is_static = STATIC_PATTERNS.iter().any(|p| upper.contains(p));

        if is_static {
            findings.push(Finding {
                severity: Severity::Low,
                category: FindingCategory::LongLivedCredential,
                path: None,
                nodes_involved: vec![secret.id],
                message: format!(
                    "'{}' looks like a long-lived static credential",
                    secret.name
                ),
                recommendation: Recommendation::FederateIdentity {
                    static_secret: secret.name.clone(),
                    oidc_provider: "GitHub Actions OIDC (id-token: write)".into(),
                },
            });
        }
    }

    findings
}

/// Tier 6 Rule: Container image without Docker digest pinning.
///
/// Job-level containers marked with `META_CONTAINER` that aren't pinned to
/// `image@sha256:<64hex>` can be silently mutated between runs. Deduplicates
/// by image name (same image in multiple jobs flags once).
pub fn floating_image(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for image in graph.nodes_of_kind(NodeKind::Image) {
        let is_container = image
            .metadata
            .get(META_CONTAINER)
            .map(|v| v == "true")
            .unwrap_or(false);

        if !is_container {
            continue;
        }

        if !seen.insert(image.name.as_str()) {
            continue;
        }

        if !is_docker_digest_pinned(&image.name) {
            findings.push(Finding {
                severity: Severity::Medium,
                category: FindingCategory::FloatingImage,
                path: None,
                nodes_involved: vec![image.id],
                message: format!(
                    "Container image '{}' is not pinned to a digest",
                    image.name
                ),
                recommendation: Recommendation::PinAction {
                    current: image.name.clone(),
                    pinned: format!(
                        "{}@sha256:<digest>",
                        image.name.split(':').next().unwrap_or(&image.name)
                    ),
                },
            });
        }
    }

    findings
}

/// Stretch Rule: checkout step with `persistCredentials: true` writes credentials to disk.
///
/// The PersistsTo edge connects a checkout step to the token it persists. Disk-resident
/// credentials are accessible to all subsequent steps (and to any process with filesystem
/// access), unlike runtime-only HasAccessTo authority which expires when the step exits.
pub fn persisted_credential(graph: &AuthorityGraph) -> Vec<Finding> {
    let mut findings = Vec::new();

    for edge in &graph.edges {
        if edge.kind != EdgeKind::PersistsTo {
            continue;
        }

        let Some(step) = graph.node(edge.from) else { continue };
        let Some(target) = graph.node(edge.to) else { continue };

        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::PersistedCredential,
            path: None,
            nodes_involved: vec![step.id, target.id],
            message: format!(
                "'{}' persists '{}' to disk via persistCredentials: true — \
                 credential remains in .git/config and is accessible to all subsequent steps",
                step.name, target.name
            ),
            recommendation: Recommendation::Manual {
                action: "Remove persistCredentials: true from the checkout step. \
                         Pass credentials explicitly only to steps that need them."
                    .into(),
            },
        });
    }

    findings
}

/// Run all rules against a graph.
pub fn run_all_rules(graph: &AuthorityGraph, max_hops: usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    // MVP rules
    findings.extend(authority_propagation(graph, max_hops));
    findings.extend(over_privileged_identity(graph));
    findings.extend(unpinned_action(graph));
    findings.extend(untrusted_with_authority(graph));
    findings.extend(artifact_boundary_crossing(graph));
    // Stretch rules
    findings.extend(long_lived_credential(graph));
    findings.extend(floating_image(graph));
    findings.extend(persisted_credential(graph));

    apply_confidence_cap(graph, &mut findings);

    findings.sort_by_key(|f| f.severity);

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::*;

    fn source(file: &str) -> PipelineSource {
        PipelineSource {
            file: file.into(),
            repo: None,
            git_ref: None,
        }
    }

    #[test]
    fn unpinned_third_party_action_flagged() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.add_node(
            NodeKind::Image,
            "actions/checkout@v4",
            TrustZone::ThirdParty,
        );

        let findings = unpinned_action(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::UnpinnedAction);
    }

    #[test]
    fn pinned_action_not_flagged() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.add_node(
            NodeKind::Image,
            "actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29",
            TrustZone::ThirdParty,
        );

        let findings = unpinned_action(&g);
        assert!(findings.is_empty());
    }

    #[test]
    fn untrusted_step_with_secret_is_critical() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let step = g.add_node(NodeKind::Step, "evil-action", TrustZone::Untrusted);
        let secret = g.add_node(NodeKind::Secret, "DEPLOY_KEY", TrustZone::FirstParty);
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let findings = untrusted_with_authority(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn artifact_crossing_detected() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let secret = g.add_node(NodeKind::Secret, "KEY", TrustZone::FirstParty);
        let build = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        let artifact = g.add_node(NodeKind::Artifact, "dist.zip", TrustZone::FirstParty);
        let deploy = g.add_node(NodeKind::Step, "deploy", TrustZone::ThirdParty);

        g.add_edge(build, secret, EdgeKind::HasAccessTo);
        g.add_edge(build, artifact, EdgeKind::Produces);
        g.add_edge(artifact, deploy, EdgeKind::Consumes);

        let findings = artifact_boundary_crossing(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].category,
            FindingCategory::ArtifactBoundaryCrossing
        );
    }

    #[test]
    fn propagation_to_sha_pinned_is_high_not_critical() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(
            "digest".into(),
            "a5ac7e51b41094c92402da3b24376905380afc29".into(),
        );
        let identity = g.add_node(NodeKind::Identity, "GITHUB_TOKEN", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "checkout", TrustZone::ThirdParty);
        let image = g.add_node_with_metadata(
            NodeKind::Image,
            "actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29",
            TrustZone::ThirdParty,
            meta,
        );

        g.add_edge(step, identity, EdgeKind::HasAccessTo);
        g.add_edge(step, image, EdgeKind::UsesImage);

        let findings = authority_propagation(&g, 4);
        // Should find propagation to the SHA-pinned image
        let image_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.nodes_involved.contains(&image))
            .collect();
        assert!(!image_findings.is_empty());
        // SHA-pinned targets get High, not Critical
        assert_eq!(image_findings[0].severity, Severity::High);
    }

    #[test]
    fn propagation_to_untrusted_is_critical() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let identity = g.add_node(NodeKind::Identity, "GITHUB_TOKEN", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "deploy", TrustZone::Untrusted);
        let image = g.add_node(NodeKind::Image, "evil/action@main", TrustZone::Untrusted);

        g.add_edge(step, identity, EdgeKind::HasAccessTo);
        g.add_edge(step, image, EdgeKind::UsesImage);

        let findings = authority_propagation(&g, 4);
        let image_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.nodes_involved.contains(&image))
            .collect();
        assert!(!image_findings.is_empty());
        assert_eq!(image_findings[0].severity, Severity::Critical);
    }

    #[test]
    fn long_lived_credential_detected() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.add_node(NodeKind::Secret, "AWS_ACCESS_KEY_ID", TrustZone::FirstParty);
        g.add_node(NodeKind::Secret, "NPM_TOKEN", TrustZone::FirstParty);
        g.add_node(NodeKind::Secret, "DEPLOY_API_KEY", TrustZone::FirstParty);
        // Non-matching names
        g.add_node(NodeKind::Secret, "CACHE_TTL", TrustZone::FirstParty);

        let findings = long_lived_credential(&g);
        assert_eq!(findings.len(), 2); // AWS_ACCESS_KEY_ID + DEPLOY_API_KEY
        assert!(findings
            .iter()
            .all(|f| f.category == FindingCategory::LongLivedCredential));
    }

    #[test]
    fn duplicate_unpinned_actions_deduplicated() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        // Same action used in two jobs — two Image nodes, same name
        g.add_node(NodeKind::Image, "actions/checkout@v4", TrustZone::Untrusted);
        g.add_node(NodeKind::Image, "actions/checkout@v4", TrustZone::Untrusted);
        g.add_node(
            NodeKind::Image,
            "actions/setup-node@v3",
            TrustZone::Untrusted,
        );

        let findings = unpinned_action(&g);
        // Should get 2 findings (checkout + setup-node), not 3
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn broad_identity_scope_flagged_as_high() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_PERMISSIONS.into(), "write-all".into());
        meta.insert(META_IDENTITY_SCOPE.into(), "broad".into());
        let identity =
            g.add_node_with_metadata(NodeKind::Identity, "GITHUB_TOKEN", TrustZone::FirstParty, meta);
        let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(step, identity, EdgeKind::HasAccessTo);

        let findings = over_privileged_identity(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("broad"));
    }

    #[test]
    fn unknown_identity_scope_flagged_as_medium() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_PERMISSIONS.into(), "custom-scope".into());
        meta.insert(META_IDENTITY_SCOPE.into(), "unknown".into());
        let identity =
            g.add_node_with_metadata(NodeKind::Identity, "GITHUB_TOKEN", TrustZone::FirstParty, meta);
        let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(step, identity, EdgeKind::HasAccessTo);

        let findings = over_privileged_identity(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("unknown"));
    }

    #[test]
    fn floating_image_unpinned_container_flagged() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_CONTAINER.into(), "true".into());
        g.add_node_with_metadata(NodeKind::Image, "ubuntu:22.04", TrustZone::Untrusted, meta);

        let findings = floating_image(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::FloatingImage);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn partial_graph_caps_critical_findings_at_high() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        g.mark_partial("matrix strategy hides some authority paths");

        let identity = g.add_node(NodeKind::Identity, "GITHUB_TOKEN", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "deploy", TrustZone::Untrusted);
        let image = g.add_node(NodeKind::Image, "evil/action@main", TrustZone::Untrusted);

        g.add_edge(step, identity, EdgeKind::HasAccessTo);
        g.add_edge(step, image, EdgeKind::UsesImage);

        let findings = run_all_rules(&g, 4);
        assert!(findings.iter().any(|f| f.category == FindingCategory::AuthorityPropagation));
        assert!(findings.iter().any(|f| f.category == FindingCategory::UntrustedWithAuthority));
        assert!(findings.iter().all(|f| f.severity >= Severity::High));
        assert!(!findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn complete_graph_keeps_critical_findings() {
        let mut g = AuthorityGraph::new(source("ci.yml"));

        let identity = g.add_node(NodeKind::Identity, "GITHUB_TOKEN", TrustZone::FirstParty);
        let step = g.add_node(NodeKind::Step, "deploy", TrustZone::Untrusted);
        let image = g.add_node(NodeKind::Image, "evil/action@main", TrustZone::Untrusted);

        g.add_edge(step, identity, EdgeKind::HasAccessTo);
        g.add_edge(step, image, EdgeKind::UsesImage);

        let findings = run_all_rules(&g, 4);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn floating_image_digest_pinned_container_not_flagged() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_CONTAINER.into(), "true".into());
        g.add_node_with_metadata(
            NodeKind::Image,
            "ubuntu@sha256:a5ac7e51b41094c92402da3b24376905380afc29a5ac7e51b41094c92402da3b",
            TrustZone::ThirdParty,
            meta,
        );

        let findings = floating_image(&g);
        assert!(findings.is_empty(), "digest-pinned container should not be flagged");
    }

    #[test]
    fn unpinned_action_does_not_flag_container_images() {
        // Regression: container Image nodes are handled by floating_image, not unpinned_action.
        // The same node must not generate findings from both rules.
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_CONTAINER.into(), "true".into());
        g.add_node_with_metadata(NodeKind::Image, "ubuntu:22.04", TrustZone::Untrusted, meta);

        let findings = unpinned_action(&g);
        assert!(
            findings.is_empty(),
            "unpinned_action must skip container images to avoid double-flagging"
        );
    }

    #[test]
    fn floating_image_ignores_action_images() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        // Image node without META_CONTAINER — this is a step uses: action, not a container
        g.add_node(NodeKind::Image, "actions/checkout@v4", TrustZone::Untrusted);

        let findings = floating_image(&g);
        assert!(findings.is_empty(), "floating_image should not flag step actions");
    }

    #[test]
    fn persisted_credential_rule_fires_on_persists_to_edge() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let token = g.add_node(NodeKind::Identity, "System.AccessToken", TrustZone::FirstParty);
        let checkout = g.add_node(NodeKind::Step, "checkout", TrustZone::FirstParty);
        g.add_edge(checkout, token, EdgeKind::PersistsTo);

        let findings = persisted_credential(&g);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::PersistedCredential);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("persistCredentials"));
    }

    #[test]
    fn untrusted_with_cli_flag_exposed_secret_notes_log_exposure() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let step = g.add_node(NodeKind::Step, "TerraformCLI@0", TrustZone::Untrusted);
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_CLI_FLAG_EXPOSED.into(), "true".into());
        let secret = g.add_node_with_metadata(
            NodeKind::Secret,
            "db_password",
            TrustZone::FirstParty,
            meta,
        );
        g.add_edge(step, secret, EdgeKind::HasAccessTo);

        let findings = untrusted_with_authority(&g);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains("-var flag"),
            "message should note -var flag log exposure"
        );
        assert!(matches!(
            findings[0].recommendation,
            Recommendation::Manual { .. }
        ));
    }

    #[test]
    fn constrained_identity_scope_not_flagged() {
        let mut g = AuthorityGraph::new(source("ci.yml"));
        let mut meta = std::collections::HashMap::new();
        meta.insert(META_PERMISSIONS.into(), "{ contents: read }".into());
        meta.insert(META_IDENTITY_SCOPE.into(), "constrained".into());
        let identity =
            g.add_node_with_metadata(NodeKind::Identity, "GITHUB_TOKEN", TrustZone::FirstParty, meta);
        let step = g.add_node(NodeKind::Step, "build", TrustZone::FirstParty);
        g.add_edge(step, identity, EdgeKind::HasAccessTo);

        let findings = over_privileged_identity(&g);
        assert!(findings.is_empty(), "constrained scope should not be flagged");
    }
}
