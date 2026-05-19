from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from dataclasses import dataclass
from typing import Any


REPORT_SCHEMA_URI = "https://taudit.dev/schemas/taudit-report.schema.json"
EXPLOIT_GRAPH_SCHEMA_URI = "https://taudit.dev/schemas/exploit-graph.v1.json"

FINGERPRINT_RE = re.compile(r"^[0-9a-f]{32}$")
SUPPRESSION_KEY_RE = re.compile(r"^sk1_[0-9a-f]{32}$")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PIPELINE_ID_RE = re.compile(r"^urn:taudit:pipeline:sha256:[0-9a-f]{64}$")
RULE_ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")
SEMVER_1_RE = re.compile(r"^1\.[0-9]+\.[0-9]+$")

FINDING_REQUIRED_FIELDS = [
    "severity",
    "category",
    "nodes_involved",
    "message",
    "recommendation",
    "rule_id",
    "source",
    "fingerprint",
    "suppression_key",
    "finding_group_id",
]

FORBIDDEN_DEFAULT_KEYS = {
    "canary_value",
    "canary_values",
    "disclosure_score",
    "disclosureScore",
    "fingerprint_anchor",
    "observed_sink_claim",
    "observed_sink_claims",
    "observedSinkClaim",
    "observedSinkClaims",
    "private_hosted_run_artifact",
    "private_hosted_run_artifacts",
    "witness_spec_next_action",
    "witnessSpecNextAction",
}


@dataclass(frozen=True)
class Issue:
    status: str
    surface: str
    artifact: str
    path: str
    code: str
    message: str

    def to_json(self) -> dict[str, str]:
        return {
            "status": self.status,
            "surface": self.surface,
            "artifact": self.artifact,
            "path": self.path,
            "code": self.code,
            "message": self.message,
        }


@dataclass
class ArtifactReceipt:
    surface: str
    path: str
    status: str
    fail: int
    pending: int

    def to_json(self) -> dict[str, Any]:
        return {
            "surface": self.surface,
            "path": self.path,
            "status": self.status,
            "fail": self.fail,
            "pending": self.pending,
        }


def check_current_profile(
    *,
    report_json: list[pathlib.Path] | None = None,
    cloudevent_json: list[pathlib.Path] | None = None,
    sarif_json: list[pathlib.Path] | None = None,
    exploit_graph_json: list[pathlib.Path] | None = None,
    baseline_json: list[pathlib.Path] | None = None,
    allow_observed_evidence: bool = False,
) -> dict[str, Any]:
    issues: list[Issue] = []
    artifacts: list[ArtifactReceipt] = []
    identity_surfaces: dict[str, list[dict[str, Any]]] = {}

    for path in report_json or []:
        before = len(issues)
        doc = _load_json(path, "report-json", issues)
        identities: list[dict[str, Any]] = []
        if doc is not None:
            identities = _check_report_json(doc, path, issues)
            identity_surfaces.setdefault("report-json", []).extend(identities)
        artifacts.append(_artifact_receipt("report-json", path, issues[before:]))

    for path in cloudevent_json or []:
        before = len(issues)
        docs = _load_cloudevents(path, issues)
        identities = []
        for index, doc in enumerate(docs):
            identities.append(_check_cloudevent(doc, path, index, issues))
        if docs:
            identity_surfaces.setdefault("cloudevents", []).extend(identities)
        artifacts.append(_artifact_receipt("cloudevents", path, issues[before:]))

    for path in sarif_json or []:
        before = len(issues)
        doc = _load_json(path, "sarif", issues)
        identities = []
        if doc is not None:
            identities = _check_sarif(doc, path, issues)
            identity_surfaces.setdefault("sarif", []).extend(identities)
        artifacts.append(_artifact_receipt("sarif", path, issues[before:]))

    for path in exploit_graph_json or []:
        before = len(issues)
        doc = _load_json(path, "exploit-graph", issues)
        if doc is not None:
            _check_exploit_graph(doc, path, issues, allow_observed_evidence)
        artifacts.append(_artifact_receipt("exploit-graph", path, issues[before:]))

    for path in baseline_json or []:
        before = len(issues)
        doc = _load_json(path, "baseline", issues)
        if doc is not None:
            _check_baseline(doc, path, issues)
        artifacts.append(_artifact_receipt("baseline", path, issues[before:]))

    if len(identity_surfaces) > 1:
        before = len(issues)
        _check_cross_surface_identity(list(identity_surfaces.items()), issues)
        if len(issues) > before:
            artifacts.append(
                _artifact_receipt(
                    "cross-surface",
                    pathlib.Path("<provided-artifacts>"),
                    issues[before:],
                )
            )

    fail_count = sum(1 for issue in issues if issue.status == "fail")
    pending_count = sum(1 for issue in issues if issue.status == "pending")
    status = "fail" if fail_count else ("incomplete" if pending_count else "pass")
    return {
        "schema": "taudit.current-output-profile-check.v1",
        "profile": "v1.2.0-rc.1",
        "status": status,
        "counts": {
            "artifacts": len(artifacts),
            "pass": sum(1 for artifact in artifacts if artifact.status == "pass"),
            "fail": fail_count,
            "pending": pending_count,
        },
        "artifacts": [artifact.to_json() for artifact in artifacts],
        "issues": [issue.to_json() for issue in issues],
    }


def _load_json(path: pathlib.Path, surface: str, issues: list[Issue]) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        _fail(issues, surface, path, "$", "read-error", str(exc))
    except json.JSONDecodeError as exc:
        _fail(issues, surface, path, "$", "invalid-json", str(exc))
    return None


def _load_cloudevents(path: pathlib.Path, issues: list[Issue]) -> list[dict[str, Any]]:
    text = ""
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        _fail(issues, "cloudevents", path, "$", "read-error", str(exc))
        return []
    if not text:
        _fail(issues, "cloudevents", path, "$", "empty-artifact", "CloudEvents artifact is empty")
        return []
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        events: list[dict[str, Any]] = []
        for index, line in enumerate(text.splitlines()):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                _fail(issues, "cloudevents", path, f"$.lines[{index}]", "invalid-json", str(exc))
                continue
            if isinstance(item, dict):
                events.append(item)
            else:
                _fail(
                    issues,
                    "cloudevents",
                    path,
                    f"$.lines[{index}]",
                    "type",
                    "CloudEvents JSONL entries must be objects",
                )
        return events
    if isinstance(loaded, dict):
        return [loaded]
    if isinstance(loaded, list):
        events = []
        for index, item in enumerate(loaded):
            if isinstance(item, dict):
                events.append(item)
            else:
                _fail(
                    issues,
                    "cloudevents",
                    path,
                    f"$[{index}]",
                    "type",
                    "CloudEvents array entries must be objects",
                )
        return events
    _fail(issues, "cloudevents", path, "$", "type", "CloudEvents artifact must be an object, array, or JSONL")
    return []


def _check_report_json(doc: Any, path: pathlib.Path, issues: list[Issue]) -> list[dict[str, Any]]:
    surface = "report-json"
    if not isinstance(doc, dict):
        _fail(issues, surface, path, "$", "type", "report JSON root must be an object")
        return []

    _expect_equal(issues, surface, path, "$.schema_version", doc.get("schema_version"), "1.0.0")
    _expect_equal(issues, surface, path, "$.schema_uri", doc.get("schema_uri"), REPORT_SCHEMA_URI)
    _scan_forbidden_default_keys(doc, surface, path, "$", issues)

    graph = _expect_object(issues, surface, path, "$.graph", doc.get("graph"))
    if graph is not None:
        source = _expect_object(issues, surface, path, "$.graph.source", graph.get("source"))
        if source is not None:
            _expect_present(issues, surface, path, "$.graph.source.file", source, "file")
        _check_dense_integer_ids(issues, surface, path, "$.graph.nodes", graph.get("nodes"))
        _check_dense_integer_ids(issues, surface, path, "$.graph.edges", graph.get("edges"))
        _expect_present(issues, surface, path, "$.graph.completeness", graph, "completeness")

    summary = _expect_object(issues, surface, path, "$.summary", doc.get("summary"))
    if summary is not None:
        _expect_present(issues, surface, path, "$.summary.completeness", summary, "completeness")

    findings = _expect_array(issues, surface, path, "$.findings", doc.get("findings"))
    identities: list[dict[str, Any]] = []
    if findings is None:
        return identities

    ordered_evidence_seen = False
    for index, finding in enumerate(findings):
        finding_path = f"$.findings[{index}]"
        if not isinstance(finding, dict):
            _fail(issues, surface, path, finding_path, "type", "finding must be an object")
            continue
        for field in FINDING_REQUIRED_FIELDS:
            _expect_present(issues, surface, path, f"{finding_path}.{field}", finding, field)
        _expect_regex(issues, surface, path, f"{finding_path}.fingerprint", finding.get("fingerprint"), FINGERPRINT_RE)
        _expect_regex(
            issues,
            surface,
            path,
            f"{finding_path}.suppression_key",
            finding.get("suppression_key"),
            SUPPRESSION_KEY_RE,
        )
        _expect_regex(
            issues,
            surface,
            path,
            f"{finding_path}.finding_group_id",
            finding.get("finding_group_id"),
            UUID_RE,
        )
        _check_suppression_metadata(issues, surface, path, finding_path, finding)
        ordered_evidence_seen = ordered_evidence_seen or "ordered_authority_evidence" in finding
        identities.append(
            {
                "rule_id": finding.get("rule_id"),
                "fingerprint": finding.get("fingerprint"),
                "suppression_key": finding.get("suppression_key"),
                "finding_group_id": finding.get("finding_group_id"),
            }
        )

    if findings and not ordered_evidence_seen:
        _pending(
            issues,
            surface,
            path,
            "$.findings[*].ordered_authority_evidence",
            "ordered-authority-evidence-pending",
            "L2-03/L4 ordered authority evidence is still a pending current-profile dependency",
        )
    return identities


def _check_cloudevent(
    doc: dict[str, Any],
    path: pathlib.Path,
    index: int,
    issues: list[Issue],
) -> dict[str, Any]:
    surface = "cloudevents"
    prefix = "$" if index == 0 else f"$[{index}]"
    _scan_forbidden_default_keys(doc, surface, path, prefix, issues)

    _expect_equal(issues, surface, path, f"{prefix}.specversion", doc.get("specversion"), "1.0")
    _expect_present(issues, surface, path, f"{prefix}.id", doc, "id")
    _expect_equal(issues, surface, path, f"{prefix}.source", doc.get("source"), "taudit")
    _expect_regex(issues, surface, path, f"{prefix}.type", doc.get("type"), re.compile(r"^io\.taudit\.finding\.[a-z_]+$"))
    _expect_present(issues, surface, path, f"{prefix}.subject", doc, "subject")
    _expect_equal(
        issues,
        surface,
        path,
        f"{prefix}.datacontenttype",
        doc.get("datacontenttype"),
        "application/json",
    )
    _expect_present(issues, surface, path, f"{prefix}.time", doc, "time")

    for field in [
        "correlationid",
        "tauditscanrunid",
        "provenanceversion",
    ]:
        _expect_present(issues, surface, path, f"{prefix}.{field}", doc, field)
    _expect_regex(
        issues,
        surface,
        path,
        f"{prefix}.tauditpipelineid",
        doc.get("tauditpipelineid"),
        PIPELINE_ID_RE,
    )
    _expect_equal(issues, surface, path, f"{prefix}.provenancerepo", doc.get("provenancerepo"), "taudit")
    _expect_equal(
        issues,
        surface,
        path,
        f"{prefix}.provenanceproducer",
        doc.get("provenanceproducer"),
        "taudit-sink-cloudevents",
    )
    _expect_equal(issues, surface, path, f"{prefix}.provenancekind", doc.get("provenancekind"), "finding")

    _expect_regex(issues, surface, path, f"{prefix}.tauditruleid", doc.get("tauditruleid"), RULE_ID_RE)
    _expect_regex(
        issues,
        surface,
        path,
        f"{prefix}.tauditfindingfingerprint",
        doc.get("tauditfindingfingerprint"),
        FINGERPRINT_RE,
    )
    _expect_regex(
        issues,
        surface,
        path,
        f"{prefix}.tauditsuppressionkey",
        doc.get("tauditsuppressionkey"),
        SUPPRESSION_KEY_RE,
    )
    _expect_regex(
        issues,
        surface,
        path,
        f"{prefix}.tauditfindinggroup",
        doc.get("tauditfindinggroup"),
        UUID_RE,
    )
    if "tauditplatform" in doc:
        _expect_in(
            issues,
            surface,
            path,
            f"{prefix}.tauditplatform",
            doc.get("tauditplatform"),
            {"ado", "bb", "bitbucket", "gha", "gitlab"},
        )
    _expect_in(
        issues,
        surface,
        path,
        f"{prefix}.tauditcompleteness",
        doc.get("tauditcompleteness"),
        {"complete", "partial", "unknown"},
    )
    if doc.get("tauditcompleteness") in {"partial", "unknown"}:
        _expect_present(
            issues,
            surface,
            path,
            f"{prefix}.tauditcompletenessgaps",
            doc,
            "tauditcompletenessgaps",
        )

    data = _expect_object(issues, surface, path, f"{prefix}.data", doc.get("data"))
    if data is not None:
        for field in ["severity", "category", "message", "recommendation"]:
            _expect_present(issues, surface, path, f"{prefix}.data.{field}", data, field)
        _check_suppression_metadata(issues, surface, path, f"{prefix}.data", data)

    return {
        "rule_id": doc.get("tauditruleid"),
        "fingerprint": doc.get("tauditfindingfingerprint"),
        "suppression_key": doc.get("tauditsuppressionkey"),
        "finding_group_id": doc.get("tauditfindinggroup"),
    }


def _check_sarif(doc: Any, path: pathlib.Path, issues: list[Issue]) -> list[dict[str, Any]]:
    surface = "sarif"
    if not isinstance(doc, dict):
        _fail(issues, surface, path, "$", "type", "SARIF root must be an object")
        return []

    _expect_equal(issues, surface, path, "$.version", doc.get("version"), "2.1.0")
    runs = _expect_array(issues, surface, path, "$.runs", doc.get("runs"))
    if not runs:
        return []

    identities: list[dict[str, Any]] = []
    for run_index, run in enumerate(runs):
        run_path = f"$.runs[{run_index}]"
        if not isinstance(run, dict):
            _fail(issues, surface, path, run_path, "type", "SARIF run must be an object")
            continue
        driver = (
            run.get("tool", {})
            .get("driver", {})
            if isinstance(run.get("tool"), dict) and isinstance(run.get("tool", {}).get("driver"), dict)
            else {}
        )
        rules = driver.get("rules")
        rule_ids = set()
        if isinstance(rules, list):
            rule_ids = {rule.get("id") for rule in rules if isinstance(rule, dict)}
        else:
            _fail(
                issues,
                surface,
                path,
                f"{run_path}.tool.driver.rules",
                "missing",
                "SARIF driver rules must be present",
            )
        results = _expect_array(issues, surface, path, f"{run_path}.results", run.get("results"))
        if results is None:
            continue
        for result_index, result in enumerate(results):
            result_path = f"{run_path}.results[{result_index}]"
            if not isinstance(result, dict):
                _fail(issues, surface, path, result_path, "type", "SARIF result must be an object")
                continue
            rule_id = result.get("ruleId")
            _expect_present(issues, surface, path, f"{result_path}.ruleId", result, "ruleId")
            if rule_id not in rule_ids:
                _fail(
                    issues,
                    surface,
                    path,
                    f"{run_path}.tool.driver.rules",
                    "missing-rule",
                    f"driver rules must include result.ruleId {rule_id!r}",
                )
            partials = _expect_object(
                issues,
                surface,
                path,
                f"{result_path}.partialFingerprints",
                result.get("partialFingerprints"),
            )
            primary = taudit = None
            if partials is not None:
                primary = partials.get("primaryLocationLineHash")
                taudit = partials.get("taudit/v1")
                _expect_regex(
                    issues,
                    surface,
                    path,
                    f"{result_path}.partialFingerprints.primaryLocationLineHash",
                    primary,
                    FINGERPRINT_RE,
                )
                _expect_regex(
                    issues,
                    surface,
                    path,
                    f"{result_path}.partialFingerprints['taudit/v1']",
                    taudit,
                    FINGERPRINT_RE,
                )
                if primary is not None and taudit is not None and primary != taudit:
                    _fail(
                        issues,
                        surface,
                        path,
                        f"{result_path}.partialFingerprints['taudit/v1']",
                        "mismatch",
                        "SARIF taudit/v1 fingerprint must equal primaryLocationLineHash",
                    )
            properties = _expect_object(
                issues,
                surface,
                path,
                f"{result_path}.properties",
                result.get("properties"),
            )
            suppression_key = finding_group_id = None
            if properties is not None:
                suppression_key = properties.get("suppressionKey")
                finding_group_id = properties.get("findingGroupId")
                _expect_regex(
                    issues,
                    surface,
                    path,
                    f"{result_path}.properties.suppressionKey",
                    suppression_key,
                    SUPPRESSION_KEY_RE,
                )
                _expect_regex(
                    issues,
                    surface,
                    path,
                    f"{result_path}.properties.findingGroupId",
                    finding_group_id,
                    UUID_RE,
                )
                if properties.get("suppressed") is True or any(
                    key in properties for key in ["originalSeverity", "suppressionReason"]
                ):
                    _expect_present(
                        issues,
                        surface,
                        path,
                        f"{result_path}.properties.originalSeverity",
                        properties,
                        "originalSeverity",
                    )
                    _expect_present(
                        issues,
                        surface,
                        path,
                        f"{result_path}.properties.suppressionReason",
                        properties,
                        "suppressionReason",
                    )
            identities.append(
                {
                    "rule_id": rule_id,
                    "fingerprint": primary,
                    "suppression_key": suppression_key,
                    "finding_group_id": finding_group_id,
                }
            )
    return identities


def _check_exploit_graph(
    doc: Any,
    path: pathlib.Path,
    issues: list[Issue],
    allow_observed_evidence: bool,
) -> None:
    surface = "exploit-graph"
    if not isinstance(doc, dict):
        _fail(issues, surface, path, "$", "type", "exploit graph root must be an object")
        return
    _expect_equal(issues, surface, path, "$.schema_version", doc.get("schema_version"), "1.0.0")
    _expect_equal(issues, surface, path, "$.schema_uri", doc.get("schema_uri"), EXPLOIT_GRAPH_SCHEMA_URI)
    _expect_equal(issues, surface, path, "$.view", doc.get("view"), "exploit")
    source = _expect_object(issues, surface, path, "$.source", doc.get("source"))
    if source is not None:
        _expect_present(issues, surface, path, "$.source.file", source, "file")
    summary = _expect_object(issues, surface, path, "$.summary", doc.get("summary"))
    paths = _expect_array(issues, surface, path, "$.paths", doc.get("paths"))
    if summary is not None:
        for field in ["path_count", "observed_path_count", "authority_path_count"]:
            _expect_present(issues, surface, path, f"$.summary.{field}", summary, field)
    if paths is None:
        return
    if summary is not None and isinstance(summary.get("path_count"), int) and summary["path_count"] != len(paths):
        _fail(
            issues,
            surface,
            path,
            "$.summary.path_count",
            "mismatch",
            "summary.path_count must equal len(paths)",
        )
    observed_paths = 0
    for path_index, exploit_path in enumerate(paths):
        path_prefix = f"$.paths[{path_index}]"
        if not isinstance(exploit_path, dict):
            _fail(issues, surface, path, path_prefix, "type", "exploit path must be an object")
            continue
        for field in [
            "rule_id",
            "umbrella_rule_id",
            "rule_scope",
            "mutable_channel",
            "helper",
            "helper_resolution",
            "authority_transport",
            "authority_origin",
            "nodes",
            "edges",
        ]:
            _expect_present(issues, surface, path, f"{path_prefix}.{field}", exploit_path, field)
        nodes = _expect_array(issues, surface, path, f"{path_prefix}.nodes", exploit_path.get("nodes"))
        if nodes is not None:
            for node_index, node in enumerate(nodes):
                if not isinstance(node, dict):
                    _fail(issues, surface, path, f"{path_prefix}.nodes[{node_index}]", "type", "node must be an object")
                    continue
                for field in ["id", "kind", "label"]:
                    _expect_present(
                        issues,
                        surface,
                        path,
                        f"{path_prefix}.nodes[{node_index}].{field}",
                        node,
                        field,
                    )
        edges = _expect_array(issues, surface, path, f"{path_prefix}.edges", exploit_path.get("edges"))
        path_observed = False
        if edges is not None:
            for edge_index, edge in enumerate(edges):
                edge_path = f"{path_prefix}.edges[{edge_index}]"
                if not isinstance(edge, dict):
                    _fail(issues, surface, path, edge_path, "type", "edge must be an object")
                    continue
                for field in ["from", "to", "kind", "confidence", "authority_bearing"]:
                    _expect_present(issues, surface, path, f"{edge_path}.{field}", edge, field)
                if edge.get("observed") is True:
                    path_observed = True
                    if not allow_observed_evidence:
                        _fail(
                            issues,
                            surface,
                            path,
                            f"{edge_path}.observed",
                            "observed-evidence-not-declared",
                            "observed=true requires --allow-observed-evidence",
                        )
                if edge.get("confidence") == "observed":
                    path_observed = True
                    if not allow_observed_evidence:
                        _fail(
                            issues,
                            surface,
                            path,
                            f"{edge_path}.confidence",
                            "observed-evidence-not-declared",
                            "confidence=observed requires --allow-observed-evidence",
                        )
        if path_observed:
            observed_paths += 1
    if summary is not None and isinstance(summary.get("observed_path_count"), int):
        if summary["observed_path_count"] != observed_paths:
            _fail(
                issues,
                surface,
                path,
                "$.summary.observed_path_count",
                "mismatch",
                "summary.observed_path_count must equal paths containing observed evidence",
            )


def _check_baseline(doc: Any, path: pathlib.Path, issues: list[Issue]) -> None:
    surface = "baseline"
    if not isinstance(doc, dict):
        _fail(issues, surface, path, "$", "type", "baseline root must be an object")
        return
    for field in [
        "schema_version",
        "pipeline_path",
        "pipeline_content_hash",
        "captured_at",
        "captured_by",
        "captured_with",
        "baseline_findings",
    ]:
        _expect_present(issues, surface, path, f"$.{field}", doc, field)
    _expect_regex(issues, surface, path, "$.schema_version", doc.get("schema_version"), SEMVER_1_RE)
    _expect_regex(issues, surface, path, "$.pipeline_content_hash", doc.get("pipeline_content_hash"), SHA256_RE)
    if "pipeline_identity_material_hash" in doc:
        _expect_regex(
            issues,
            surface,
            path,
            "$.pipeline_identity_material_hash",
            doc.get("pipeline_identity_material_hash"),
            SHA256_RE,
        )
    findings = _expect_array(issues, surface, path, "$.baseline_findings", doc.get("baseline_findings"))
    if findings is None:
        return
    for index, finding in enumerate(findings):
        finding_path = f"$.baseline_findings[{index}]"
        if not isinstance(finding, dict):
            _fail(issues, surface, path, finding_path, "type", "baseline finding must be an object")
            continue
        for field in ["fingerprint", "rule_id", "severity", "first_seen_at"]:
            _expect_present(issues, surface, path, f"{finding_path}.{field}", finding, field)
        _expect_regex(issues, surface, path, f"{finding_path}.fingerprint", finding.get("fingerprint"), FINGERPRINT_RE)
        _expect_in(
            issues,
            surface,
            path,
            f"{finding_path}.severity",
            finding.get("severity"),
            {"critical", "high", "medium", "low", "info"},
        )
        if finding.get("severity_override") == "critical":
            _expect_present(issues, surface, path, f"{finding_path}.expires_at", finding, "expires_at")
            reason = finding.get("reason_waived")
            if not isinstance(reason, str) or len(reason.strip()) < 10:
                _fail(
                    issues,
                    surface,
                    path,
                    f"{finding_path}.reason_waived",
                    "invalid",
                    "critical baseline waiver requires a reason_waived of at least 10 characters",
                )


def _check_cross_surface_identity(
    identity_surfaces: list[tuple[str, list[dict[str, Any]]]],
    issues: list[Issue],
) -> None:
    base_name, base_identities = identity_surfaces[0]
    fields = ["rule_id", "fingerprint", "suppression_key", "finding_group_id"]
    for surface_name, identities in identity_surfaces[1:]:
        if len(identities) != len(base_identities):
            _fail(
                issues,
                "cross-surface",
                pathlib.Path("<provided-artifacts>"),
                "$.cross_surface.findings",
                "count-mismatch",
                f"{base_name} emitted {len(base_identities)} identities but {surface_name} emitted {len(identities)}",
            )
            continue
        for index, base_identity in enumerate(base_identities):
            other_identity = identities[index]
            for field in fields:
                base_value = base_identity.get(field)
                other_value = other_identity.get(field)
                if base_value is None or other_value is None:
                    continue
                if base_value != other_value:
                    _fail(
                        issues,
                        "cross-surface",
                        pathlib.Path("<provided-artifacts>"),
                        f"$.cross_surface.findings[{index}].{field}",
                        "mismatch",
                        f"{base_name}.{field}={base_value!r} differs from {surface_name}.{field}={other_value!r}",
                    )


def _artifact_receipt(surface: str, path: pathlib.Path, issues: list[Issue]) -> ArtifactReceipt:
    fail = sum(1 for issue in issues if issue.status == "fail")
    pending = sum(1 for issue in issues if issue.status == "pending")
    status = "fail" if fail else ("incomplete" if pending else "pass")
    return ArtifactReceipt(surface=surface, path=str(path), status=status, fail=fail, pending=pending)


def _expect_object(
    issues: list[Issue],
    surface: str,
    artifact: pathlib.Path,
    json_path: str,
    value: Any,
) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    _fail(issues, surface, artifact, json_path, "type", "expected object")
    return None


def _expect_array(
    issues: list[Issue],
    surface: str,
    artifact: pathlib.Path,
    json_path: str,
    value: Any,
) -> list[Any] | None:
    if isinstance(value, list):
        return value
    _fail(issues, surface, artifact, json_path, "type", "expected array")
    return None


def _expect_present(
    issues: list[Issue],
    surface: str,
    artifact: pathlib.Path,
    json_path: str,
    parent: dict[str, Any],
    key: str,
) -> None:
    if key not in parent or parent[key] is None or parent[key] == "":
        _fail(issues, surface, artifact, json_path, "missing", f"{key} is required by the current profile")


def _expect_equal(
    issues: list[Issue],
    surface: str,
    artifact: pathlib.Path,
    json_path: str,
    actual: Any,
    expected: Any,
) -> None:
    if actual != expected:
        _fail(issues, surface, artifact, json_path, "mismatch", f"expected {expected!r}, got {actual!r}")


def _expect_in(
    issues: list[Issue],
    surface: str,
    artifact: pathlib.Path,
    json_path: str,
    actual: Any,
    allowed: set[str],
) -> None:
    if actual not in allowed:
        _fail(issues, surface, artifact, json_path, "invalid", f"expected one of {sorted(allowed)!r}, got {actual!r}")


def _expect_regex(
    issues: list[Issue],
    surface: str,
    artifact: pathlib.Path,
    json_path: str,
    actual: Any,
    pattern: re.Pattern[str],
) -> None:
    if not isinstance(actual, str) or pattern.fullmatch(actual) is None:
        _fail(issues, surface, artifact, json_path, "invalid", f"value must match {pattern.pattern}")


def _check_dense_integer_ids(
    issues: list[Issue],
    surface: str,
    artifact: pathlib.Path,
    json_path: str,
    value: Any,
) -> None:
    items = _expect_array(issues, surface, artifact, json_path, value)
    if items is None:
        return
    ids = [item.get("id") if isinstance(item, dict) else None for item in items]
    expected = list(range(len(items)))
    if ids != expected:
        _fail(issues, surface, artifact, json_path, "dense-id-mismatch", f"expected dense ids {expected!r}, got {ids!r}")


def _check_suppression_metadata(
    issues: list[Issue],
    surface: str,
    artifact: pathlib.Path,
    json_path: str,
    value: dict[str, Any],
) -> None:
    if value.get("suppressed") is True or any(key in value for key in ["original_severity", "suppression_reason"]):
        _expect_present(issues, surface, artifact, f"{json_path}.original_severity", value, "original_severity")
        _expect_present(issues, surface, artifact, f"{json_path}.suppression_reason", value, "suppression_reason")


def _scan_forbidden_default_keys(
    value: Any,
    surface: str,
    artifact: pathlib.Path,
    json_path: str,
    issues: list[Issue],
) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{json_path}.{key}" if json_path != "$" else f"$.{key}"
            if key in FORBIDDEN_DEFAULT_KEYS:
                _fail(
                    issues,
                    surface,
                    artifact,
                    child_path,
                    "forbidden-default-field",
                    f"{key} exceeds the ADR 0013 default-output ceiling",
                )
            _scan_forbidden_default_keys(child, surface, artifact, child_path, issues)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_forbidden_default_keys(child, surface, artifact, f"{json_path}[{index}]", issues)


def _fail(
    issues: list[Issue],
    surface: str,
    artifact: pathlib.Path,
    path: str,
    code: str,
    message: str,
) -> None:
    issues.append(Issue("fail", surface, str(artifact), path, code, message))


def _pending(
    issues: list[Issue],
    surface: str,
    artifact: pathlib.Path,
    path: str,
    code: str,
    message: str,
) -> None:
    issues.append(Issue("pending", surface, str(artifact), path, code, message))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate taudit v1.2.0-rc.1 current-output profile fields against offline JSON artifacts.",
    )
    parser.add_argument("--report-json", action="append", type=pathlib.Path, default=[])
    parser.add_argument("--cloudevent-json", action="append", type=pathlib.Path, default=[])
    parser.add_argument("--sarif-json", "--sarif", action="append", type=pathlib.Path, default=[])
    parser.add_argument("--exploit-graph-json", action="append", type=pathlib.Path, default=[])
    parser.add_argument("--baseline-json", action="append", type=pathlib.Path, default=[])
    parser.add_argument(
        "--allow-observed-evidence",
        action="store_true",
        help="Allow exploit graph observed=true or confidence=observed fields when an observed evidence fixture is explicit.",
    )
    parser.add_argument("--format", choices=["json", "text"], default="json")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not any(
        [
            args.report_json,
            args.cloudevent_json,
            args.sarif_json,
            args.exploit_graph_json,
            args.baseline_json,
        ]
    ):
        parser.error("at least one artifact path must be supplied")

    receipt = check_current_profile(
        report_json=args.report_json,
        cloudevent_json=args.cloudevent_json,
        sarif_json=args.sarif_json,
        exploit_graph_json=args.exploit_graph_json,
        baseline_json=args.baseline_json,
        allow_observed_evidence=args.allow_observed_evidence,
    )
    if args.format == "json":
        print(json.dumps(receipt, indent=2, sort_keys=True))
    else:
        print(_format_text(receipt))
    if receipt["status"] == "fail":
        return 1
    if receipt["status"] == "incomplete":
        return 3
    return 0


def _format_text(receipt: dict[str, Any]) -> str:
    lines = [
        f"current-output-profile: {receipt['status']}",
        f"artifacts={receipt['counts']['artifacts']} fail={receipt['counts']['fail']} pending={receipt['counts']['pending']}",
    ]
    for issue in receipt["issues"]:
        lines.append(
            f"{issue['status']}: {issue['surface']} {issue['artifact']} {issue['path']} {issue['code']}: {issue['message']}"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
