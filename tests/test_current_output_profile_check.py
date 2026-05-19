from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "current_output_profile_check.py"
SPEC = importlib.util.spec_from_file_location("current_output_profile_check", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
current_output_profile_check = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = current_output_profile_check
SPEC.loader.exec_module(current_output_profile_check)


def write_json(tmp_path: pathlib.Path, name: str, value: object) -> pathlib.Path:
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def current_report(fingerprint: str = "0123456789abcdef0123456789abcdef") -> dict:
    return {
        "schema_version": "1.0.0",
        "schema_uri": "https://taudit.dev/schemas/taudit-report.schema.json",
        "graph": {
            "source": {"file": "tests/fixtures/current.yml"},
            "nodes": [
                {
                    "id": 0,
                    "kind": "identity",
                    "name": "GITHUB_TOKEN",
                    "trust_zone": "first_party",
                    "metadata": {},
                }
            ],
            "edges": [{"id": 0, "from": 0, "to": 0, "kind": "has_access_to"}],
            "completeness": "complete",
        },
        "findings": [
            {
                "severity": "critical",
                "category": "authority_propagation",
                "nodes_involved": [0],
                "message": "authority reached an untrusted sink",
                "recommendation": {"type": "manual", "action": "scope the authority"},
                "rule_id": "authority_propagation",
                "source": "built-in",
                "fingerprint": fingerprint,
                "suppression_key": "sk1_0123456789abcdef0123456789abcdef",
                "finding_group_id": "123e4567-e89b-12d3-a456-426614174000",
            }
        ],
        "summary": {
            "total_findings": 1,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total_nodes": 1,
            "total_edges": 1,
            "completeness": "complete",
        },
    }


def current_cloudevent(fingerprint: str = "0123456789abcdef0123456789abcdef") -> dict:
    return {
        "specversion": "1.0",
        "id": "00000000-0000-4000-8000-000000000001",
        "source": "taudit",
        "type": "io.taudit.finding.authority_propagation",
        "subject": "tests/fixtures/current.yml",
        "datacontenttype": "application/json",
        "time": "2026-05-18T00:00:00Z",
        "correlationid": "current-profile-test",
        "tauditpipelineid": "urn:taudit:pipeline:sha256:" + ("a" * 64),
        "tauditscanrunid": "scan-run-1",
        "provenancerepo": "taudit",
        "provenanceproducer": "taudit-sink-cloudevents",
        "provenanceversion": "3.0.1",
        "provenancekind": "finding",
        "tauditruleid": "authority_propagation",
        "tauditfindingfingerprint": fingerprint,
        "tauditsuppressionkey": "sk1_0123456789abcdef0123456789abcdef",
        "tauditfindinggroup": "123e4567-e89b-12d3-a456-426614174000",
        "tauditcompleteness": "complete",
        "data": {
            "severity": "critical",
            "category": "authority_propagation",
            "nodes_involved": [0],
            "message": "authority reached an untrusted sink",
            "recommendation": {"type": "manual", "action": "scope the authority"},
        },
    }


def current_sarif(fingerprint: str = "0123456789abcdef0123456789abcdef") -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "taudit",
                        "rules": [{"id": "authority_propagation"}],
                    }
                },
                "results": [
                    {
                        "ruleId": "authority_propagation",
                        "message": {"text": "authority reached an untrusted sink"},
                        "partialFingerprints": {
                            "primaryLocationLineHash": fingerprint,
                            "taudit/v1": fingerprint,
                        },
                        "properties": {
                            "suppressionKey": "sk1_0123456789abcdef0123456789abcdef",
                            "findingGroupId": "123e4567-e89b-12d3-a456-426614174000",
                        },
                    }
                ],
            }
        ],
    }


def current_exploit_graph(observed: bool = False) -> dict:
    edge = {
        "from": "step:build",
        "to": "helper:git",
        "kind": "invokes_helper",
        "confidence": "static",
        "authority_bearing": True,
    }
    if observed:
        edge["observed"] = True
        edge["confidence"] = "observed"
    return {
        "schema_version": "1.0.0",
        "schema_uri": "https://taudit.dev/schemas/exploit-graph.v1.json",
        "view": "exploit",
        "source": {"file": ".github/workflows/release.yml"},
        "paths": [
            {
                "rule_id": "EXPLOIT_PATH_HELPER_AUTHORITY",
                "umbrella_rule_id": "EXPLOIT_PATH_HELPER_AUTHORITY",
                "rule_scope": "exploit_path",
                "mutable_channel": "GITHUB_PATH",
                "helper": "git",
                "helper_resolution": "bare_command",
                "authority_transport": ["env"],
                "authority_origin": "github_token",
                "nodes": [
                    {"id": "step:build", "kind": "Step", "label": "build"},
                    {"id": "helper:git", "kind": "ResolvedHelper", "label": "git"},
                ],
                "edges": [edge],
            }
        ],
        "summary": {
            "path_count": 1,
            "observed_path_count": 1 if observed else 0,
            "authority_path_count": 1,
        },
    }


def current_baseline() -> dict:
    return {
        "schema_version": "1.1.0",
        "pipeline_path": ".github/workflows/current.yml",
        "pipeline_content_hash": "sha256:" + ("b" * 64),
        "pipeline_identity_material_hash": "sha256:" + ("c" * 64),
        "captured_at": "2026-05-18T00:00:00Z",
        "captured_by": "current-profile@example.test",
        "captured_with": {"taudit_version": "1.2.0-rc.1", "rules_version": "test"},
        "baseline_findings": [
            {
                "fingerprint": "0123456789abcdef0123456789abcdef",
                "rule_id": "authority_propagation",
                "severity": "critical",
                "first_seen_at": "2026-05-18T00:00:00Z",
            }
        ],
    }


def issue_paths(receipt: dict) -> set[str]:
    return {issue["path"] for issue in receipt["issues"]}


def test_report_json_requires_current_identity_fields_and_schema_uri(tmp_path: pathlib.Path) -> None:
    report = current_report()
    del report["schema_uri"]
    del report["findings"][0]["fingerprint"]
    report["findings"][0]["suppression_key"] = "legacy"
    report_path = write_json(tmp_path, "report.json", report)

    receipt = current_output_profile_check.check_current_profile(
        report_json=[report_path],
    )

    assert receipt["status"] == "fail"
    assert "$.schema_uri" in issue_paths(receipt)
    assert "$.findings[0].fingerprint" in issue_paths(receipt)
    assert "$.findings[0].suppression_key" in issue_paths(receipt)


def test_report_json_tracks_ordered_evidence_gap_as_pending(tmp_path: pathlib.Path) -> None:
    report_path = write_json(tmp_path, "report.json", current_report())

    receipt = current_output_profile_check.check_current_profile(
        report_json=[report_path],
    )

    assert receipt["status"] == "incomplete"
    assert receipt["counts"]["fail"] == 0
    assert any(
        issue["status"] == "pending"
        and issue["path"] == "$.findings[*].ordered_authority_evidence"
        for issue in receipt["issues"]
    )


def test_multiple_report_json_artifacts_do_not_cross_compare_each_other(
    tmp_path: pathlib.Path,
) -> None:
    first_path = write_json(
        tmp_path,
        "first.json",
        current_report("00000000000000000000000000000000"),
    )
    second_path = write_json(
        tmp_path,
        "second.json",
        current_report("11111111111111111111111111111111"),
    )

    receipt = current_output_profile_check.check_current_profile(
        report_json=[first_path, second_path],
    )

    assert receipt["status"] == "incomplete"
    assert receipt["counts"]["fail"] == 0
    assert not any(issue["surface"] == "cross-surface" for issue in receipt["issues"])


def test_checked_in_cloudevent_example_satisfies_current_profile() -> None:
    receipt = current_output_profile_check.check_current_profile(
        cloudevent_json=[ROOT / "contracts" / "examples" / "over-privileged-finding.cloudevent.json"],
    )

    assert receipt["status"] == "pass"
    assert receipt["counts"]["fail"] == 0


def test_cross_surface_identity_mismatch_fails(tmp_path: pathlib.Path) -> None:
    report_path = write_json(tmp_path, "report.json", current_report())
    event_path = write_json(
        tmp_path,
        "event.json",
        current_cloudevent("ffffffffffffffffffffffffffffffff"),
    )
    sarif_path = write_json(tmp_path, "result.sarif", current_sarif())

    receipt = current_output_profile_check.check_current_profile(
        report_json=[report_path],
        cloudevent_json=[event_path],
        sarif_json=[sarif_path],
    )

    assert receipt["status"] == "fail"
    assert "$.cross_surface.findings[0].fingerprint" in issue_paths(receipt)


def test_sarif_requires_driver_rule_entry_and_identity_properties(tmp_path: pathlib.Path) -> None:
    sarif = current_sarif()
    sarif["runs"][0]["tool"]["driver"]["rules"] = []
    del sarif["runs"][0]["results"][0]["partialFingerprints"]["taudit/v1"]
    del sarif["runs"][0]["results"][0]["properties"]["suppressionKey"]
    sarif_path = write_json(tmp_path, "result.sarif", sarif)

    receipt = current_output_profile_check.check_current_profile(sarif_json=[sarif_path])

    assert receipt["status"] == "fail"
    assert "$.runs[0].tool.driver.rules" in issue_paths(receipt)
    assert "$.runs[0].results[0].partialFingerprints['taudit/v1']" in issue_paths(receipt)
    assert "$.runs[0].results[0].properties.suppressionKey" in issue_paths(receipt)


def test_exploit_graph_observed_edges_require_observed_evidence_flag(tmp_path: pathlib.Path) -> None:
    graph_path = write_json(tmp_path, "exploit.json", current_exploit_graph(observed=True))

    receipt = current_output_profile_check.check_current_profile(
        exploit_graph_json=[graph_path],
    )
    allowed = current_output_profile_check.check_current_profile(
        exploit_graph_json=[graph_path],
        allow_observed_evidence=True,
    )

    assert receipt["status"] == "fail"
    assert "$.paths[0].edges[0].observed" in issue_paths(receipt)
    assert allowed["status"] == "pass"


def test_baseline_hashes_and_finding_identity_are_checked(tmp_path: pathlib.Path) -> None:
    baseline = current_baseline()
    baseline["pipeline_content_hash"] = "sha256:nothex"
    baseline["baseline_findings"][0]["fingerprint"] = "short"
    baseline_path = write_json(tmp_path, "baseline.json", baseline)

    receipt = current_output_profile_check.check_current_profile(
        baseline_json=[baseline_path],
    )

    assert receipt["status"] == "fail"
    assert "$.pipeline_content_hash" in issue_paths(receipt)
    assert "$.baseline_findings[0].fingerprint" in issue_paths(receipt)


def test_cli_emits_json_receipt_and_exit_codes(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad_report = current_report()
    del bad_report["schema_uri"]
    report_path = write_json(tmp_path, "report.json", bad_report)

    fail_rc = current_output_profile_check.main(
        ["--report-json", str(report_path), "--format", "json"]
    )
    fail_receipt = json.loads(capsys.readouterr().out)

    event_path = write_json(tmp_path, "event.json", current_cloudevent())
    pass_rc = current_output_profile_check.main(
        ["--cloudevent-json", str(event_path), "--format", "json"]
    )
    pass_receipt = json.loads(capsys.readouterr().out)

    assert fail_rc == 1
    assert fail_receipt["status"] == "fail"
    assert pass_rc == 0
    assert pass_receipt["status"] == "pass"
