from __future__ import annotations

import importlib.util
import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "examples" / "consumers" / "python" / "report_identity_summary.py"
SPEC = importlib.util.spec_from_file_location("report_identity_summary", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
consumer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = consumer
SPEC.loader.exec_module(consumer)


def test_report_example_summarizes_completeness_and_finding_identity() -> None:
    summary = consumer.summarize_path(
        ROOT / "contracts" / "examples" / "over-privileged-report.json"
    )

    assert summary == [
        {
            "kind": "report",
            "schema_version": "1.0.0",
            "schema_uri": None,
            "source_file": "tests/fixtures/over-privileged.yml",
            "graph_completeness": "complete",
            "graph_completeness_gap_kinds": [],
            "summary_completeness": "complete",
            "summary_completeness_gap_kinds": [],
            "total_findings": 11,
            "finding_identities": [
                {
                    "index": 0,
                    "severity": "critical",
                    "category": "authority_propagation",
                    "rule_id": None,
                    "fingerprint": None,
                    "suppression_key": None,
                    "finding_group_id": None,
                    "source": None,
                }
            ],
        }
    ]


def test_cloudevent_example_summarizes_completeness_and_identity_extensions() -> None:
    summary = consumer.summarize_path(
        ROOT / "contracts" / "examples" / "over-privileged-finding.cloudevent.json"
    )

    assert summary == [
        {
            "kind": "cloudevent",
            "specversion": "1.0",
            "event_id": "00000000-0000-4000-8000-000000000001",
            "event_type": "io.taudit.finding.authority_propagation",
            "subject": "tests/fixtures/over-privileged.yml",
            "completeness": "complete",
            "completeness_gap_kinds": [],
            "severity": "critical",
            "category": "authority_propagation",
            "identity": {
                "rule_id": "authority_propagation",
                "fingerprint": None,
                "suppression_key": None,
                "finding_group_id": None,
                "pipeline_id": "urn:taudit:pipeline:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "scan_run_id": "demo-scan-run-2026-04-19-001",
                "correlation_id": "demo-flow-2026-04-19-001",
                "platform": None,
            },
            "provenance": {
                "repo": "taudit",
                "producer": "taudit-sink-cloudevents",
                "version": "0.1.1",
                "kind": "finding",
            },
        }
    ]


def test_unknown_report_metadata_and_extra_fields_are_ignored(tmp_path: pathlib.Path) -> None:
    report_path = ROOT / "contracts" / "examples" / "clean-report.json"
    doc = json.loads(report_path.read_text(encoding="utf-8"))
    doc["future_root_extension"] = {"ignored": True}
    doc["graph"]["metadata"] = {
        "platform": "gha",
        "future_metadata_key": "opaque to this consumer",
    }
    doc["graph"]["nodes"][0]["metadata"]["future_node_metadata"] = "ignored"
    doc["findings"][0]["future_finding_field"] = "ignored"
    doc["summary"]["future_summary_field"] = 123
    mutated_path = tmp_path / "future-report.json"
    mutated_path.write_text(json.dumps(doc), encoding="utf-8")

    summary = consumer.summarize_path(mutated_path)

    assert summary[0]["kind"] == "report"
    assert summary[0]["source_file"] == "tests/fixtures/clean.yml"
    assert summary[0]["graph_completeness"] == "complete"
    assert summary[0]["summary_completeness"] == "complete"
    assert summary[0]["total_findings"] == 1
    assert summary[0]["finding_identities"][0]["category"] == "authority_propagation"


def test_unknown_cloudevent_extensions_and_data_fields_are_ignored(
    tmp_path: pathlib.Path,
) -> None:
    event_path = ROOT / "contracts" / "examples" / "over-privileged-finding.cloudevent.json"
    doc = json.loads(event_path.read_text(encoding="utf-8"))
    doc["futureextension"] = {"ignored": True}
    doc["tauditfindingfingerprint"] = "0123456789abcdef0123456789abcdef"
    doc["tauditsuppressionkey"] = "sk1_0123456789abcdef0123456789abcdef"
    doc["tauditfindinggroup"] = "00000000-0000-5000-8000-000000000001"
    doc["tauditplatform"] = "gha"
    doc["data"]["future_finding_field"] = "ignored"
    mutated_path = tmp_path / "future-event.jsonl"
    mutated_path.write_text(json.dumps(doc) + "\n", encoding="utf-8")

    summary = consumer.summarize_path(mutated_path)

    assert summary[0]["kind"] == "cloudevent"
    assert summary[0]["identity"]["fingerprint"] == "0123456789abcdef0123456789abcdef"
    assert summary[0]["identity"]["suppression_key"] == "sk1_0123456789abcdef0123456789abcdef"
    assert summary[0]["identity"]["finding_group_id"] == "00000000-0000-5000-8000-000000000001"
    assert summary[0]["identity"]["platform"] == "gha"


def test_reference_consumer_reports_completeness_gap_kinds(tmp_path: pathlib.Path) -> None:
    report_path = ROOT / "contracts" / "examples" / "clean-report.json"
    doc = json.loads(report_path.read_text(encoding="utf-8"))
    doc["graph"]["completeness"] = "partial"
    doc["graph"]["completeness_gap_kinds"] = ["structural"]
    doc["summary"]["completeness"] = "partial"
    doc["summary"]["completeness_gaps"] = [{"kind": "expression", "reason": "matrix"}]
    mutated_path = tmp_path / "partial-report.json"
    mutated_path.write_text(json.dumps(doc), encoding="utf-8")

    summary = consumer.summarize_path(mutated_path)

    assert summary[0]["graph_completeness"] == "partial"
    assert summary[0]["graph_completeness_gap_kinds"] == ["structural"]
    assert summary[0]["summary_completeness"] == "partial"
    assert summary[0]["summary_completeness_gap_kinds"] == ["expression"]
