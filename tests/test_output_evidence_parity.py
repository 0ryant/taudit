from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "output_evidence_parity.py"
SPEC = importlib.util.spec_from_file_location("output_evidence_parity", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
output_evidence_parity = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = output_evidence_parity
SPEC.loader.exec_module(output_evidence_parity)


def write_json(path: pathlib.Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_payload_set(
    root: pathlib.Path,
    *,
    include_extras: bool = True,
    include_ordered_evidence: bool = False,
    omit_cloud_event_extra: str | None = None,
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    identity = {
        "rule_id": "authority_propagation",
        "fingerprint": "0123456789abcdef0123456789abcdef",
        "suppression_key": "sk1_0123456789abcdef0123456789abcdef",
        "finding_group_id": "123e4567-e89b-12d3-a456-426614174000",
    }
    public_extras = {
        "confidence_scope": "yaml_only",
        "runtime_preconditions": ["repo permits workflow write token"],
        "portal_control_dependency": True,
        "authority_kinds": ["job_token"],
        "attacker_surface_kinds": ["mutable_dependency_ref"],
        "template_resolution_strength": "partial",
        "time_to_fix": "small",
        "compensating_controls": ["permissions narrowed"],
    }
    ordered = {
        "schema": "taudit.ordered_authority_evidence.v1",
        "events": [],
        "predicate": {
            "confidence": "high",
            "same_job_caveat": True,
        },
    }

    json_finding = {
        **identity,
        "severity": "critical",
        "category": "authority_propagation",
        "message": "finding",
        "nodes_involved": [0, 1],
    }
    sarif_properties = {
        "suppressionKey": identity["suppression_key"],
        "findingGroupId": identity["finding_group_id"],
    }
    cloudevent_data = {
        "severity": "critical",
        "category": "authority_propagation",
        "message": "finding",
        "nodes_involved": [0, 1],
    }

    if include_extras:
        json_finding.update(public_extras)
        sarif_properties.update(
            {
                "confidenceScope": public_extras["confidence_scope"],
                "runtimePreconditions": public_extras["runtime_preconditions"],
                "portalControlDependency": public_extras["portal_control_dependency"],
                "authorityKinds": public_extras["authority_kinds"],
                "attackerSurfaceKinds": public_extras["attacker_surface_kinds"],
                "templateResolutionStrength": public_extras[
                    "template_resolution_strength"
                ],
                "timeToFix": public_extras["time_to_fix"],
                "compensatingControls": public_extras["compensating_controls"],
            }
        )
        cloudevent_data.update(public_extras)

    if include_ordered_evidence:
        json_finding["ordered_authority_evidence"] = ordered
        sarif_properties["ordered_authority_evidence"] = ordered
        cloudevent_data["ordered_authority_evidence"] = ordered

    if omit_cloud_event_extra is not None:
        cloudevent_data.pop(omit_cloud_event_extra, None)

    json_path = root / "report.json"
    sarif_path = root / "report.sarif"
    cloud_path = root / "events.jsonl"

    write_json(
        json_path,
        {
            "schema_version": "1.0.0",
            "findings": [json_finding],
        },
    )
    write_json(
        sarif_path,
        {
            "version": "2.1.0",
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": identity["rule_id"],
                            "partialFingerprints": {
                                "primaryLocationLineHash": identity["fingerprint"],
                                "taudit/v1": identity["fingerprint"],
                            },
                            "properties": sarif_properties,
                        }
                    ]
                }
            ],
        },
    )
    cloud_path.write_text(
        json.dumps(
            {
                "specversion": "1.0",
                "type": "io.taudit.finding.authority_propagation",
                "tauditruleid": identity["rule_id"],
                "tauditfindingfingerprint": identity["fingerprint"],
                "tauditsuppressionkey": identity["suppression_key"],
                "tauditfindinggroup": identity["finding_group_id"],
                "data": cloudevent_data,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return json_path, sarif_path, cloud_path


class OutputEvidenceParityTests(unittest.TestCase):
    def test_reports_incomplete_when_ordered_evidence_is_absent_everywhere(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_path, sarif_path, cloud_path = write_payload_set(pathlib.Path(tmp_dir))

            summary = output_evidence_parity.run_harness(
                json_report=json_path,
                sarif_report=sarif_path,
                cloudevents=cloud_path,
            )

        self.assertEqual(summary["status"], "incomplete")
        self.assertEqual(summary["counts"]["fail"], 0)
        self.assertGreater(summary["counts"]["pass"], 0)
        pending_ids = {
            check["id"] for check in summary["checks"] if check["status"] == "pending"
        }
        self.assertIn("finding[0].evidence.ordered_authority_evidence", pending_ids)

    def test_passes_when_identity_and_evidence_presence_match_across_sinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_path, sarif_path, cloud_path = write_payload_set(
                pathlib.Path(tmp_dir),
                include_ordered_evidence=True,
            )

            summary = output_evidence_parity.run_harness(
                json_report=json_path,
                sarif_report=sarif_path,
                cloudevents=cloud_path,
            )

        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["counts"]["fail"], 0)
        self.assertEqual(summary["counts"]["pending"], 0)

    def test_fails_when_public_extra_presence_diverges_across_sinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_path, sarif_path, cloud_path = write_payload_set(
                pathlib.Path(tmp_dir),
                include_ordered_evidence=True,
                omit_cloud_event_extra="authority_kinds",
            )

            summary = output_evidence_parity.run_harness(
                json_report=json_path,
                sarif_report=sarif_path,
                cloudevents=cloud_path,
            )

        self.assertEqual(summary["status"], "fail")
        failed = [check for check in summary["checks"] if check["status"] == "fail"]
        self.assertEqual(failed[0]["id"], "finding[0].evidence.authority_kinds")
        self.assertEqual(failed[0]["presence"]["json"], True)
        self.assertEqual(failed[0]["presence"]["sarif"], True)
        self.assertEqual(failed[0]["presence"]["cloudevents"], False)

    def test_main_prints_json_and_returns_three_for_pending_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_path, sarif_path, cloud_path = write_payload_set(pathlib.Path(tmp_dir))
            stdout = StringIO()

            with redirect_stdout(stdout):
                exit_code = output_evidence_parity.main(
                    [
                        "--json-report",
                        str(json_path),
                        "--sarif",
                        str(sarif_path),
                        "--cloudevents",
                        str(cloud_path),
                        "--format",
                        "json",
                    ]
                )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 3)
        self.assertEqual(payload["status"], "incomplete")
        self.assertGreater(payload["counts"]["pending"], 0)


if __name__ == "__main__":
    unittest.main()
