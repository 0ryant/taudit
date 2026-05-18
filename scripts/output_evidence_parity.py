from __future__ import annotations

import argparse
import json
import pathlib
from dataclasses import dataclass
from typing import Any


REPORT_KIND = "taudit.output_evidence_parity"
SURFACES = ("json", "sarif", "cloudevents")
MISSING = object()


@dataclass(frozen=True)
class FieldSpec:
    family: str
    key: str
    paths: dict[str, tuple[tuple[str, ...], ...]]
    absent_everywhere_status: str = "pass"


FIELD_SPECS = (
    FieldSpec(
        "identity",
        "rule_id",
        {
            "json": (("rule_id",),),
            "sarif": (("ruleId",),),
            "cloudevents": (("tauditruleid",),),
        },
        absent_everywhere_status="fail",
    ),
    FieldSpec(
        "identity",
        "fingerprint",
        {
            "json": (("fingerprint",),),
            "sarif": (
                ("partialFingerprints", "primaryLocationLineHash"),
                ("partialFingerprints", "taudit/v1"),
            ),
            "cloudevents": (("tauditfindingfingerprint",),),
        },
        absent_everywhere_status="fail",
    ),
    FieldSpec(
        "identity",
        "suppression_key",
        {
            "json": (("suppression_key",),),
            "sarif": (("properties", "suppressionKey"),),
            "cloudevents": (("tauditsuppressionkey",),),
        },
        absent_everywhere_status="fail",
    ),
    FieldSpec(
        "identity",
        "finding_group_id",
        {
            "json": (("finding_group_id",),),
            "sarif": (("properties", "findingGroupId"),),
            "cloudevents": (("tauditfindinggroup",),),
        },
        absent_everywhere_status="fail",
    ),
    FieldSpec(
        "evidence",
        "confidence_scope",
        {
            "json": (("confidence_scope",),),
            "sarif": (("properties", "confidenceScope"),),
            "cloudevents": (("data", "confidence_scope"),),
        },
    ),
    FieldSpec(
        "evidence",
        "runtime_preconditions",
        {
            "json": (("runtime_preconditions",),),
            "sarif": (("properties", "runtimePreconditions"),),
            "cloudevents": (("data", "runtime_preconditions"),),
        },
    ),
    FieldSpec(
        "evidence",
        "portal_control_dependency",
        {
            "json": (("portal_control_dependency",),),
            "sarif": (("properties", "portalControlDependency"),),
            "cloudevents": (("data", "portal_control_dependency"),),
        },
    ),
    FieldSpec(
        "evidence",
        "authority_kinds",
        {
            "json": (("authority_kinds",),),
            "sarif": (("properties", "authorityKinds"),),
            "cloudevents": (("data", "authority_kinds"),),
        },
    ),
    FieldSpec(
        "evidence",
        "attacker_surface_kinds",
        {
            "json": (("attacker_surface_kinds",),),
            "sarif": (("properties", "attackerSurfaceKinds"),),
            "cloudevents": (("data", "attacker_surface_kinds"),),
        },
    ),
    FieldSpec(
        "evidence",
        "template_resolution_strength",
        {
            "json": (("template_resolution_strength",),),
            "sarif": (("properties", "templateResolutionStrength"),),
            "cloudevents": (("data", "template_resolution_strength"),),
        },
    ),
    FieldSpec(
        "evidence",
        "time_to_fix",
        {
            "json": (("time_to_fix",),),
            "sarif": (("properties", "timeToFix"),),
            "cloudevents": (("data", "time_to_fix"),),
        },
    ),
    FieldSpec(
        "evidence",
        "compensating_controls",
        {
            "json": (("compensating_controls",),),
            "sarif": (("properties", "compensatingControls"),),
            "cloudevents": (("data", "compensating_controls"),),
        },
    ),
    FieldSpec(
        "evidence",
        "ordered_authority_evidence",
        {
            "json": (("ordered_authority_evidence",),),
            "sarif": (("properties", "ordered_authority_evidence"),),
            "cloudevents": (("data", "ordered_authority_evidence"),),
        },
        absent_everywhere_status="pending",
    ),
)


def load_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc


def load_cloudevents(path: pathlib.Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    stripped = text.strip()
    if not stripped:
        return []
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        events = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL event: {exc}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"{path}:{line_no}: CloudEvents JSONL item must be an object")
            events.append(item)
        return events

    if isinstance(payload, list):
        if not all(isinstance(item, dict) for item in payload):
            raise ValueError(f"{path}: CloudEvents array items must be objects")
        return payload
    if isinstance(payload, dict):
        return [payload]
    raise ValueError(f"{path}: CloudEvents payload must be an object, array, or JSONL stream")


def json_findings(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ValueError("JSON report must be an object")
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise ValueError("JSON report must contain a findings array")
    if not all(isinstance(item, dict) for item in findings):
        raise ValueError("JSON report findings must be objects")
    return findings


def sarif_results(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ValueError("SARIF report must be an object")
    runs = payload.get("runs")
    if not isinstance(runs, list):
        raise ValueError("SARIF report must contain a runs array")
    results: list[dict[str, Any]] = []
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise ValueError(f"SARIF run[{run_index}] must be an object")
        run_results = run.get("results", [])
        if not isinstance(run_results, list):
            raise ValueError(f"SARIF run[{run_index}].results must be an array")
        for result_index, result in enumerate(run_results):
            if not isinstance(result, dict):
                raise ValueError(
                    f"SARIF run[{run_index}].results[{result_index}] must be an object"
                )
            results.append(result)
    return results


def value_at(payload: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return MISSING
        current = current[key]
    return current


def has_all_paths(payload: dict[str, Any], paths: tuple[tuple[str, ...], ...]) -> bool:
    return all(value_at(payload, path) is not MISSING for path in paths)


def evaluate_field(
    spec: FieldSpec,
    index: int,
    records: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    presence = {}
    for surface in SURFACES:
        surface_records = records[surface]
        if index >= len(surface_records):
            presence[surface] = False
            continue
        presence[surface] = has_all_paths(surface_records[index], spec.paths[surface])

    present_count = sum(1 for value in presence.values() if value)
    if present_count == len(SURFACES):
        status = "pass"
        message = f"{spec.key} is present on every sink for finding[{index}]"
    elif present_count == 0:
        status = spec.absent_everywhere_status
        if status == "pending":
            message = (
                f"{spec.key} is absent on every sink for finding[{index}]; "
                "treat as pending until that evidence object is wired"
            )
        elif status == "fail":
            message = f"{spec.key} is absent on every sink for finding[{index}]"
        else:
            message = (
                f"{spec.key} is absent on every sink for finding[{index}]; "
                "no parity obligation was triggered"
            )
    else:
        status = "fail"
        missing = ", ".join(surface for surface, is_present in presence.items() if not is_present)
        message = f"{spec.key} presence diverges for finding[{index}]; missing: {missing}"

    return {
        "id": f"finding[{index}].{spec.family}.{spec.key}",
        "status": status,
        "family": spec.family,
        "field": spec.key,
        "presence": presence,
        "message": message,
    }


def count_checks(checks: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "pass": sum(1 for check in checks if check["status"] == "pass"),
        "pending": sum(1 for check in checks if check["status"] == "pending"),
        "fail": sum(1 for check in checks if check["status"] == "fail"),
    }


def status_from_counts(counts: dict[str, int]) -> str:
    if counts["fail"]:
        return "fail"
    if counts["pending"]:
        return "incomplete"
    return "pass"


def run_harness(
    *,
    json_report: pathlib.Path,
    sarif_report: pathlib.Path,
    cloudevents: pathlib.Path,
) -> dict[str, Any]:
    records = {
        "json": json_findings(load_json(json_report)),
        "sarif": sarif_results(load_json(sarif_report)),
        "cloudevents": load_cloudevents(cloudevents),
    }
    checks: list[dict[str, Any]] = []
    lengths = {surface: len(records[surface]) for surface in SURFACES}
    if len(set(lengths.values())) != 1:
        checks.append(
            {
                "id": "surface.finding_count",
                "status": "fail",
                "family": "shape",
                "field": "finding_count",
                "counts": lengths,
                "message": "sink fixture finding counts differ",
            }
        )

    max_findings = max(lengths.values(), default=0)
    for index in range(max_findings):
        for spec in FIELD_SPECS:
            checks.append(evaluate_field(spec, index, records))

    counts = count_checks(checks)
    return {
        "report_kind": REPORT_KIND,
        "status": status_from_counts(counts),
        "counts": counts,
        "surfaces": {
            "json": {"path": str(json_report), "findings": lengths["json"]},
            "sarif": {"path": str(sarif_report), "findings": lengths["sarif"]},
            "cloudevents": {"path": str(cloudevents), "findings": lengths["cloudevents"]},
        },
        "checks": checks,
    }


def render_text(summary: dict[str, Any]) -> str:
    lines = [
        f"{summary['report_kind']}: {summary['status']}",
        (
            "checks: "
            f"{summary['counts']['pass']} pass, "
            f"{summary['counts']['pending']} pending, "
            f"{summary['counts']['fail']} fail"
        ),
    ]
    for check in summary["checks"]:
        if check["status"] != "pass":
            lines.append(f"- {check['status']}: {check['id']}: {check['message']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare public evidence and identity key presence across saved "
            "JSON, SARIF, and CloudEvents fixtures."
        )
    )
    parser.add_argument("--json-report", type=pathlib.Path, required=True)
    parser.add_argument("--sarif", dest="sarif_report", type=pathlib.Path, required=True)
    parser.add_argument("--cloudevents", type=pathlib.Path, required=True)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)

    try:
        summary = run_harness(
            json_report=args.json_report,
            sarif_report=args.sarif_report,
            cloudevents=args.cloudevents,
        )
    except ValueError as exc:
        summary = {
            "report_kind": REPORT_KIND,
            "status": "fail",
            "counts": {"pass": 0, "pending": 0, "fail": 1},
            "checks": [
                {
                    "id": "input.load",
                    "status": "fail",
                    "family": "input",
                    "field": "load",
                    "message": str(exc),
                }
            ],
        }

    if args.format == "json":
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(render_text(summary))

    if summary["status"] == "fail":
        return 1
    if summary["status"] == "incomplete":
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
