#!/usr/bin/env python3
"""Offline ADR 0020 conformance harness skeleton."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import Counter
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]

DEFAULT_REQUIRED_PATHS = (
    pathlib.Path("contracts/schemas/taudit-report.schema.json"),
    pathlib.Path("contracts/schemas/taudit-cloudevent-finding-v1.schema.json"),
    pathlib.Path("contracts/schemas/authority-invariant-v1.schema.json"),
    pathlib.Path("contracts/schemas/ecosystem-evidence-envelope-v0.schema.json"),
    pathlib.Path("contracts/examples/clean-report.json"),
    pathlib.Path("contracts/examples/over-privileged-report.json"),
    pathlib.Path("contracts/examples/over-privileged-finding.cloudevent.json"),
    pathlib.Path("contracts/examples/authority-invariant-v1.example.json"),
    pathlib.Path("contracts/examples/ecosystem-evidence-envelope.example.json"),
    pathlib.Path("schemas/authority-graph.v1.json"),
    pathlib.Path("schemas/exploit-graph.v1.json"),
    pathlib.Path("schemas/finding.v1.json"),
    pathlib.Path("schemas/baseline.v1.json"),
)

CONTRACT_EXAMPLE_GLOB = pathlib.PurePosixPath("contracts/examples/*.json")

CURRENT_PROFILE_PLACEHOLDERS = (
    ("current_profile.report_json", "pending current-profile field assertions for scan/report JSON"),
    ("current_profile.cloudevents", "pending current-profile field assertions for CloudEvents"),
    ("current_profile.sarif", "pending current-profile field assertions for SARIF"),
    ("current_profile.exploit_graph", "pending current-profile field assertions for exploit graph JSON"),
    (
        "current_profile.suppressions_baselines",
        "pending current-profile assertions for suppressions and baselines",
    ),
    (
        "current_profile.terminal_verbose",
        "pending current-profile assertions for terminal verbose output",
    ),
    ("parity.identity", "pending cross-sink identity parity assertions"),
    ("parity.evidence", "pending cross-sink evidence parity assertions"),
    ("reference_consumers", "pending reference consumer conformance checks"),
    ("exit_code_matrix", "pending exit-code matrix conformance checks"),
)


def relative_posix(path: pathlib.Path) -> str:
    return path.as_posix()


def check_path_presence(root: pathlib.Path, relative_path: pathlib.Path) -> dict[str, str]:
    path = root / relative_path
    rel = relative_posix(relative_path)
    if path.exists():
        return {
            "id": f"presence.{rel}",
            "kind": "path_presence",
            "status": "pass",
            "path": rel,
            "message": "expected path exists",
        }
    return {
        "id": f"presence.{rel}",
        "kind": "path_presence",
        "status": "fail",
        "path": rel,
        "message": "expected path is missing",
    }


def discover_contract_examples(root: pathlib.Path) -> list[pathlib.Path]:
    examples_dir = root / "contracts" / "examples"
    if not examples_dir.exists():
        return []
    return sorted(
        (path.relative_to(root) for path in examples_dir.glob("*.json")),
        key=relative_posix,
    )


def check_json_parse(root: pathlib.Path, relative_path: pathlib.Path) -> dict[str, str]:
    path = root / relative_path
    rel = relative_posix(relative_path)
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {
            "id": f"json.{rel}",
            "kind": "json_parse",
            "status": "fail",
            "path": rel,
            "message": f"invalid JSON: line {exc.lineno} column {exc.colno}: {exc.msg}",
        }
    except OSError as exc:
        return {
            "id": f"json.{rel}",
            "kind": "json_parse",
            "status": "fail",
            "path": rel,
            "message": f"could not read JSON: {exc}",
        }
    return {
        "id": f"json.{rel}",
        "kind": "json_parse",
        "status": "pass",
        "path": rel,
        "message": "contract example parses as JSON",
    }


def pending_check(check_id: str, message: str) -> dict[str, str]:
    return {
        "id": check_id,
        "kind": "placeholder",
        "status": "pending",
        "path": "",
        "message": message,
    }


def run_harness(root: pathlib.Path) -> dict[str, Any]:
    root = root.resolve()
    checks: list[dict[str, str]] = []

    for relative_path in DEFAULT_REQUIRED_PATHS:
        checks.append(check_path_presence(root, relative_path))

    for relative_path in discover_contract_examples(root):
        checks.append(check_json_parse(root, relative_path))

    for check_id, message in CURRENT_PROFILE_PLACEHOLDERS:
        checks.append(pending_check(check_id, message))

    counts = Counter(check["status"] for check in checks)
    status = "fail" if counts["fail"] else ("incomplete" if counts["pending"] else "pass")

    return {
        "schema": "taudit.conformance-harness.summary.v0",
        "harness": "adr-0020-offline-skeleton",
        "status": status,
        "full_conformance": False,
        "contract_example_glob": str(CONTRACT_EXAMPLE_GLOB),
        "counts": {
            "pass": counts["pass"],
            "fail": counts["fail"],
            "pending": counts["pending"],
        },
        "checks": checks,
    }


def format_text(summary: dict[str, Any]) -> str:
    lines = [
        f"status: {summary['status']}",
        f"full_conformance: {str(summary['full_conformance']).lower()}",
        (
            "counts: "
            f"pass={summary['counts']['pass']} "
            f"fail={summary['counts']['fail']} "
            f"pending={summary['counts']['pending']}"
        ),
    ]
    for check in summary["checks"]:
        path = f" {check['path']}" if check["path"] else ""
        lines.append(f"{check['status']} {check['id']}{path} - {check['message']}")
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=ROOT,
        help="Repository root to validate.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="Output summary format.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    summary = run_harness(args.root)
    if args.format == "json":
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        sys.stdout.write(format_text(summary))
    if summary["status"] == "fail":
        return 1
    if summary["status"] == "incomplete":
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
