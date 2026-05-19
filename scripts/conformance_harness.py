#!/usr/bin/env python3
"""ADR 0020 output conformance harness."""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
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

ORDERED_EVIDENCE_DEFERRAL_PATHS = (
    pathlib.Path("CHANGELOG.md"),
    pathlib.Path("docs/rc/v1.2.0/current-output-profile.md"),
    pathlib.Path("docs/rc/v1.2.0/evidence-parity-harness.md"),
    pathlib.Path("docs/rc/v1.2.0/operator-evidence-output-guide.md"),
)

EXPLOIT_FIXTURE = """\
name: deploy
on: push
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Create fake npx and persist PATH mutation
        run: |
          mkdir -p /tmp/fake
          echo /tmp/fake >> "$GITHUB_PATH"
      - name: Run Firebase Hosting witness
        uses: FirebaseExtended/action-hosting-deploy@v0
        with:
          firebaseServiceAccount: ${{ secrets.FIREBASE_SERVICE_ACCOUNT }}
          projectId: canary-project
"""


def _load_module(name: str, path: pathlib.Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


current_output_profile_check = _load_module(
    "current_output_profile_check_for_conformance",
    ROOT / "scripts" / "current_output_profile_check.py",
)
output_evidence_parity = _load_module(
    "output_evidence_parity_for_conformance",
    ROOT / "scripts" / "output_evidence_parity.py",
)
report_identity_summary = _load_module(
    "report_identity_summary_for_conformance",
    ROOT / "examples" / "consumers" / "python" / "report_identity_summary.py",
)


def relative_posix(path: pathlib.Path) -> str:
    return path.as_posix()


def check(
    check_id: str,
    kind: str,
    status: str,
    path: str,
    message: str,
    **extra: Any,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": check_id,
        "kind": kind,
        "status": status,
        "path": path,
        "message": message,
    }
    record.update(extra)
    return record


def check_path_presence(root: pathlib.Path, relative_path: pathlib.Path) -> dict[str, Any]:
    path = root / relative_path
    rel = relative_posix(relative_path)
    if path.exists():
        return check(
            f"presence.{rel}",
            "path_presence",
            "pass",
            rel,
            "expected path exists",
        )
    return check(
        f"presence.{rel}",
        "path_presence",
        "fail",
        rel,
        "expected path is missing",
    )


def discover_contract_examples(root: pathlib.Path) -> list[pathlib.Path]:
    examples_dir = root / "contracts" / "examples"
    if not examples_dir.exists():
        return []
    return sorted(
        (path.relative_to(root) for path in examples_dir.glob("*.json")),
        key=relative_posix,
    )


def check_json_parse(root: pathlib.Path, relative_path: pathlib.Path) -> dict[str, Any]:
    path = root / relative_path
    rel = relative_posix(relative_path)
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return check(
            f"json.{rel}",
            "json_parse",
            "fail",
            rel,
            f"invalid JSON: line {exc.lineno} column {exc.colno}: {exc.msg}",
        )
    except OSError as exc:
        return check(
            f"json.{rel}",
            "json_parse",
            "fail",
            rel,
            f"could not read JSON: {exc}",
        )
    return check(
        f"json.{rel}",
        "json_parse",
        "pass",
        rel,
        "contract example parses as JSON",
    )


def documented_ordered_evidence_deferral(root: pathlib.Path) -> bool:
    for relative in ORDERED_EVIDENCE_DEFERRAL_PATHS:
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8").lower()
        except OSError:
            return False
        if "ordered_authority_evidence" not in text:
            return False
        if not any(token in text for token in ("pending", "defer", "not wired", "not a current-output claim")):
            return False
    return True


def ordered_deferral_check(root: pathlib.Path) -> dict[str, Any]:
    if documented_ordered_evidence_deferral(root):
        return check(
            "ordered_authority_evidence.deferral",
            "documented_deferral",
            "pass",
            "CHANGELOG.md",
            "ordered_authority_evidence is explicitly scoped as a documented RC deferral",
        )
    return check(
        "ordered_authority_evidence.deferral",
        "documented_deferral",
        "fail",
        "CHANGELOG.md",
        "ordered_authority_evidence is missing an explicit RC deferral boundary",
    )


def _only_ordered_pending_profile(receipt: dict[str, Any]) -> bool:
    issues = receipt.get("issues")
    if not isinstance(issues, list) or not issues:
        return False
    for issue in issues:
        if not isinstance(issue, dict):
            return False
        if issue.get("status") != "pending":
            return False
        if issue.get("code") != "ordered-authority-evidence-pending":
            return False
    return True


def _only_ordered_pending_parity(receipt: dict[str, Any]) -> bool:
    checks = receipt.get("checks")
    if not isinstance(checks, list) or not checks:
        return False
    pending = [item for item in checks if isinstance(item, dict) and item.get("status") == "pending"]
    if not pending:
        return False
    return all(item.get("field") == "ordered_authority_evidence" for item in pending)


def profile_check(
    check_id: str,
    receipt: dict[str, Any],
    path: str,
    *,
    ordered_deferral: bool,
) -> dict[str, Any]:
    status = receipt.get("status")
    counts = receipt.get("counts", {})
    if status == "pass":
        return check(
            check_id,
            "current_profile",
            "pass",
            path,
            "current-output profile passed",
            receipt_counts=counts,
        )
    if status == "incomplete" and ordered_deferral and _only_ordered_pending_profile(receipt):
        return check(
            check_id,
            "current_profile",
            "pass",
            path,
            "current-output profile passed with documented ordered_authority_evidence deferral",
            receipt_counts=counts,
        )
    return check(
        check_id,
        "current_profile",
        "fail",
        path,
        f"current-output profile reported {status!r}",
        receipt_counts=counts,
        issues=receipt.get("issues", []),
    )


def parity_check(
    check_id: str,
    receipt: dict[str, Any],
    path: str,
    *,
    ordered_deferral: bool,
) -> dict[str, Any]:
    status = receipt.get("status")
    counts = receipt.get("counts", {})
    if status == "pass":
        return check(
            check_id,
            "evidence_parity",
            "pass",
            path,
            "cross-sink evidence parity passed",
            receipt_counts=counts,
        )
    if status == "incomplete" and ordered_deferral and _only_ordered_pending_parity(receipt):
        return check(
            check_id,
            "evidence_parity",
            "pass",
            path,
            "cross-sink evidence parity passed with documented ordered_authority_evidence deferral",
            receipt_counts=counts,
        )
    return check(
        check_id,
        "evidence_parity",
        "fail",
        path,
        f"cross-sink evidence parity reported {status!r}",
        receipt_counts=counts,
        checks=receipt.get("checks", []),
    )


def checked_in_profile_checks(root: pathlib.Path, ordered_deferral: bool) -> list[dict[str, Any]]:
    report_paths = [
        root / "contracts" / "examples" / "clean-report.json",
        root / "contracts" / "examples" / "over-privileged-report.json",
    ]
    cloudevent_path = root / "contracts" / "examples" / "over-privileged-finding.cloudevent.json"

    report_receipt = current_output_profile_check.check_current_profile(
        report_json=report_paths,
    )
    event_receipt = current_output_profile_check.check_current_profile(
        cloudevent_json=[cloudevent_path],
    )
    return [
        profile_check(
            "current_profile.report_json",
            report_receipt,
            "contracts/examples/{clean-report,over-privileged-report}.json",
            ordered_deferral=ordered_deferral,
        ),
        profile_check(
            "current_profile.cloudevents",
            event_receipt,
            "contracts/examples/over-privileged-finding.cloudevent.json",
            ordered_deferral=ordered_deferral,
        ),
    ]


def reference_consumer_check(root: pathlib.Path) -> dict[str, Any]:
    paths = [
        root / "contracts" / "examples" / "over-privileged-report.json",
        root / "contracts" / "examples" / "over-privileged-finding.cloudevent.json",
    ]
    try:
        summaries = []
        for path in paths:
            summaries.extend(report_identity_summary.summarize_path(path))
    except Exception as exc:  # noqa: BLE001 - harness reports consumer exceptions as failures.
        return check(
            "reference_consumers",
            "reference_consumer",
            "fail",
            "examples/consumers/python/report_identity_summary.py",
            f"reference consumer failed: {exc}",
        )

    kinds = {summary.get("kind") for summary in summaries if isinstance(summary, dict)}
    report = next((item for item in summaries if item.get("kind") == "report"), None)
    event = next((item for item in summaries if item.get("kind") == "cloudevent"), None)
    if kinds >= {"report", "cloudevent"} and report and event:
        identities = report.get("finding_identities")
        event_identity = event.get("identity", {})
        if isinstance(identities, list) and identities and event_identity.get("fingerprint"):
            return check(
                "reference_consumers",
                "reference_consumer",
                "pass",
                "examples/consumers/python/report_identity_summary.py",
                "reference consumer reads report and CloudEvent identity fields",
            )
    return check(
        "reference_consumers",
        "reference_consumer",
        "fail",
        "examples/consumers/python/report_identity_summary.py",
        "reference consumer did not return expected report and CloudEvent identity summaries",
        summaries=summaries,
    )


def run_command(
    root: pathlib.Path,
    argv: list[str],
    *,
    stdout_path: pathlib.Path | None = None,
) -> subprocess.CompletedProcess[str]:
    if stdout_path is None:
        return subprocess.run(
            argv,
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    with stdout_path.open("w", encoding="utf-8") as stdout:
        return subprocess.run(
            argv,
            cwd=root,
            check=False,
            stdout=stdout,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )


def command_check(
    check_id: str,
    kind: str,
    root: pathlib.Path,
    argv: list[str],
    path: str,
) -> dict[str, Any]:
    result = run_command(root, argv)
    if result.returncode == 0:
        return check(check_id, kind, "pass", path, "command exited 0", command=argv)
    return check(
        check_id,
        kind,
        "fail",
        path,
        f"command exited {result.returncode}",
        command=argv,
        stderr=result.stderr[-4000:],
        stdout=result.stdout[-4000:],
    )


def generated_cli_checks(root: pathlib.Path, ordered_deferral: bool) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="taudit-conformance-") as tmp_dir:
        tmp = pathlib.Path(tmp_dir)
        report_json = tmp / "report.json"
        sarif_json = tmp / "report.sarif"
        events_jsonl = tmp / "events.jsonl"

        scan_commands = [
            (
                "generated.scan.report_json",
                [
                    "cargo",
                    "run",
                    "-q",
                    "-p",
                    "taudit",
                    "--",
                    "scan",
                    "tests/fixtures/over-privileged.yml",
                    "--format",
                    "json",
                ],
                report_json,
            ),
            (
                "generated.scan.sarif",
                [
                    "cargo",
                    "run",
                    "-q",
                    "-p",
                    "taudit",
                    "--",
                    "scan",
                    "tests/fixtures/over-privileged.yml",
                    "--format",
                    "sarif",
                ],
                sarif_json,
            ),
            (
                "generated.scan.cloudevents",
                [
                    "cargo",
                    "run",
                    "-q",
                    "-p",
                    "taudit",
                    "--",
                    "scan",
                    "tests/fixtures/over-privileged.yml",
                    "--format",
                    "cloudevents",
                ],
                events_jsonl,
            ),
        ]
        for check_id, argv, stdout_path in scan_commands:
            result = run_command(root, argv, stdout_path=stdout_path)
            if result.returncode != 0:
                checks.append(
                    check(
                        check_id,
                        "generated_artifact",
                        "fail",
                        str(stdout_path),
                        f"artifact generation exited {result.returncode}",
                        command=argv,
                        stderr=result.stderr[-4000:],
                    )
                )
                return checks
            checks.append(
                check(
                    check_id,
                    "generated_artifact",
                    "pass",
                    str(stdout_path),
                    "artifact generated",
                    command=argv,
                )
            )

        generated_profile = current_output_profile_check.check_current_profile(
            report_json=[report_json],
            sarif_json=[sarif_json],
            cloudevent_json=[events_jsonl],
        )
        checks.append(
            profile_check(
                "current_profile.generated_json_sarif_cloudevents",
                generated_profile,
                str(tmp),
                ordered_deferral=ordered_deferral,
            )
        )

        parity = output_evidence_parity.run_harness(
            json_report=report_json,
            sarif_report=sarif_json,
            cloudevents=events_jsonl,
        )
        checks.append(
            parity_check(
                "parity.identity_and_evidence",
                parity,
                str(tmp),
                ordered_deferral=ordered_deferral,
            )
        )

        exploit_fixture = tmp / "exploit-fixture.yml"
        exploit_fixture.write_text(EXPLOIT_FIXTURE, encoding="utf-8")
        exploit_json = tmp / "exploit.json"
        exploit_command = [
            "cargo",
            "run",
            "-q",
            "-p",
            "taudit",
            "--",
            "graph",
            "--platform",
            "github-actions",
            "--format",
            "json",
            "--view",
            "exploit",
            str(exploit_fixture),
        ]
        result = run_command(root, exploit_command, stdout_path=exploit_json)
        if result.returncode == 0:
            checks.append(
                check(
                    "generated.exploit_graph",
                    "generated_artifact",
                    "pass",
                    str(exploit_json),
                    "exploit graph artifact generated",
                    command=exploit_command,
                )
            )
            exploit_profile = current_output_profile_check.check_current_profile(
                exploit_graph_json=[exploit_json],
            )
            checks.append(
                profile_check(
                    "current_profile.exploit_graph",
                    exploit_profile,
                    str(exploit_json),
                    ordered_deferral=ordered_deferral,
                )
            )
        else:
            checks.append(
                check(
                    "generated.exploit_graph",
                    "generated_artifact",
                    "fail",
                    str(exploit_json),
                    f"exploit graph generation exited {result.returncode}",
                    command=exploit_command,
                    stderr=result.stderr[-4000:],
                )
            )

        baseline_root = tmp / "baseline-root"
        baseline_command = [
            "cargo",
            "run",
            "-q",
            "-p",
            "taudit",
            "--",
            "baseline",
            "init",
            "--root",
            str(baseline_root),
            "--captured-by",
            "conformance@example.com",
            "--platform",
            "github-actions",
            "tests/fixtures/over-privileged.yml",
        ]
        result = run_command(root, baseline_command)
        if result.returncode == 0:
            baselines = sorted((baseline_root / ".taudit" / "baselines").glob("*.json"))
            checks.append(
                check(
                    "generated.baseline",
                    "generated_artifact",
                    "pass",
                    str(baseline_root),
                    f"baseline init generated {len(baselines)} baseline file(s)",
                    command=baseline_command,
                )
            )
            baseline_profile = current_output_profile_check.check_current_profile(
                baseline_json=baselines,
            )
            checks.append(
                profile_check(
                    "current_profile.suppressions_baselines",
                    baseline_profile,
                    str(baseline_root),
                    ordered_deferral=ordered_deferral,
                )
            )
        else:
            checks.append(
                check(
                    "generated.baseline",
                    "generated_artifact",
                    "fail",
                    str(baseline_root),
                    f"baseline init exited {result.returncode}",
                    command=baseline_command,
                    stderr=result.stderr[-4000:],
                )
            )

        terminal_command = [
            "cargo",
            "run",
            "-q",
            "-p",
            "taudit",
            "--",
            "scan",
            "tests/fixtures/over-privileged.yml",
            "--no-color",
            "--verbose",
        ]
        result = run_command(root, terminal_command)
        terminal_out = result.stdout
        terminal_tokens = [
            "rule_id:",
            "fingerprint:",
            "suppression_key: sk1_",
            "finding_group_id:",
            "Recommendation:",
        ]
        if result.returncode == 0 and all(token in terminal_out for token in terminal_tokens):
            checks.append(
                check(
                    "current_profile.terminal_verbose",
                    "terminal_profile",
                    "pass",
                    "tests/fixtures/over-privileged.yml",
                    "terminal verbose output includes sanitized triage and identity fields",
                    command=terminal_command,
                )
            )
        else:
            checks.append(
                check(
                    "current_profile.terminal_verbose",
                    "terminal_profile",
                    "fail",
                    "tests/fixtures/over-privileged.yml",
                    "terminal verbose output did not include required triage identity fields",
                    command=terminal_command,
                    exit_code=result.returncode,
                    stdout=terminal_out[-4000:],
                    stderr=result.stderr[-4000:],
                )
            )

    checks.append(
        command_check(
            "exit_code_matrix",
            "rust_contract_test",
            root,
            ["cargo", "test", "-p", "taudit", "--test", "suppression_baseline_exit_matrix"],
            "crates/taudit-cli/tests/suppression_baseline_exit_matrix.rs",
        )
    )
    checks.append(
        command_check(
            "sink_identity_contract",
            "rust_contract_test",
            root,
            ["cargo", "test", "-p", "taudit", "--test", "cross_sink_contract"],
            "crates/taudit-cli/tests/cross_sink_contract.rs",
        )
    )
    checks.append(
        command_check(
            "hostile_rendering_contract",
            "rust_contract_test",
            root,
            ["cargo", "test", "-p", "taudit", "--test", "hostile_rendering_corpus"],
            "crates/taudit-cli/tests/hostile_rendering_corpus.rs",
        )
    )
    return checks


def run_harness(root: pathlib.Path, *, run_generated: bool = True) -> dict[str, Any]:
    root = root.resolve()
    checks: list[dict[str, Any]] = []

    for relative_path in DEFAULT_REQUIRED_PATHS:
        checks.append(check_path_presence(root, relative_path))

    for relative_path in discover_contract_examples(root):
        checks.append(check_json_parse(root, relative_path))

    ordered_deferral = documented_ordered_evidence_deferral(root)
    checks.append(ordered_deferral_check(root))
    checks.extend(checked_in_profile_checks(root, ordered_deferral))
    checks.append(reference_consumer_check(root))

    if run_generated:
        checks.extend(generated_cli_checks(root, ordered_deferral))

    counts = Counter(item["status"] for item in checks)
    status = "fail" if counts["fail"] else ("incomplete" if counts["pending"] else "pass")
    full_conformance = run_generated and status == "pass"

    return {
        "schema": "taudit.conformance-harness.summary.v0",
        "harness": "adr-0020-output-conformance",
        "status": status,
        "full_conformance": full_conformance,
        "contract_example_glob": str(CONTRACT_EXAMPLE_GLOB),
        "generated_checks": run_generated,
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
    for item in summary["checks"]:
        path = f" {item['path']}" if item["path"] else ""
        lines.append(f"{item['status']} {item['id']}{path} - {item['message']}")
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
    parser.add_argument(
        "--skip-generated",
        action="store_true",
        help="Skip generated CLI artifact checks; intended for fast unit tests only.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    summary = run_harness(args.root, run_generated=not args.skip_generated)
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
