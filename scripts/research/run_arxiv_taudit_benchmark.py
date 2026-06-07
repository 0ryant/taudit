#!/usr/bin/env python3
"""Run taudit in the arXiv scanner-benchmark shape.

The benchmark shape is one workflow file per invocation, JSON output, no color,
repeated wall-clock timing, raw output retention, and fail-closed taxonomy
normalization.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import hashlib
import json
import os
import statistics
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from normalize_taudit_arxiv_findings import (  # noqa: E402
    ArxivNormalizationError,
    load_rule_map,
    normalize_report,
)


TIMING_COLUMNS = [
    "workflow_path",
    "workflow_id",
    "repeat_index",
    "exit_code",
    "elapsed_ms",
    "status",
    "stdout_path",
    "stderr_path",
]


@dataclasses.dataclass(frozen=True)
class RunConfig:
    taudit_cmd: Sequence[str]
    output_dir: Path
    rule_map: Path
    platform: str = "github-actions"
    repeat: int = 3
    timeout_seconds: float = 30.0
    include_out_of_scope: bool = False


@dataclasses.dataclass
class RepeatResult:
    workflow_path: str
    workflow_id: str
    repeat_index: int
    exit_code: int | None
    elapsed_ms: int
    status: str
    stdout_path: str
    stderr_path: str


def process_output_text(value: str | bytes | None, fallback: str = "") -> str:
    if value is None:
        return fallback
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def workflow_id(path: Path, root: Path | None = None) -> str:
    try:
        rel = path.resolve().relative_to(root.resolve()) if root else path.resolve()
    except ValueError:
        rel = path.resolve()
    digest = hashlib.sha256(str(rel).replace("\\", "/").encode("utf-8")).hexdigest()[:16]
    stem = "".join(ch if ch.isalnum() else "-" for ch in path.stem.lower()).strip("-")[:40]
    return f"{stem}-{digest}" if stem else digest


def discover_workflows(root: Path | None, workflow_list: Path | None, limit: int | None) -> list[Path]:
    paths: list[Path] = []
    if workflow_list:
        for raw in workflow_list.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                paths.append(Path(line))
    if root:
        paths.extend(sorted(p for p in root.rglob("*") if p.suffix.lower() in {".yml", ".yaml"}))
    unique = sorted({p.resolve() for p in paths})
    return unique[:limit] if limit is not None else unique


def run_taudit_once(
    workflow: Path,
    workflow_root: Path | None,
    repeat_index: int,
    config: RunConfig,
) -> tuple[RepeatResult, dict | None]:
    wid = workflow_id(workflow, workflow_root)
    raw_dir = config.output_dir / "raw" / wid
    raw_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = raw_dir / f"repeat-{repeat_index}.json"
    stderr_path = raw_dir / f"repeat-{repeat_index}.stderr.txt"
    cmd = [
        *config.taudit_cmd,
        "scan",
        str(workflow),
        "--platform",
        config.platform,
        "--format",
        "json",
        "--no-color",
    ]

    started = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=config.timeout_seconds,
        )
        elapsed_ms = int((time.perf_counter() - started) * 1000)
    except subprocess.TimeoutExpired as exc:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        stdout_path.write_text(process_output_text(exc.stdout), encoding="utf-8")
        stderr_path.write_text(process_output_text(exc.stderr, "timeout"), encoding="utf-8")
        return (
            RepeatResult(
                str(workflow),
                wid,
                repeat_index,
                None,
                elapsed_ms,
                "timeout",
                str(stdout_path),
                str(stderr_path),
            ),
            None,
        )
    except OSError as exc:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text(f"{exc.__class__.__name__}: {exc}\n", encoding="utf-8")
        return (
            RepeatResult(
                str(workflow),
                wid,
                repeat_index,
                None,
                elapsed_ms,
                "launch_error",
                str(stdout_path),
                str(stderr_path),
            ),
            None,
        )

    stdout_path.write_text(process_output_text(proc.stdout), encoding="utf-8")
    stderr_path.write_text(process_output_text(proc.stderr), encoding="utf-8")
    if proc.returncode != 0:
        status = "nonzero_exit"
        parsed = None
    else:
        try:
            parsed = json.loads(proc.stdout)
            status = "ok"
        except json.JSONDecodeError:
            parsed = None
            status = "invalid_json"
    return (
        RepeatResult(
            str(workflow),
            wid,
            repeat_index,
            proc.returncode,
            elapsed_ms,
            status,
            str(stdout_path),
            str(stderr_path),
        ),
        parsed,
    )


def write_timing_csv(path: Path, rows: list[RepeatResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=TIMING_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(dataclasses.asdict(row))


def write_findings_csv(path: Path, rows: list[dict[str, str]]) -> None:
    if not rows:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def summarize(
    workflows: list[Path],
    timing_rows: list[RepeatResult],
    finding_rows: list[dict[str, str]],
    config: RunConfig,
    normalization_errors: list[dict[str, str]] | None = None,
) -> dict:
    normalization_errors = normalization_errors or []
    by_workflow: dict[str, list[RepeatResult]] = {}
    for row in timing_rows:
        by_workflow.setdefault(row.workflow_path, []).append(row)

    workflow_medians = []
    workflow_statuses = {}
    for workflow_path, rows in by_workflow.items():
        ok_times = [row.elapsed_ms for row in rows if row.status == "ok"]
        workflow_statuses[workflow_path] = {
            "ok_repeats": len(ok_times),
            "failed_repeats": len(rows) - len(ok_times),
            "median_elapsed_ms": statistics.median(ok_times) if ok_times else None,
        }
        if ok_times:
            workflow_medians.append(statistics.median(ok_times))

    status_counts = Counter(row.status for row in timing_rows)
    weakness_counts = Counter(row["arxiv_weakness"] for row in finding_rows)
    rule_counts = Counter(row["rule_id"] for row in finding_rows)
    return {
        "report_kind": "taudit.arxiv_benchmark_run.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "claim_ceiling": "source-local benchmark evidence only",
        "command_contract": {
            "taudit_cmd": list(config.taudit_cmd),
            "platform": config.platform,
            "format": "json",
            "no_color": True,
            "repeat": config.repeat,
            "timeout_seconds": config.timeout_seconds,
            "rule_map": str(config.rule_map),
        },
        "workflow_count": len(workflows),
        "repeat_count": config.repeat,
        "status_counts": dict(sorted(status_counts.items())),
        "workflow_median_elapsed_ms": statistics.median(workflow_medians) if workflow_medians else None,
        "finding_count": len(finding_rows),
        "normalization_status": "error" if normalization_errors else "ok",
        "normalization_error_count": len(normalization_errors),
        "normalization_errors": normalization_errors,
        "by_weakness": dict(sorted(weakness_counts.items())),
        "by_rule": dict(sorted(rule_counts.items())),
        "workflow_statuses": workflow_statuses,
        "outputs": {
            "timings_csv": str(config.output_dir / "timings.csv"),
            "findings_csv": str(config.output_dir / "findings.csv"),
            "findings_jsonl": str(config.output_dir / "findings.jsonl"),
            "raw_dir": str(config.output_dir / "raw"),
        },
    }


def run_benchmark(
    workflows: list[Path],
    workflow_root: Path | None,
    config: RunConfig,
) -> dict:
    if config.repeat < 1:
        raise ValueError("repeat must be at least 1")
    config.output_dir.mkdir(parents=True, exist_ok=True)
    rule_map = load_rule_map(config.rule_map)

    timing_rows: list[RepeatResult] = []
    finding_rows: list[dict[str, str]] = []
    normalization_errors: list[dict[str, str]] = []
    first_ok_report_by_workflow: dict[str, dict] = {}

    for workflow in workflows:
        for repeat_index in range(1, config.repeat + 1):
            result, report = run_taudit_once(workflow, workflow_root, repeat_index, config)
            timing_rows.append(result)
            if report is not None and result.workflow_path not in first_ok_report_by_workflow:
                first_ok_report_by_workflow[result.workflow_path] = report

    for workflow_path, report in first_ok_report_by_workflow.items():
        try:
            finding_rows.extend(
                normalize_report(
                    report,
                    rule_map,
                    workflow_path=workflow_path,
                    include_out_of_scope=config.include_out_of_scope,
                )
            )
        except ArxivNormalizationError as exc:
            normalization_errors.append({"workflow_path": workflow_path, "error": str(exc)})

    write_timing_csv(config.output_dir / "timings.csv", timing_rows)
    write_findings_csv(config.output_dir / "findings.csv", finding_rows)
    write_jsonl(config.output_dir / "findings.jsonl", finding_rows)

    manifest = {
        "workflows": [str(path) for path in workflows],
        "taudit_cmd": list(config.taudit_cmd),
        "platform": config.platform,
        "repeat": config.repeat,
        "timeout_seconds": config.timeout_seconds,
    }
    (config.output_dir / "run-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    summary = summarize(workflows, timing_rows, finding_rows, config, normalization_errors)
    (config.output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--workflows-root", type=Path)
    source.add_argument("--workflow-list", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--rule-map", type=Path, default=Path("docs/research/arxiv-taudit-rule-map.csv"))
    parser.add_argument("--taudit", type=Path, default=Path("target/release/taudit.exe" if os.name == "nt" else "target/release/taudit"))
    parser.add_argument("--platform", default="github-actions")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--include-out-of-scope", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    workflows = discover_workflows(args.workflows_root, args.workflow_list, args.limit)
    if not workflows:
        print("error: no workflow files found", file=sys.stderr)
        return 2
    config = RunConfig(
        taudit_cmd=[str(args.taudit)],
        output_dir=args.output_dir,
        rule_map=args.rule_map,
        platform=args.platform,
        repeat=args.repeat,
        timeout_seconds=args.timeout,
        include_out_of_scope=args.include_out_of_scope,
    )
    try:
        summary = run_benchmark(workflows, args.workflows_root, config)
    except (ArxivNormalizationError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    expected_ok_repeats = len(workflows) * args.repeat
    failed_repeats = summary["status_counts"].get("ok", 0) != expected_ok_repeats
    failed_normalization = summary.get("normalization_error_count", 0) > 0
    return 1 if failed_repeats or failed_normalization else 0


if __name__ == "__main__":
    raise SystemExit(main())
