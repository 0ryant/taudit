#!/usr/bin/env python3
"""Normalize taudit JSON findings into the arXiv scanner-benchmark taxonomy.

The benchmark paper uses ten GitHub Actions weakness classes. This tool is
deliberately strict: every emitted taudit rule id must appear in the mapping
CSV, and every mapped class must be canonical or explicitly out of scope.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable, TextIO


TAXONOMY = {
    "AIW",
    "CFW",
    "EPW",
    "GRCW",
    "HGW",
    "IW",
    "KVCW",
    "PTW",
    "SEW",
    "UDW",
    "out_of_scope",
}

RAW_WEAKNESS_ALIASES = {
    "TMW": "PTW",
}

REQUIRED_MAP_COLUMNS = {
    "taudit_rule_id",
    "arxiv_weakness",
    "upstream_raw_weakness",
    "benchmark_scope",
    "enabled_by_default",
    "mapping_status",
    "rationale",
    "evidence",
}

OUTPUT_COLUMNS = [
    "workflow_path",
    "rule_id",
    "arxiv_weakness",
    "upstream_raw_weakness",
    "severity",
    "fingerprint",
    "line",
    "nodes_involved",
    "taudit_category",
    "source",
    "benchmark_scope",
    "mapping_status",
    "message",
]


class ArxivNormalizationError(RuntimeError):
    """Raised when a report cannot be normalized without losing evidence."""


@dataclasses.dataclass(frozen=True)
class RuleMapEntry:
    rule_id: str
    arxiv_weakness: str
    upstream_raw_weakness: str
    benchmark_scope: str
    enabled_by_default: str
    mapping_status: str
    rationale: str
    evidence: str


def canonical_weakness(value: str, *, field_name: str = "arXiv weakness") -> str:
    value = value.strip()
    if not value:
        raise ArxivNormalizationError(f"empty {field_name}")
    value = RAW_WEAKNESS_ALIASES.get(value, value)
    if value not in TAXONOMY:
        raise ArxivNormalizationError(f"unknown {field_name}: {value}")
    return value


def load_rule_map(path: Path) -> dict[str, RuleMapEntry]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle, strict=True)
            missing = REQUIRED_MAP_COLUMNS.difference(reader.fieldnames or [])
            if missing:
                cols = ", ".join(sorted(missing))
                raise ArxivNormalizationError(f"{path}: missing map columns: {cols}")
            entries: dict[str, RuleMapEntry] = {}
            for row_number, row in enumerate(reader, start=2):
                rule_id = (row.get("taudit_rule_id") or "").strip()
                if not rule_id:
                    raise ArxivNormalizationError(f"{path}:{row_number}: empty taudit_rule_id")
                if rule_id in entries:
                    raise ArxivNormalizationError(f"{path}:{row_number}: duplicate rule id {rule_id}")
                arxiv_weakness = canonical_weakness(row.get("arxiv_weakness") or "")
                raw = (row.get("upstream_raw_weakness") or arxiv_weakness).strip() or arxiv_weakness
                canonical_weakness(raw, field_name="upstream raw weakness")
                entries[rule_id] = RuleMapEntry(
                    rule_id=rule_id,
                    arxiv_weakness=arxiv_weakness,
                    upstream_raw_weakness=raw,
                    benchmark_scope=(row.get("benchmark_scope") or "").strip(),
                    enabled_by_default=(row.get("enabled_by_default") or "").strip(),
                    mapping_status=(row.get("mapping_status") or "").strip(),
                    rationale=(row.get("rationale") or "").strip(),
                    evidence=(row.get("evidence") or "").strip(),
                )
    except ArxivNormalizationError:
        raise
    except OSError as exc:
        raise ArxivNormalizationError(f"{path}: cannot read rule map: {exc}") from exc
    except csv.Error as exc:
        raise ArxivNormalizationError(f"{path}: invalid rule-map CSV: {exc}") from exc
    if not entries:
        raise ArxivNormalizationError(f"{path}: rule map contains no rows")
    return entries


def iter_report_paths(inputs: Iterable[Path]) -> list[Path]:
    paths: list[Path] = []
    for input_path in inputs:
        if input_path.is_dir():
            try:
                paths.extend(sorted(input_path.rglob("*.json")))
            except OSError as exc:
                raise ArxivNormalizationError(f"{input_path}: cannot scan input directory: {exc}") from exc
        else:
            paths.append(input_path)
    return paths


def finding_rule_id(finding: dict) -> str:
    rule_id = finding.get("rule_id") or finding.get("category")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ArxivNormalizationError("finding lacks rule_id/category")
    return rule_id.strip()


def finding_line(finding: dict) -> str:
    for key in ("line", "start_line"):
        value = finding.get(key)
        if isinstance(value, int):
            return str(value)
    location = finding.get("location")
    if isinstance(location, dict):
        value = location.get("line") or location.get("start_line")
        if isinstance(value, int):
            return str(value)
    return "unknown"


def normalize_report(
    report: dict,
    rule_map: dict[str, RuleMapEntry],
    *,
    workflow_path: str | None = None,
    include_out_of_scope: bool = False,
) -> list[dict[str, str]]:
    if not isinstance(report, dict):
        raise ArxivNormalizationError("report must be a JSON object")
    graph = report.get("graph", {})
    if graph is None:
        graph = {}
    if not isinstance(graph, dict):
        raise ArxivNormalizationError("report.graph must be an object")
    source = graph.get("source", {})
    if source is None:
        source = {}
    if not isinstance(source, dict):
        raise ArxivNormalizationError("report.graph.source must be an object")
    source_file = workflow_path or source.get("file") or "unknown"
    if not isinstance(source_file, str):
        source_file = "unknown"

    rows: list[dict[str, str]] = []
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ArxivNormalizationError("report.findings must be a list")

    for finding in findings:
        if not isinstance(finding, dict):
            raise ArxivNormalizationError("finding entry must be an object")
        rule_id = finding_rule_id(finding)
        entry = rule_map.get(rule_id)
        if entry is None:
            raise ArxivNormalizationError(f"no arXiv rule-map row for taudit rule {rule_id}")
        if entry.arxiv_weakness == "out_of_scope" and not include_out_of_scope:
            continue
        rows.append(
            {
                "workflow_path": source_file,
                "rule_id": rule_id,
                "arxiv_weakness": entry.arxiv_weakness,
                "upstream_raw_weakness": entry.upstream_raw_weakness,
                "severity": str(finding.get("severity", "")),
                "fingerprint": str(finding.get("fingerprint", "")),
                "line": finding_line(finding),
                "nodes_involved": json.dumps(
                    finding.get("nodes_involved", []),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                "taudit_category": str(finding.get("category", "")),
                "source": str(finding.get("source", "")),
                "benchmark_scope": entry.benchmark_scope,
                "mapping_status": entry.mapping_status,
                "message": str(finding.get("message", "")),
            }
        )
    return rows


def summarize_rows(rows: list[dict[str, str]]) -> dict:
    by_weakness = Counter(row["arxiv_weakness"] for row in rows)
    by_rule = Counter(row["rule_id"] for row in rows)
    workflows = sorted({row["workflow_path"] for row in rows})
    return {
        "row_count": len(rows),
        "workflow_count_with_findings": len(workflows),
        "by_weakness": dict(sorted(by_weakness.items())),
        "by_rule": dict(sorted(by_rule.items())),
        "workflows_with_findings": workflows,
    }


def write_jsonl(path: Path, rows: Iterable[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_csv_stdout(handle: TextIO, rows: list[dict[str, str]]) -> None:
    writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)


def normalize_paths(
    report_paths: Iterable[Path],
    rule_map: dict[str, RuleMapEntry],
    *,
    include_out_of_scope: bool = False,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for report_path in report_paths:
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ArxivNormalizationError(f"{report_path}: cannot read input: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ArxivNormalizationError(f"{report_path}: invalid JSON: {exc}") from exc
        rows.extend(
            normalize_report(
                report,
                rule_map,
                include_out_of_scope=include_out_of_scope,
            )
        )
    return rows


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="taudit JSON report file(s) or directories")
    parser.add_argument(
        "--rule-map",
        type=Path,
        default=Path("docs/research/arxiv-taudit-rule-map.csv"),
        help="CSV mapping taudit rule ids to arXiv weakness classes",
    )
    parser.add_argument("--output-csv", type=Path)
    parser.add_argument("--output-jsonl", type=Path)
    parser.add_argument("--summary-json", type=Path)
    parser.add_argument("--include-out-of-scope", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        rule_map = load_rule_map(args.rule_map)
        report_paths = iter_report_paths(args.inputs)
        if not report_paths:
            raise ArxivNormalizationError("no JSON report inputs found")
        rows = normalize_paths(
            report_paths,
            rule_map,
            include_out_of_scope=args.include_out_of_scope,
        )
        if args.output_csv:
            write_csv(args.output_csv, rows)
        else:
            write_csv_stdout(sys.stdout, rows)
        if args.output_jsonl:
            write_jsonl(args.output_jsonl, rows)
        if args.summary_json:
            args.summary_json.parent.mkdir(parents=True, exist_ok=True)
            args.summary_json.write_text(json.dumps(summarize_rows(rows), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except ArxivNormalizationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except csv.Error as exc:
        print(f"error: invalid CSV output: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
