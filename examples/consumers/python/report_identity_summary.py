#!/usr/bin/env python3
"""Compatibility reference consumer for taudit report and CloudEvents JSON.

This is intentionally small and stdlib-only. It is not a schema validator; it
shows how a downstream tool can read known v1 completeness and identity fields
while ignoring additive metadata and extension fields it does not understand.

Usage:
    python3 report_identity_summary.py contracts/examples/clean-report.json
    python3 report_identity_summary.py contracts/examples/over-privileged-finding.cloudevent.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


JsonObject = dict[str, Any]


class ConsumerError(ValueError):
    """Raised when the input is not a taudit report or CloudEvent example."""


def _as_object(value: Any) -> JsonObject:
    return value if isinstance(value, dict) else {}


def _first_finding_identity(findings: Any) -> list[JsonObject]:
    if not isinstance(findings, list) or not findings:
        return []

    first = _as_object(findings[0])
    return [
        {
            "index": 0,
            "severity": first.get("severity"),
            "category": first.get("category"),
            "rule_id": first.get("rule_id"),
            "fingerprint": first.get("fingerprint"),
            "suppression_key": first.get("suppression_key"),
            "finding_group_id": first.get("finding_group_id"),
            "source": first.get("source"),
        }
    ]


def _gap_kinds_from(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    kinds: list[str] = []
    for item in value:
        if isinstance(item, str):
            kinds.append(item)
        elif isinstance(item, dict) and isinstance(item.get("kind"), str):
            kinds.append(item["kind"])
    return kinds


def summarize_report(doc: JsonObject) -> JsonObject:
    graph = _as_object(doc.get("graph"))
    source = _as_object(graph.get("source"))
    summary = _as_object(doc.get("summary"))
    findings = doc.get("findings")

    return {
        "kind": "report",
        "schema_version": doc.get("schema_version"),
        "schema_uri": doc.get("schema_uri"),
        "source_file": source.get("file"),
        "graph_completeness": graph.get("completeness"),
        "graph_completeness_gap_kinds": _gap_kinds_from(graph.get("completeness_gap_kinds")),
        "summary_completeness": summary.get("completeness"),
        "summary_completeness_gap_kinds": _gap_kinds_from(
            summary.get("completeness_gap_kinds") or summary.get("completeness_gaps")
        ),
        "total_findings": summary.get("total_findings"),
        "finding_identities": _first_finding_identity(findings),
    }


def summarize_cloudevent(doc: JsonObject) -> JsonObject:
    data = _as_object(doc.get("data"))

    return {
        "kind": "cloudevent",
        "specversion": doc.get("specversion"),
        "event_id": doc.get("id"),
        "event_type": doc.get("type"),
        "subject": doc.get("subject"),
        "completeness": doc.get("tauditcompleteness"),
        "completeness_gap_kinds": _gap_kinds_from(doc.get("tauditcompletenessgaps")),
        "severity": data.get("severity"),
        "category": data.get("category"),
        "identity": {
            "rule_id": doc.get("tauditruleid"),
            "fingerprint": doc.get("tauditfindingfingerprint"),
            "suppression_key": doc.get("tauditsuppressionkey"),
            "finding_group_id": doc.get("tauditfindinggroup"),
            "pipeline_id": doc.get("tauditpipelineid"),
            "scan_run_id": doc.get("tauditscanrunid"),
            "correlation_id": doc.get("correlationid"),
            "platform": doc.get("tauditplatform"),
        },
        "provenance": {
            "repo": doc.get("provenancerepo"),
            "producer": doc.get("provenanceproducer"),
            "version": doc.get("provenanceversion"),
            "kind": doc.get("provenancekind"),
        },
    }


def summarize_document(doc: JsonObject) -> JsonObject:
    if doc.get("schema_version") == "1.0.0" and "graph" in doc and "summary" in doc:
        return summarize_report(doc)
    if doc.get("specversion") == "1.0" and doc.get("source") == "taudit":
        return summarize_cloudevent(doc)
    raise ConsumerError("expected a taudit report JSON object or taudit CloudEvent JSON object")


def _load_json_documents(path: Path) -> list[JsonObject]:
    text = path.read_text(encoding="utf-8")
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        docs: list[JsonObject] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ConsumerError(f"{path}:{line_no}: invalid JSON line: {exc.msg}") from exc
            if not isinstance(item, dict):
                raise ConsumerError(f"{path}:{line_no}: expected JSON object")
            docs.append(item)
        return docs

    if isinstance(loaded, dict):
        return [loaded]
    if isinstance(loaded, list):
        objects: list[JsonObject] = []
        for index, item in enumerate(loaded):
            if not isinstance(item, dict):
                raise ConsumerError(f"{path}: item {index}: expected JSON object")
            objects.append(item)
        return objects
    raise ConsumerError(f"{path}: expected JSON object, JSON array, or JSONL objects")


def summarize_path(path: str | Path) -> list[JsonObject]:
    return [summarize_document(doc) for doc in _load_json_documents(Path(path))]


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(
            f"usage: {argv[0] if argv else 'report_identity_summary.py'} <report-or-cloudevent.json> [...]",
            file=sys.stderr,
        )
        return 2

    try:
        for raw_path in argv[1:]:
            for summary in summarize_path(raw_path):
                print(json.dumps(summary, sort_keys=True))
    except (OSError, ConsumerError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
