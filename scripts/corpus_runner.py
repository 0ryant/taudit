#!/usr/bin/env python3
"""Validate and run the taudit real-input corpus manifest."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "corpus-manifest.v1.json"
REPORT_SCHEMA_PATH = ROOT / "contracts" / "schemas" / "taudit-report.schema.json"

COMPLETENESS = ("complete", "failure", "partial", "unknown")
OBSERVED_COMPLETENESS = ("complete", "partial", "unknown")
GAP_KINDS = ("expression", "opaque", "structural", "unknown")
KNOWN_GAP_KINDS = {"expression", "structural", "opaque"}
PROVIDERS = {
    "github_actions": "taudit-parse-gha",
    "azure_pipelines": "taudit-parse-ado",
    "gitlab_ci": "taudit-parse-gitlab",
    "bitbucket_pipelines": "taudit-parse-bitbucket",
}
CACHE_MODES = {"tracked_copy", "fetch_cache", "external_reference"}
LICENSE_BASES = {
    "repo_license",
    "public_repository_terms",
    "explicit_permission",
    "internal_fixture",
    "unknown_pending_review",
}
SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
MANIFEST_SCHEMA_VERSION_RE = re.compile(r"^1\.[0-9]+\.[0-9]+$")


class CorpusManifestError(RuntimeError):
    """Raised when a corpus manifest does not match the v1 contract."""


@dataclass(frozen=True)
class RunConfig:
    taudit: str = "taudit"
    timeout_seconds: float = 30.0
    report_schema: pathlib.Path | None = None


def load_json(path: pathlib.Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise CorpusManifestError(f"{path}: failed to read JSON: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CorpusManifestError(f"{path}: invalid JSON: {exc}") from exc


def load_manifest(path: pathlib.Path) -> dict[str, Any]:
    manifest = load_json(path)
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: Any) -> None:
    require_object(manifest, "manifest")
    reject_extra(manifest, {"$schema", "schema_version", "name", "description", "entries"}, "manifest")
    schema_version = require_string(manifest, "schema_version", "manifest")
    if MANIFEST_SCHEMA_VERSION_RE.fullmatch(schema_version) is None:
        raise CorpusManifestError("manifest.schema_version must match 1.x.y")
    require_string(manifest, "name", "manifest")
    if "description" in manifest and not isinstance(manifest["description"], str):
        raise CorpusManifestError("manifest.description must be a string")
    entries = require_array(manifest, "entries", "manifest")
    if not entries:
        raise CorpusManifestError("manifest.entries must contain at least one entry")

    seen_ids: set[str] = set()
    for index, raw_entry in enumerate(entries):
        validate_entry(raw_entry, f"entries[{index}]", seen_ids)


def validate_entry(entry: Any, path: str, seen_ids: set[str]) -> None:
    require_object(entry, path)
    reject_extra(entry, {"id", "provider", "source", "license", "expected", "local", "tags"}, path)
    entry_id = require_string(entry, "id", path)
    if ID_RE.fullmatch(entry_id) is None:
        raise CorpusManifestError(f"{path}.id must be a stable lowercase id")
    if entry_id in seen_ids:
        raise CorpusManifestError(f"{path}.id duplicates {entry_id!r}")
    seen_ids.add(entry_id)

    provider = require_string(entry, "provider", path)
    if provider not in PROVIDERS:
        raise CorpusManifestError(f"{path}.provider must be one of {sorted(PROVIDERS)}")

    validate_source(require_key(entry, "source", path), f"{path}.source")
    validate_license(require_key(entry, "license", path), f"{path}.license")
    parser = validate_expected(require_key(entry, "expected", path), f"{path}.expected")
    if parser != PROVIDERS[provider]:
        raise CorpusManifestError(
            f"{path}.expected.parser {parser!r} does not match provider {provider!r}"
        )
    validate_local(require_key(entry, "local", path), f"{path}.local")
    validate_tags(require_key(entry, "tags", path), f"{path}.tags")


def validate_source(source: Any, path: str) -> None:
    require_object(source, path)
    reject_extra(source, {"url", "commit", "digest", "path", "pulled_at"}, path)
    url = require_string(source, "url", path)
    if not (url.startswith("https://") or url.startswith("http://")):
        raise CorpusManifestError(f"{path}.url must be an http(s) URL")
    require_string(source, "path", path)
    commit = source.get("commit")
    digest = source.get("digest")
    if commit is None and digest is None:
        raise CorpusManifestError(f"{path} must include commit or digest")
    if commit is not None and (not isinstance(commit, str) or SHA_RE.fullmatch(commit) is None):
        raise CorpusManifestError(f"{path}.commit must be a 7-64 character hex SHA")
    if digest is not None and (not isinstance(digest, str) or DIGEST_RE.fullmatch(digest) is None):
        raise CorpusManifestError(f"{path}.digest must be sha256:<64 lowercase hex>")
    if "pulled_at" in source and not isinstance(source["pulled_at"], str):
        raise CorpusManifestError(f"{path}.pulled_at must be a string")


def validate_license(license_info: Any, path: str) -> None:
    require_object(license_info, path)
    reject_extra(license_info, {"basis", "name", "url", "notes"}, path)
    basis = require_string(license_info, "basis", path)
    if basis not in LICENSE_BASES:
        raise CorpusManifestError(f"{path}.basis must be one of {sorted(LICENSE_BASES)}")
    require_string(license_info, "name", path)
    for optional in ("url", "notes"):
        if optional in license_info and not isinstance(license_info[optional], str):
            raise CorpusManifestError(f"{path}.{optional} must be a string")


def validate_expected(expected: Any, path: str) -> str:
    require_object(expected, path)
    reject_extra(expected, {"parser", "completeness", "gap_kinds", "gap_reasons"}, path)
    parser = require_string(expected, "parser", path)
    if parser not in set(PROVIDERS.values()):
        raise CorpusManifestError(f"{path}.parser must be a known taudit parser crate")
    completeness = require_string(expected, "completeness", path)
    if completeness not in OBSERVED_COMPLETENESS:
        raise CorpusManifestError(f"{path}.completeness must be one of {list(OBSERVED_COMPLETENESS)}")
    validate_gap_kind_array(require_key(expected, "gap_kinds", path), f"{path}.gap_kinds")
    if "gap_reasons" in expected:
        reasons = require_array(expected, "gap_reasons", path)
        for index, reason in enumerate(reasons):
            if not isinstance(reason, str) or not reason:
                raise CorpusManifestError(f"{path}.gap_reasons[{index}] must be a non-empty string")
    return parser


def validate_local(local: Any, path: str) -> None:
    require_object(local, path)
    reject_extra(local, {"path", "cache"}, path)
    require_string(local, "path", path)
    cache = require_key(local, "cache", path)
    require_object(cache, f"{path}.cache")
    reject_extra(cache, {"mode", "key", "digest", "notes"}, f"{path}.cache")
    mode = require_string(cache, "mode", f"{path}.cache")
    if mode not in CACHE_MODES:
        raise CorpusManifestError(f"{path}.cache.mode must be one of {sorted(CACHE_MODES)}")
    if "key" in cache:
        require_string(cache, "key", f"{path}.cache")
    if "digest" in cache:
        digest = require_string(cache, "digest", f"{path}.cache")
        if DIGEST_RE.fullmatch(digest) is None:
            raise CorpusManifestError(f"{path}.cache.digest must be sha256:<64 lowercase hex>")
    if "notes" in cache and not isinstance(cache["notes"], str):
        raise CorpusManifestError(f"{path}.cache.notes must be a string")


def validate_tags(tags: Any, path: str) -> None:
    if not isinstance(tags, list):
        raise CorpusManifestError(f"{path} must be an array")
    if not tags:
        raise CorpusManifestError(f"{path} must contain at least one tag")
    seen: set[str] = set()
    for index, tag in enumerate(tags):
        if not isinstance(tag, str) or not tag:
            raise CorpusManifestError(f"{path}[{index}] must be a non-empty string")
        if tag in seen:
            raise CorpusManifestError(f"{path}[{index}] duplicates tag {tag!r}")
        seen.add(tag)


def validate_gap_kind_array(value: Any, path: str) -> None:
    if not isinstance(value, list):
        raise CorpusManifestError(f"{path} must be an array")
    seen: set[str] = set()
    for index, kind in enumerate(value):
        if kind not in KNOWN_GAP_KINDS:
            raise CorpusManifestError(f"{path}[{index}] must be expression, structural, or opaque")
        if kind in seen:
            raise CorpusManifestError(f"{path}[{index}] duplicates gap kind {kind!r}")
        seen.add(kind)


def require_key(obj: dict[str, Any], key: str, path: str) -> Any:
    if key not in obj:
        raise CorpusManifestError(f"{path}.{key} is required")
    return obj[key]


def require_object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CorpusManifestError(f"{path} must be an object")
    return value


def require_array(obj: dict[str, Any], key: str, path: str) -> list[Any]:
    value = require_key(obj, key, path)
    if not isinstance(value, list):
        raise CorpusManifestError(f"{path}.{key} must be an array")
    return value


def require_string(obj: dict[str, Any], key: str, path: str) -> str:
    value = require_key(obj, key, path)
    if not isinstance(value, str) or not value:
        raise CorpusManifestError(f"{path}.{key} must be a non-empty string")
    return value


def reject_extra(obj: dict[str, Any], allowed: set[str], path: str) -> None:
    extra = sorted(set(obj) - allowed)
    if extra:
        raise CorpusManifestError(f"{path} has unsupported keys: {', '.join(extra)}")


def summarize_expected(manifest: dict[str, Any], manifest_path: pathlib.Path) -> dict[str, Any]:
    summary = new_summary("expected", manifest_path)
    for entry in sorted_entries(manifest):
        expected = entry["expected"]
        status = expected["completeness"]
        gap_kinds = list(expected["gap_kinds"])
        add_result(
            summary,
            {
                "id": entry["id"],
                "provider": entry["provider"],
                "parser": expected["parser"],
                "status": status,
                "gap_kinds": gap_kinds,
                "source_url": entry["source"]["url"],
                "local_path": entry["local"]["path"],
            },
            status,
            gap_kinds,
        )
    finish_summary(summary)
    return summary


def run_manifest(
    manifest: dict[str, Any],
    manifest_path: pathlib.Path,
    config: RunConfig,
) -> dict[str, Any]:
    if config.timeout_seconds <= 0:
        raise CorpusManifestError("timeout-seconds must be positive")
    summary = new_summary("run", manifest_path)
    for entry in sorted_entries(manifest):
        result = scan_entry(entry, manifest_path, config)
        add_result(summary, result, result["status"], result.get("gap_kinds", []))
    finish_summary(summary)
    return summary


def scan_entry(
    entry: dict[str, Any],
    manifest_path: pathlib.Path,
    config: RunConfig,
) -> dict[str, Any]:
    local_path = resolve_local_path(entry["local"]["path"], manifest_path)
    base = {
        "id": entry["id"],
        "provider": entry["provider"],
        "parser": entry["expected"]["parser"],
        "source_url": entry["source"]["url"],
        "local_path": str(local_path),
    }
    if not local_path.exists():
        return failure_result(base, "missing_local_path", f"{local_path} does not exist")

    command = [config.taudit, "scan", "--format", "json", "--no-color", str(local_path)]
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=config.timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return failure_result(base, "timeout", f"scan exceeded {config.timeout_seconds:g}s")
    except OSError as exc:
        return failure_result(base, "spawn_error", str(exc))

    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        kind = "parser_panic" if "panic" in stderr.lower() else "exit_code"
        detail = stderr or f"taudit exited {completed.returncode}"
        return failure_result(base, kind, detail)

    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return failure_result(base, "invalid_json", str(exc))

    schema_error = validate_report_schema_if_requested(report, config.report_schema)
    if schema_error is not None:
        return failure_result(base, schema_error[0], schema_error[1])

    completeness = extract_completeness(report)
    if completeness not in OBSERVED_COMPLETENESS:
        return failure_result(base, "missing_completeness", "scan JSON omitted graph completeness")

    gap_kinds = extract_gap_kinds(report)
    base.update(
        {
            "status": completeness,
            "gap_kinds": gap_kinds,
            "findings": extract_findings_count(report),
        }
    )
    return base


def validate_report_schema_if_requested(
    report: dict[str, Any],
    schema_path: pathlib.Path | None,
) -> tuple[str, str] | None:
    if schema_path is None:
        return None
    try:
        import jsonschema
    except ImportError:
        return ("report_schema_validator_unavailable", "install jsonschema to validate scan reports")
    try:
        schema = load_json(schema_path)
        jsonschema.validate(instance=report, schema=schema)
    except Exception as exc:  # jsonschema surfaces several validation exception types.
        return ("report_schema_invalid", str(exc))
    return None


def resolve_local_path(path_text: str, manifest_path: pathlib.Path) -> pathlib.Path:
    path = pathlib.Path(path_text)
    if path.is_absolute():
        return path
    root_candidate = (ROOT / path).resolve()
    if root_candidate.exists():
        return root_candidate
    return (manifest_path.parent / path).resolve()


def extract_completeness(report: dict[str, Any]) -> str | None:
    graph = report.get("graph")
    if isinstance(graph, dict) and isinstance(graph.get("completeness"), str):
        return graph["completeness"]
    summary = report.get("summary")
    if isinstance(summary, dict) and isinstance(summary.get("completeness"), str):
        return summary["completeness"]
    return None


def extract_gap_kinds(report: dict[str, Any]) -> list[str]:
    graph = report.get("graph")
    if isinstance(graph, dict):
        gap_kinds = graph.get("completeness_gap_kinds")
        if isinstance(gap_kinds, list):
            return [kind if kind in KNOWN_GAP_KINDS else "unknown" for kind in gap_kinds]
    summary = report.get("summary")
    if isinstance(summary, dict):
        direct = summary.get("completeness_gap_kinds")
        if isinstance(direct, list):
            return [kind if kind in KNOWN_GAP_KINDS else "unknown" for kind in direct]
        structured = summary.get("completeness_gaps")
        if isinstance(structured, list):
            kinds: list[str] = []
            for gap in structured:
                if isinstance(gap, dict):
                    kind = gap.get("kind")
                    kinds.append(kind if kind in KNOWN_GAP_KINDS else "unknown")
            return kinds
    return []


def extract_findings_count(report: dict[str, Any]) -> int:
    summary = report.get("summary")
    if isinstance(summary, dict) and isinstance(summary.get("total_findings"), int):
        return summary["total_findings"]
    findings = report.get("findings")
    if isinstance(findings, list):
        return len(findings)
    return 0


def failure_result(base: dict[str, Any], kind: str, detail: str) -> dict[str, Any]:
    result = dict(base)
    result.update(
        {
            "status": "failure",
            "gap_kinds": [],
            "findings": 0,
            "failure_kind": kind,
            "failure_detail": detail,
        }
    )
    return result


def sorted_entries(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(manifest["entries"], key=lambda item: item["id"])


def new_summary(mode: str, manifest_path: pathlib.Path) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "mode": mode,
        "manifest_path": str(manifest_path),
        "entry_count": 0,
        "histograms": {
            "completeness": {key: 0 for key in COMPLETENESS},
            "gap_kinds": {key: 0 for key in GAP_KINDS},
            "providers": {},
            "failure_kinds": {},
        },
        "entries": [],
    }


def add_result(
    summary: dict[str, Any],
    result: dict[str, Any],
    status: str,
    gap_kinds: list[str],
) -> None:
    status_key = status if status in COMPLETENESS else "unknown"
    summary["histograms"]["completeness"][status_key] += 1
    provider_histogram = summary["histograms"]["providers"].setdefault(
        result["provider"],
        {key: 0 for key in COMPLETENESS},
    )
    provider_histogram[status_key] += 1
    for kind in gap_kinds:
        kind_key = kind if kind in KNOWN_GAP_KINDS else "unknown"
        summary["histograms"]["gap_kinds"][kind_key] += 1
    if status_key == "failure":
        failure_kind = result.get("failure_kind", "unknown")
        summary["histograms"]["failure_kinds"][failure_kind] = (
            summary["histograms"]["failure_kinds"].get(failure_kind, 0) + 1
        )
    summary["entries"].append(result)


def finish_summary(summary: dict[str, Any]) -> None:
    summary["entry_count"] = len(summary["entries"])
    summary["entries"].sort(key=lambda item: item["id"])
    summary["histograms"]["providers"] = {
        key: summary["histograms"]["providers"][key]
        for key in sorted(summary["histograms"]["providers"])
    }
    summary["histograms"]["failure_kinds"] = {
        key: summary["histograms"]["failure_kinds"][key]
        for key in sorted(summary["histograms"]["failure_kinds"])
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        required=True,
        help="Path to a corpus manifest JSON file.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "validate",
        help="Validate the manifest and emit expected completeness/gap histograms.",
    )

    run_parser = subparsers.add_parser(
        "run",
        help="Run taudit against local corpus files and emit observed histograms.",
    )
    run_parser.add_argument(
        "--taudit",
        default="taudit",
        help="taudit executable to run. Defaults to PATH lookup.",
    )
    run_parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=30.0,
        help="Per-entry scan timeout in seconds.",
    )
    run_parser.add_argument(
        "--report-schema",
        type=pathlib.Path,
        default=None,
        help="Optional JSON schema used to validate each scan report.",
    )
    return parser


def emit_json(document: dict[str, Any]) -> None:
    json.dump(document, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        manifest_path = args.manifest.resolve()
        manifest = load_manifest(manifest_path)
        if args.command == "validate":
            emit_json(summarize_expected(manifest, manifest_path))
            return 0
        if args.command == "run":
            if args.timeout_seconds <= 0:
                raise CorpusManifestError("timeout-seconds must be positive")
            report_schema = args.report_schema.resolve() if args.report_schema else None
            summary = run_manifest(
                manifest,
                manifest_path,
                RunConfig(
                    taudit=args.taudit,
                    timeout_seconds=args.timeout_seconds,
                    report_schema=report_schema,
                ),
            )
            emit_json(summary)
            return 1 if summary["histograms"]["completeness"]["failure"] else 0
        raise CorpusManifestError(f"unknown command: {args.command}")
    except CorpusManifestError as exc:
        print(f"corpus runner error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
