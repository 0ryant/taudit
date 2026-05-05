#!/usr/bin/env python3
"""Run taudit against the harvested workflow corpus and summarize training signal.

This is a dogfood harness, not a benchmark harness. It looks for:
  - scan crashes / nonzero exits
  - invalid JSON output
  - graph completeness gap distribution
  - rule/finding distribution
  - coarse missing-rule candidate patterns in YAML text
  - currently unsupported platform buckets

Output:
  corpus/workflow-yaml-testbed/analysis/summary.json
  corpus/workflow-yaml-testbed/analysis/failures.jsonl
  corpus/workflow-yaml-testbed/analysis/rule_counts.json
  corpus/workflow-yaml-testbed/analysis/missing_rule_candidates.json
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import dataclasses
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path


DEFAULT_ROOT = Path("corpus/workflow-yaml-testbed")
PLATFORM_FLAGS = {
    "gha": "github-actions",
    "ado": "azure-devops",
    "gl": "gitlab",
    "bb": "bitbucket",
}


PATTERNS = {
    "curl_pipe_shell": re.compile(r"\b(curl|wget)\b[^\n|;&]*\|\s*(bash|sh|zsh|python|ruby|perl)\b", re.I),
    "docker_privileged": re.compile(r"\bdocker\s+run\b[^\n]*--privileged\b", re.I),
    "docker_sock_mount": re.compile(r"/var/run/docker\.sock", re.I),
    "npm_install_script_surface": re.compile(r"\b(npm|pnpm|yarn)\s+(install|ci)\b", re.I),
    "pip_unpinned_install": re.compile(r"\bpip(?:3)?\s+install\b(?![^\n]*(-r|--require-hashes))", re.I),
    "go_install_latest": re.compile(r"\bgo\s+install\s+[\w./:-]+@latest\b", re.I),
    "terraform_auto_approve": re.compile(r"\bterraform\s+apply\b[^\n]*\b-auto-approve\b", re.I),
    "kubectl_apply_remote": re.compile(r"\bkubectl\s+apply\b[^\n]*\b-f\s+https?://", re.I),
    "chmod_curl_exec": re.compile(r"\bchmod\s+\+x\b.*\n.*\b\./", re.I),
    "base64_pipe_shell": re.compile(r"\bbase64\s+(-d|--decode)\b[^\n|;&]*\|\s*(bash|sh|python|ruby|perl)\b", re.I),
    "secret_echo": re.compile(r"\becho\b[^\n]*(secret|token|password|passwd|apikey|api_key)", re.I),
    "aws_credentials_literal": re.compile(r"AKIA[0-9A-Z]{16}"),
}


@dataclasses.dataclass
class ScanResult:
    platform: str
    path: str
    ok: bool
    elapsed_ms: int
    findings: list[dict]
    completeness: str | None
    gaps: list[dict]
    error: str | None = None


def files_for(root: Path, platforms: list[str], limit_per_platform: int | None) -> list[tuple[str, Path]]:
    out: list[tuple[str, Path]] = []
    for platform in platforms:
        paths = sorted((root / platform).glob("*.y*ml"))
        if limit_per_platform is not None:
            paths = paths[:limit_per_platform]
        out.extend((platform, p) for p in paths)
    return out


def scan_one(binary: Path, platform: str, path: Path, timeout: int) -> ScanResult:
    flag = PLATFORM_FLAGS.get(platform)
    if flag is None:
        return ScanResult(platform, str(path), False, 0, [], None, [], "unsupported platform")
    started = time.time()
    cmd = [str(binary), "scan", str(path), "--platform", flag, "--format", "json", "--no-color"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ScanResult(platform, str(path), False, int((time.time() - started) * 1000), [], None, [], "timeout")
    elapsed = int((time.time() - started) * 1000)
    if proc.returncode != 0:
        return ScanResult(platform, str(path), False, elapsed, [], None, [], f"exit={proc.returncode}: {proc.stderr[:2000]}")
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError as err:
        return ScanResult(platform, str(path), False, elapsed, [], None, [], f"json error: {err}: {proc.stdout[:500]}")
    summary = doc.get("summary", {})
    return ScanResult(
        platform=platform,
        path=str(path),
        ok=True,
        elapsed_ms=elapsed,
        findings=doc.get("findings", []),
        completeness=summary.get("completeness"),
        gaps=summary.get("completeness_gaps", []),
    )


def text_patterns(paths: list[tuple[str, Path]]) -> dict[str, dict[str, int]]:
    counts: dict[str, collections.Counter[str]] = {name: collections.Counter() for name in PATTERNS}
    examples: dict[str, dict[str, list[str] | int]] = {}
    for platform, path in paths:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for name, pattern in PATTERNS.items():
            if pattern.search(text):
                counts[name][platform] += 1
                examples.setdefault(name, {"total": 0, "examples": []})
                examples[name]["total"] = int(examples[name]["total"]) + 1
                ex = examples[name]["examples"]
                if isinstance(ex, list) and len(ex) < 10:
                    ex.append(str(path))
    return examples


def write_json(path: Path, obj: object) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/taudit"))
    parser.add_argument("--platform", action="append", choices=["gha", "ado", "gl", "bb"])
    parser.add_argument("--limit-per-platform", type=int)
    parser.add_argument("--jobs", type=int, default=max(2, (os.cpu_count() or 4) // 2))
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument(
        "--allow-failure-substring",
        action="append",
        default=[],
        help="Treat a scan failure as quarantined when the corpus path contains this substring.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    platforms = args.platform or ["gha", "ado", "gl"]
    corpus_files = files_for(args.root, platforms, args.limit_per_platform)
    analysis_dir = args.root / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "root": str(args.root),
        "binary": str(args.binary),
        "requested_platforms": platforms,
        "file_count": len(corpus_files),
        "scan_ok": 0,
        "scan_failed": 0,
        "scan_allowed_failed": 0,
        "by_platform": {},
        "completeness": {},
        "gap_kinds": {},
        "slowest": [],
    }
    rule_counts: collections.Counter[str] = collections.Counter()
    category_counts: collections.Counter[str] = collections.Counter()
    failures_path = analysis_dir / "failures.jsonl"
    if failures_path.exists():
        failures_path.unlink()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = [ex.submit(scan_one, args.binary, platform, path, args.timeout) for platform, path in corpus_files]
        for i, fut in enumerate(concurrent.futures.as_completed(futs), 1):
            result = fut.result()
            summary["by_platform"].setdefault(result.platform, {"ok": 0, "failed": 0, "files": 0})
            summary["by_platform"][result.platform]["files"] += 1
            if result.ok:
                summary["scan_ok"] += 1
                summary["by_platform"][result.platform]["ok"] += 1
                summary["completeness"][result.completeness or "unknown"] = summary["completeness"].get(result.completeness or "unknown", 0) + 1
                for gap in result.gaps:
                    kind = str(gap.get("kind", "unknown"))
                    summary["gap_kinds"][kind] = summary["gap_kinds"].get(kind, 0) + 1
                for finding in result.findings:
                    rule_counts[str(finding.get("rule_id", "unknown"))] += 1
                    category_counts[str(finding.get("category", "unknown"))] += 1
                summary["slowest"].append({"path": result.path, "platform": result.platform, "elapsed_ms": result.elapsed_ms})
                summary["slowest"] = sorted(summary["slowest"], key=lambda x: x["elapsed_ms"], reverse=True)[:20]
            else:
                allowed = any(s in result.path for s in args.allow_failure_substring)
                if allowed:
                    summary["scan_allowed_failed"] += 1
                    summary["by_platform"][result.platform].setdefault("allowed_failed", 0)
                    summary["by_platform"][result.platform]["allowed_failed"] += 1
                else:
                    summary["scan_failed"] += 1
                    summary["by_platform"][result.platform]["failed"] += 1
                with failures_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(dataclasses.asdict(result), sort_keys=True) + "\n")
            if i % 100 == 0:
                print(f"scanned {i}/{len(corpus_files)} ok={summary['scan_ok']} failed={summary['scan_failed']}", flush=True)

    missing_rule_candidates = text_patterns(corpus_files)
    write_json(analysis_dir / "summary.json", summary)
    write_json(analysis_dir / "rule_counts.json", {"rules": rule_counts, "categories": category_counts})
    write_json(analysis_dir / "missing_rule_candidates.json", missing_rule_candidates)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["scan_failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
