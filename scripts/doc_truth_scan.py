from __future__ import annotations

import argparse
import fnmatch
import json
import pathlib
import re
import sys
from dataclasses import asdict, dataclass
from typing import Iterable, Sequence


DEFAULT_ROOT_FILES = ("README.md", "USERGUIDE.md", "TODOS.md", "CHANGELOG.md")
DEFAULT_DOC_GLOB = "docs/**/*.md"
DEFAULT_EXCLUDES = (
    "docs/adr/**",
    "docs/research/**",
    "docs/proof/**",
)


@dataclass(frozen=True)
class TruthRule:
    code: str
    severity: str
    message: str
    patterns: tuple[re.Pattern[str], ...]
    allow_context: tuple[re.Pattern[str], ...]


@dataclass(frozen=True)
class TruthIssue:
    code: str
    severity: str
    path: str
    line: int
    column: int
    match: str
    message: str
    text: str


@dataclass(frozen=True)
class ScanReport:
    status: str
    files_scanned: int
    issue_count: int
    issues: list[TruthIssue]

    def to_jsonable(self) -> dict[str, object]:
        return {
            "status": self.status,
            "files_scanned": self.files_scanned,
            "issue_count": self.issue_count,
            "issues": [asdict(issue) for issue in self.issues],
        }


def compile_re(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


PROOF_OR_PLANNED = (
    compile_re(r"\b(?:planned|pending|future|proposed|contract|proof[- ]gated|receipt|proof state|proof-state)\b"),
    compile_re(r"\b(?:use in|filename|show:|prerequisites|capture note|asset slot|screenshot slot|shot list)\b"),
    compile_re(r"\b(?:until|before|after)\b.{0,80}\b(?:receipt|proof|gate|readback)\b"),
    compile_re(r"\b(?:only\s+after|after)\b.{0,100}\b(?:hosted|smoke|passes|receipt|proof|gate|readback)\b"),
    compile_re(r"\b(?:not|no|without|does not|do not)\b.{0,80}\b(?:published|installable|listed|available|prove|claim)\b"),
)

GATED_STABLE = (
    compile_re(r"\b(?:blocked|pending|planned|prerelease|rc|release candidate|soak|gate|gated|until|before)\b"),
    compile_re(r"\bstable promotion\b"),
    compile_re(r"\bnot\b.{0,80}\b(?:stable|production-ready|promoted|release-ready)\b"),
)

EVIDENCE_BOUND_COMPLETENESS = (
    compile_re(r"\b(?:partial|unknown|gap|gaps|corpus|matrix|fixture|evidence|measured|tranche|where supported)\b"),
    compile_re(r"\b(?:only when|unless|until|before|not|avoid)\b"),
)

HISTORICAL_VERSION = (
    compile_re(r"\b(?:historical|previous|old|incident|failure mode|backcompat|backward compatible)\b"),
    compile_re(r"\bfirst release candidate\b"),
    compile_re(r"\b(?:superseded|supersedes|released|published|promotes|unaffected|replace|replaced|stale)\b"),
    compile_re(r"\b20[0-9]{2}-[0-9]{2}-[0-9]{2}\b"),
)


RULES: tuple[TruthRule, ...] = (
    TruthRule(
        code="marketplace-proof-overclaim",
        severity="error",
        message="Marketplace or hosted adoption claim needs proof-gated/planned wording or a receipt.",
        patterns=(
            compile_re(
                r"\b(?:github\s+marketplace|marketplace|vs\s+code|visual\s+studio\s+marketplace|azure\s+devops)\b"
                r".{0,100}\b(?:published|listed|installable|available|hosted\s+smoke|backlink|v1\s+tag|moving\s+v1)\b"
            ),
            compile_re(
                r"\b(?:published|listed|installable|available|hosted\s+smoke|backlink)\b"
                r".{0,100}\b(?:github\s+marketplace|marketplace|vs\s+code|visual\s+studio\s+marketplace|azure\s+devops)\b"
            ),
            compile_re(
                r"\b(?:github\s+marketplace|marketplace|vs\s+code|visual\s+studio\s+marketplace|azure\s+devops)\b"
                r".{0,100}\blisting\b.{0,60}\b(?:exists|live|published|available|installable|ready)\b"
            ),
        ),
        allow_context=PROOF_OR_PLANNED,
    ),
    TruthRule(
        code="stable-rc-overclaim",
        severity="error",
        message="v1.2.0 stable or production-ready claims must be framed as gated/pending until promotion.",
        patterns=(
            compile_re(r"\bv1\.2\.0\b.{0,100}\b(?:stable|production-ready|release-ready|promoted|current\s+stable)\b"),
            compile_re(r"\b(?:stable|production-ready|release-ready|promoted|current\s+stable)\b.{0,100}\bv1\.2\.0\b"),
        ),
        allow_context=GATED_STABLE,
    ),
    TruthRule(
        code="parser-completeness-overclaim",
        severity="error",
        message="Parser/provider completeness claims need matrix, corpus, partiality, or evidence-bound wording.",
        patterns=(
            compile_re(
                r"\b(?:complete|full|fully)\s+(?:support|coverage|parser|platform|provider|providers|github actions|azure pipelines|gitlab|bitbucket)\b"
            ),
            compile_re(
                r"\b(?:parser|platform|provider|providers|github actions|azure pipelines|gitlab|bitbucket)\b"
                r".{0,80}\b(?:complete|fully supported|full support|complete support)\b"
            ),
            compile_re(r"\b(?:all|four|three)\s+(?:platforms|providers)\b.{0,100}\b(?:complete|supported|covered)\b"),
        ),
        allow_context=EVIDENCE_BOUND_COMPLETENESS,
    ),
    TruthRule(
        code="conformance-overclaim",
        severity="error",
        message="Full conformance language must name the harness/gate state or pending proof.",
        patterns=(
            compile_re(r"\b(?:full|complete)\s+conformance\b"),
            compile_re(r"\bADR\s+0020\b.{0,100}\b(?:has\s+passed|passed|complete|full\s+conformance)\b"),
        ),
        allow_context=(
            compile_re(r"\b(?:pending|incomplete|gate|harness|stable promotion|blocked|until|before|not)\b"),
        ),
    ),
    TruthRule(
        code="stale-install-version",
        severity="error",
        message="Stale cargo install version pin should be refreshed or explicitly historical.",
        patterns=(compile_re(r"\bcargo\s+install\s+taudit\b.{0,100}--version\s+1\.0\.12\b"),),
        allow_context=HISTORICAL_VERSION,
    ),
    TruthRule(
        code="stale-current-cycle-version",
        severity="error",
        message="v1.1.0 current-cycle wording is stale for the v1.2 RC lane.",
        patterns=(
            compile_re(r"\bv1\.1\.0(?:-rc\.1)?\b.{0,100}\b(?:current|this\s+cycle|latest|release candidate|stable promotion)\b"),
            compile_re(r"\b(?:current|this\s+cycle|latest|release candidate|stable promotion)\b.{0,100}\bv1\.1\.0(?:-rc\.1)?\b"),
        ),
        allow_context=HISTORICAL_VERSION,
    ),
    TruthRule(
        code="witness-disclosure-overclaim",
        severity="error",
        message="Witness, CVE, disclosure, or observed-exploit language must not imply proof beyond taudit output.",
        patterns=(
            compile_re(r"\b(?:CVE|disclosure|witness|observed exploit|exploited in the wild)\b.{0,100}\b(?:proves?|confirmed|ready|available|published)\b"),
            compile_re(r"\b(?:proves?|confirmed|ready|available|published)\b.{0,100}\b(?:CVE|disclosure|witness|observed exploit|exploited in the wild)\b"),
        ),
        allow_context=(
            compile_re(r"\b(?:not|no|without|avoid|do not|unless|non-goal|future|handoff|ceiling)\b"),
        ),
    ),
)


def to_repo_relative(root: pathlib.Path, path: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def excluded(rel_path: str, excludes: Sequence[str] = DEFAULT_EXCLUDES) -> bool:
    return any(fnmatch.fnmatch(rel_path, pattern) for pattern in excludes)


def collect_default_paths(root: pathlib.Path) -> list[pathlib.Path]:
    paths: set[pathlib.Path] = set()
    for rel in DEFAULT_ROOT_FILES:
        path = root / rel
        if path.is_file():
            paths.add(path)
    for path in root.glob(DEFAULT_DOC_GLOB):
        rel = to_repo_relative(root, path)
        if path.is_file() and not excluded(rel):
            paths.add(path)
    return sorted(paths, key=lambda item: to_repo_relative(root, item))


def expand_paths(root: pathlib.Path, path_args: Sequence[str]) -> list[pathlib.Path]:
    if not path_args:
        return collect_default_paths(root)

    paths: set[pathlib.Path] = set()
    for arg in path_args:
        candidate = pathlib.Path(arg)
        if not candidate.is_absolute():
            candidate = root / candidate
        if any(ch in arg for ch in "*?[]"):
            paths.update(path for path in root.glob(arg) if path.is_file())
        elif candidate.is_dir():
            paths.update(path for path in candidate.rglob("*.md") if path.is_file())
        elif candidate.is_file():
            paths.add(candidate)

    return sorted(
        (path for path in paths if not excluded(to_repo_relative(root, path))),
        key=lambda item: to_repo_relative(root, item),
    )


def iter_scannable_lines(text: str) -> Iterable[tuple[int, str]]:
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            yield number, line


def context_for(lines: list[str], index: int) -> str:
    start = max(0, index - 2)
    end = min(len(lines), index + 3)
    return "\n".join(lines[start:end])


def allowed(rule: TruthRule, context: str) -> bool:
    normalized = " ".join(context.split())
    return any(pattern.search(normalized) for pattern in rule.allow_context)


def scan_file(root: pathlib.Path, path: pathlib.Path) -> list[TruthIssue]:
    text = path.read_text(encoding="utf-8")
    all_lines = text.splitlines()
    rel_path = to_repo_relative(root, path)
    issues: list[TruthIssue] = []

    for line_number, line in iter_scannable_lines(text):
        context = context_for(all_lines, line_number - 1)
        for rule in RULES:
            for pattern in rule.patterns:
                match = pattern.search(line)
                if match is None or allowed(rule, context):
                    continue
                issues.append(
                    TruthIssue(
                        code=rule.code,
                        severity=rule.severity,
                        path=rel_path,
                        line=line_number,
                        column=match.start() + 1,
                        match=match.group(0),
                        message=rule.message,
                        text=line.strip(),
                    )
                )
                break

    return issues


def scan_paths(root: pathlib.Path, paths: Sequence[pathlib.Path]) -> ScanReport:
    root = root.resolve()
    issues: list[TruthIssue] = []
    resolved_paths = [path.resolve() for path in paths]
    for path in resolved_paths:
        issues.extend(scan_file(root, path))

    return ScanReport(
        status="issues" if issues else "pass",
        files_scanned=len(resolved_paths),
        issue_count=len(issues),
        issues=sorted(
            issues,
            key=lambda issue: (issue.path, issue.line, issue.column, issue.code),
        ),
    )


def print_text_report(report: ScanReport) -> None:
    print(f"status={report.status} files_scanned={report.files_scanned} issue_count={report.issue_count}")
    for issue in report.issues:
        print(f"{issue.path}:{issue.line}:{issue.column}: {issue.severity}: {issue.code}: {issue.message}")
        print(f"  {issue.text}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan docs for stale RC wording and overclaims without mutating files.",
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="report format",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="optional markdown files, directories, or repo-root globs to scan",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = pathlib.Path(args.root)
    paths = expand_paths(root, args.paths)
    report = scan_paths(root, paths)

    if args.format == "json":
        print(json.dumps(report.to_jsonable(), indent=2, sort_keys=True))
    else:
        print_text_report(report)

    return 1 if report.issues else 0


if __name__ == "__main__":
    sys.exit(main())
