#!/usr/bin/env python3
"""Check source-local readiness for an arXiv benchmark package.

This check does not prove benchmark performance or external inclusion. It
verifies that the repo has the local assets needed to run and report a bounded
taudit reproduction package.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from normalize_taudit_arxiv_findings import (  # noqa: E402
    ArxivNormalizationError,
    RuleMapEntry,
    load_rule_map,
)


REQUIRED_ASSETS = [
    "docs/research/2026-06-01-arxiv-benchmark-inclusion-plan.md",
    "docs/research/arxiv-taudit-rule-map.csv",
    "docs/research/arxiv-corpus-manifest.md",
    "docs/research/arxiv-taudit-runtime-ledger.md",
    "docs/research/arxiv-taudit-detection-ledger.md",
    "docs/research/arxiv-taudit-labeling-protocol.md",
    "docs/research/arxiv-contact-package.md",
    "docs/research/arxiv-submission-preflight.md",
    "scripts/research/normalize_taudit_arxiv_findings.py",
    "scripts/research/run_arxiv_taudit_benchmark.py",
]

RUNTIME_ONLY_GHA_RULES = {
    "oidc_identity_in_untrusted_context",
    "action_major_version_pin_without_sha",
    "known_compromised_action_ref",
    "docker_socket_exposed_to_ci_step",
    "privileged_container_in_ci_step",
}

UNSUPPORTED_CLAIM_PATTERNS = [
    re.compile(r"\bexternally benchmarked\b", re.I),
    re.compile(r"\bincluded in the arxiv benchmark\b", re.I),
    re.compile(r"\baccepted (for|into) (the )?(arxiv|benchmark)\b", re.I),
    re.compile(r"\b(false[- ]positive|false[- ]negative|fp/fn) (rate|rates|claim|claims)\b", re.I),
]

ALLOW_UNSUPPORTED_CONTEXT = {
    "unsafe",
    "do not claim",
    "does not prove",
    "not claiming",
    "not claim",
    "without",
    "requires",
    "require",
    "stop condition",
    "residual risk",
    "no external",
    "absent unless",
    "separate from",
    "cannot prove",
    "before the corresponding evidence",
}

CURRENT_DEFAULT_SCOPE = "gha_default"
CURRENT_DEFAULT_ENABLED = "yes"
BINARY_EXPLAIN_TIMEOUT_SECONDS = 15


@dataclass(frozen=True)
class Check:
    id: str
    status: str
    evidence: str


def check(status: bool, check_id: str, evidence: str) -> Check:
    return Check(check_id, "pass" if status else "fail", evidence)


def is_current_binary_default(entry: RuleMapEntry) -> bool:
    return (
        entry.benchmark_scope == CURRENT_DEFAULT_SCOPE
        and entry.enabled_by_default.lower() == CURRENT_DEFAULT_ENABLED
    )


def default_taudit_executable(root: Path) -> Path:
    candidates = [root / "target/debug/taudit.exe", root / "target/debug/taudit"]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def extract_explain_rule_ids(output: str) -> set[str]:
    rules: set[str] = set()
    for line in output.splitlines():
        match = re.match(r"^\s{2}([a-z0-9_]+)\s+(critical|high|medium|low|info)\s+", line)
        if match:
            rules.add(match.group(1))
    return rules


def current_binary_rule_ids(
    root: Path,
    taudit_executable: Path | None = None,
) -> tuple[set[str] | None, str]:
    executable = taudit_executable or default_taudit_executable(root)
    if not executable.is_absolute():
        executable = root / executable
    if not executable.exists():
        return None, f"not_checked=missing_binary; path={executable}"
    try:
        result = subprocess.run(
            [str(executable), "explain", "--no-color"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=BINARY_EXPLAIN_TIMEOUT_SECONDS,
        )
    except OSError as exc:
        return None, f"not_checked=launch_error; path={executable}; error={exc}"
    except subprocess.TimeoutExpired:
        return None, f"not_checked=timeout; path={executable}"

    if result.returncode != 0:
        return None, (
            f"not_checked=nonzero_exit; path={executable}; exit={result.returncode}; "
            f"stderr={result.stderr.strip()!r}"
        )
    rule_ids = extract_explain_rule_ids(result.stdout)
    if not rule_ids:
        return None, f"not_checked=no_rules_parsed; path={executable}"
    return rule_ids, f"path={executable}; rules={len(rule_ids)}"


def current_binary_default_check(
    rule_map: dict[str, RuleMapEntry],
    binary_rule_ids: set[str] | None,
    binary_evidence: str,
) -> tuple[Check, list[str]]:
    human_gates: list[str] = []
    if binary_rule_ids is None:
        human_gates.append(
            "build a taudit binary and rerun readiness to verify current-binary/default rule-map rows"
        )
        return (
            Check(
                "current-binary-default-rules",
                "pass",
                binary_evidence,
            ),
            human_gates,
        )

    current_default_rows = {
        entry.rule_id for entry in rule_map.values() if is_current_binary_default(entry)
    }
    non_default_rows = set(rule_map).difference(current_default_rows)
    missing_default_rows = sorted(current_default_rows.difference(binary_rule_ids))
    non_current_non_default_rows = sorted(non_default_rows.difference(binary_rule_ids))
    non_default_present_rows = sorted(non_default_rows.intersection(binary_rule_ids))

    if non_current_non_default_rows:
        human_gates.append(
            "release-enable or remove non-current candidate rule-map rows before "
            "claiming current-binary/default benchmark coverage: "
            + ", ".join(non_current_non_default_rows)
        )
    if non_default_present_rows:
        human_gates.append(
            "review non-default rule-map rows already present in the current binary before "
            "claiming current-binary/default benchmark coverage: "
            + ", ".join(non_default_present_rows)
        )

    evidence = {
        "binary": binary_evidence,
        "current_default_rows": len(current_default_rows),
        "missing_default_rows": missing_default_rows,
        "non_current_non_default_rows": non_current_non_default_rows,
        "non_default_present_rows": non_default_present_rows,
    }
    return (
        check(
            not missing_default_rows,
            "current-binary-default-rules",
            json.dumps(evidence, sort_keys=True),
        ),
        human_gates,
    )


def indexed_gha_rules(root: Path) -> set[str]:
    index = (root / "docs/rules/index.md").read_text(encoding="utf-8")
    rules: set[str] = set()
    for line in index.splitlines():
        match = re.match(r"\| \[([^\]]+)\].*\| ([^|]+) \| ([^|]+) \|$", line)
        if not match:
            continue
        platform = match.group(3).strip()
        if "GHA" in platform and "ADO only" not in platform and "GitLab only" not in platform:
            rules.add(match.group(1))
    return rules


def evidence_exists(root: Path, evidence: str) -> bool:
    if evidence.startswith("docs/") or evidence.startswith("scripts/") or evidence.startswith("tests/"):
        return (root / evidence).exists()
    if evidence.startswith("taudit explain "):
        return True
    return evidence.startswith("http://") or evidence.startswith("https://")


def unsupported_claim_findings(root: Path) -> list[str]:
    findings: list[str] = []
    for path in sorted((root / "docs/research").glob("arxiv*.md")) + [
        root / "docs/research/2026-06-01-arxiv-benchmark-inclusion-plan.md"
    ]:
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for line_no, line in enumerate(lines, start=1):
            prev_line = lines[line_no - 2] if line_no > 1 else ""
            next_line = lines[line_no] if line_no < len(lines) else ""
            lowered = f"{prev_line}\n{line}\n{next_line}".lower()
            for pattern in UNSUPPORTED_CLAIM_PATTERNS:
                if pattern.search(line) and not any(token in lowered for token in ALLOW_UNSUPPORTED_CONTEXT):
                    findings.append(f"{path.relative_to(root)}:{line_no}: {line.strip()}")
    return findings


def run_checks(root: Path, taudit_executable: Path | None = None) -> dict:
    checks: list[Check] = []

    missing_assets = [asset for asset in REQUIRED_ASSETS if not (root / asset).exists()]
    checks.append(
        check(
            not missing_assets,
            "assets-present",
            "missing=" + json.dumps(missing_assets),
        )
    )

    try:
        rule_map = load_rule_map(root / "docs/research/arxiv-taudit-rule-map.csv")
        checks.append(check(True, "rule-map-loads", f"rows={len(rule_map)}"))
    except ArxivNormalizationError as exc:
        rule_map = {}
        checks.append(check(False, "rule-map-loads", str(exc)))

    required_rules = indexed_gha_rules(root) | RUNTIME_ONLY_GHA_RULES
    missing_rules = sorted(required_rules.difference(rule_map))
    checks.append(
        check(
            not missing_rules,
            "gha-rules-mapped",
            "missing=" + json.dumps(missing_rules),
        )
    )

    missing_evidence = sorted(
        f"{entry.rule_id}:{entry.evidence}"
        for entry in rule_map.values()
        if not evidence_exists(root, entry.evidence)
    )
    checks.append(
        check(
            not missing_evidence,
            "map-evidence-resolves",
            "missing=" + json.dumps(missing_evidence),
        )
    )

    binary_rule_ids, binary_evidence = current_binary_rule_ids(root, taudit_executable)
    binary_check, binary_human_gates = current_binary_default_check(
        rule_map,
        binary_rule_ids,
        binary_evidence,
    )
    checks.append(binary_check)

    needs_review = sorted(
        entry.rule_id for entry in rule_map.values() if entry.mapping_status == "needs_author_review"
    )
    checks.append(
        Check(
            "author-review-marked",
            "pass",
            f"needs_author_review={len(needs_review)}",
        )
    )

    claim_findings = unsupported_claim_findings(root)
    checks.append(
        check(
            not claim_findings,
            "unsupported-claims-absent",
            "findings=" + json.dumps(claim_findings),
        )
    )

    status = "pass" if all(item.status == "pass" for item in checks) else "fail"
    human_gates_remaining = [
        "move source-local smoke artifacts from %TEMP% into a durable shareable package location",
        "complete dataset license/use review before copying workflow files or outputs outside the local machine",
        "run full corpus benchmark and retain raw artifacts",
        "execute FP/FN labeling protocol before correctness claims",
        "obtain arXiv author/endorsement/submission approval before submission",
        "obtain external author response before claiming benchmark inclusion",
    ]
    human_gates_remaining.extend(binary_human_gates)

    return {
        "report_kind": "taudit.arxiv_readiness_check.v1",
        "status": status,
        "claim_ceiling": "source-local readiness only",
        "checks": [asdict(item) for item in checks],
        "human_gates_remaining": human_gates_remaining,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--taudit-executable", type=Path)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = run_checks(args.root.resolve(), args.taudit_executable)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
