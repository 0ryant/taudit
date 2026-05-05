#!/usr/bin/env python3
"""Security-pattern scan for the harvested workflow YAML corpus.

This is a corpus-mining tool for taudit rule development. It does not claim a
YAML file is exploitable or CVE-affected by itself; it finds security-relevant
patterns and emits evidence-rich candidates for follow-up rules.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import json
import os
import re
from pathlib import Path


DEFAULT_ROOT = Path("corpus/workflow-yaml-testbed")
PLATFORMS = ("gha", "ado", "bb", "gl")


@dataclasses.dataclass(frozen=True)
class PatternDef:
    id: str
    severity: str
    regex: re.Pattern[str]
    rationale: str
    taudit_rule_candidate: str
    cve_relevance: str


PATTERNS = [
    PatternDef(
        "curl_pipe_shell",
        "high",
        re.compile(r"\b(curl|wget)\b[^\n|;&]*\|\s*(sudo\s+)?(bash|sh|zsh|python|ruby|perl)\b", re.I),
        "Remote script is executed directly without a reviewable artifact boundary.",
        "Generalize runtime_script_fetched_from_floating_url across all parsers and catch pipe-to-shell forms.",
        "May expose known vulnerable installer scripts or compromised endpoints, but CVE identity requires URL/package resolution.",
    ),
    PatternDef(
        "remote_kubectl_apply",
        "high",
        re.compile(r"\bkubectl\s+(apply|create)\b[^\n]*\s-f\s+https?://", re.I),
        "Cluster mutation is driven directly from remote YAML.",
        "Add remote_kubectl_manifest_apply with trust-zone and credential context.",
        "CVE relevance depends on remote manifest content and cluster version.",
    ),
    PatternDef(
        "docker_sock_mount",
        "critical",
        re.compile(r"/var/run/docker\.sock", re.I),
        "Docker socket exposure gives container processes host-level Docker control.",
        "Add docker_socket_exposed_to_ci_step for all platforms.",
        "Often converts container escape CVEs or malicious build steps into host compromise.",
    ),
    PatternDef(
        "docker_privileged",
        "high",
        re.compile(r"\bdocker\s+run\b[^\n]*--privileged\b", re.I),
        "Privileged container execution weakens CI isolation.",
        "Add privileged_container_in_ci_step with authority-aware severity.",
        "Relevant to container-runtime CVE blast radius, but not itself a CVE.",
    ),
    PatternDef(
        "docker_dind",
        "high",
        re.compile(r"\bdocker(?:[:/][\w.-]+)?[:@][^\s'\"]*dind\b|\bdind\b", re.I),
        "Docker-in-Docker commonly grants broad build/container authority.",
        "Extend dind_service_grants_host_authority beyond GitLab where applicable.",
        "CVE relevance depends on Docker daemon image/version and daemon exposure.",
    ),
    PatternDef(
        "latest_tag",
        "medium",
        re.compile(r"(?m)(image:\s*[^#\n]+:latest\b|docker\s+pull\s+[^#\n]+:latest\b|uses:\s*[^#\n]+@(?:main|master|latest)\b)", re.I),
        "Mutable action/image references make build inputs non-reproducible.",
        "Broaden mutable_ref_or_latest_image to all platform parsers.",
        "Mutable refs can silently pick up vulnerable versions after disclosure.",
    ),
    PatternDef(
        "gh_action_major_pin_only",
        "medium",
        re.compile(r"(?m)uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@v\d+\s*$", re.I),
        "Major-version-only GitHub Action refs are mutable within the major line.",
        "Add action_major_version_pin_without_sha as a lower-noise variant of unpinned_action.",
        "Can pull vulnerable action releases; exact CVE/advisory requires action/version mapping.",
    ),
    PatternDef(
        "setup_old_node",
        "medium",
        re.compile(r"(?is)(node-version|NODE_VERSION|nodejs_version)\s*[:=]\s*['\"]?(8|10|12|14|16)(?:\D|$)"),
        "Old Node runtimes are often EOL and accumulate unpatched vulnerabilities.",
        "Add eol_runtime_version for setup-node and CI language setup tasks.",
        "CVE relevance is high for EOL runtimes, but exact CVEs require version/date mapping.",
    ),
    PatternDef(
        "python_eol_runtime",
        "medium",
        re.compile(r"(?is)(python-version|PYTHON_VERSION)\s*[:=]\s*['\"]?(2\.7|3\.6|3\.7|3\.8)(?:\D|$)"),
        "Old Python runtimes are often EOL and accumulate unpatched vulnerabilities.",
        "Add eol_runtime_version for setup-python and platform images.",
        "CVE relevance is high for EOL runtimes, but exact CVEs require version/date mapping.",
    ),
    PatternDef(
        "npm_ignore_scripts_disabled_absent",
        "low",
        re.compile(r"\b(npm|pnpm|yarn)\s+(install|ci)\b", re.I),
        "Package install scripts execute arbitrary package-maintainer code unless disabled or isolated.",
        "Add package_manager_install_scripts_with_authority when secrets/identity are in scope.",
        "Often relevant to dependency-confusion or compromised-package advisories, not a direct CVE.",
    ),
    PatternDef(
        "pip_unhashed_install",
        "low",
        re.compile(r"\bpip(?:3)?\s+install\b(?![^\n]*--require-hashes)", re.I),
        "Python package install lacks hash pinning.",
        "Add unpinned_package_install_when_privileged for package-manager commands.",
        "Can pull vulnerable package versions; exact CVE requires dependency resolution.",
    ),
    PatternDef(
        "go_install_latest",
        "medium",
        re.compile(r"\bgo\s+install\s+[\w./:-]+@latest\b", re.I),
        "Build tool is fetched at a mutable latest ref.",
        "Add mutable_tool_install_ref for language tool installers.",
        "Can pick up vulnerable tool releases; exact CVE requires module resolution.",
    ),
    PatternDef(
        "terraform_auto_approve",
        "high",
        re.compile(r"\bterraform\s+apply\b[^\n]*\b-auto-approve\b", re.I),
        "Infrastructure mutation bypasses human approval.",
        "Generalize terraform_auto_approve_in_prod across non-ADO platforms.",
        "Not a CVE, but can amplify vulnerable IaC/provider usage.",
    ),
    PatternDef(
        "hardcoded_aws_access_key",
        "critical",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "Literal AWS access-key id appears in CI YAML.",
        "Add hardcoded_cloud_access_key_identifier with secret-scanner caveat or delegate to gitleaks.",
        "Credential exposure, not CVE.",
    ),
    PatternDef(
        "secret_echo_or_print",
        "high",
        re.compile(r"\b(echo|printf|Write-Host|print)\b[^\n]*(secret|token|password|passwd|apikey|api_key)", re.I),
        "Command appears to print sensitive material.",
        "Add secret_material_logged_to_stdout where graph confirms secret source.",
        "Credential leakage, not CVE.",
    ),
    PatternDef(
        "base64_decode_to_shell",
        "high",
        re.compile(r"\bbase64\s+(-d|--decode)\b[^\n|;&]*\|\s*(bash|sh|zsh|python|ruby|perl)\b", re.I),
        "Opaque base64 payload is decoded and executed.",
        "Add opaque_encoded_payload_execution.",
        "Could hide exploitation of known CVEs, but YAML alone cannot identify one.",
    ),
    PatternDef(
        "advisory_tj_actions_changed_files",
        "critical",
        re.compile(r"(?m)uses:\s*['\"]?tj-actions/changed-files@([^\s'\"#]+)", re.I),
        "Workflow references tj-actions/changed-files, a known compromised GitHub Action family.",
        "Add known_compromised_action_ref backed by advisory data and version/range metadata.",
        "Known GitHub Actions supply-chain incident; exact CVE/advisory exposure depends on tag/SHA and execution date.",
    ),
    PatternDef(
        "advisory_reviewdog_action_setup",
        "critical",
        re.compile(r"(?m)uses:\s*['\"]?reviewdog/action-setup@([^\s'\"#]+)", re.I),
        "Workflow references reviewdog/action-setup, a known compromised GitHub Action family.",
        "Add known_compromised_action_ref backed by advisory data and version/range metadata.",
        "Known GitHub Actions supply-chain incident; exact CVE/advisory exposure depends on tag/SHA and execution date.",
    ),
    PatternDef(
        "advisory_reviewdog_wrapper_action",
        "high",
        re.compile(r"(?m)uses:\s*['\"]?reviewdog/action-(shellcheck|composite-template|staticcheck|ast-grep|typos)@([^\s'\"#]+)", re.I),
        "Workflow references a reviewdog wrapper action family with published compromise advisories.",
        "Add known_compromised_action_ref backed by advisory data and version/range metadata.",
        "Known GitHub Actions supply-chain incident; exact CVE/advisory exposure depends on action, tag/SHA, and execution date.",
    ),
]


GHA_ACTION_RE = re.compile(r"(?m)uses:\s*['\"]?([^'\"\s#]+)")
IMAGE_RE = re.compile(r"(?m)(?:image:\s*|docker\s+(?:pull|run)\s+)(['\"]?)([A-Za-z0-9._:/@-]+)\1", re.I)


def files_for(root: Path, platforms: list[str], limit_per_platform: int | None) -> list[tuple[str, Path]]:
    out: list[tuple[str, Path]] = []
    for platform in platforms:
        files = sorted((root / platform).glob("*.y*ml"))
        if limit_per_platform is not None:
            files = files[:limit_per_platform]
        out.extend((platform, path) for path in files)
    return out


def line_no(text: str, start: int) -> int:
    return text.count("\n", 0, start) + 1


def snippet(text: str, start: int, end: int) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    s = text[line_start:line_end].strip()
    return s[:240]


def scan_file(platform: str, path: Path) -> list[dict]:
    try:
        text = path.read_text(errors="replace")
    except OSError as err:
        return [{"id": "read_error", "platform": platform, "path": str(path), "error": str(err)}]
    findings: list[dict] = []
    for pat in PATTERNS:
        for m in pat.regex.finditer(text):
            findings.append(
                {
                    "id": pat.id,
                    "severity": pat.severity,
                    "platform": platform,
                    "path": str(path),
                    "line": line_no(text, m.start()),
                    "snippet": snippet(text, m.start(), m.end()),
                    "rationale": pat.rationale,
                    "taudit_rule_candidate": pat.taudit_rule_candidate,
                    "cve_relevance": pat.cve_relevance,
                }
            )
            break
    if platform == "gha":
        for m in GHA_ACTION_RE.finditer(text):
            ref = m.group(1)
            if "@" not in ref:
                continue
            action, version = ref.rsplit("@", 1)
            if version.lower() in {"master", "main", "latest"}:
                continue
            if re.fullmatch(r"v?(\d+)(?:\.\d+){0,2}", version):
                major = re.match(r"v?(\d+)", version)
                if major and int(major.group(1)) <= 2:
                    findings.append(
                        {
                            "id": "old_github_action_major",
                            "severity": "medium",
                            "platform": platform,
                            "path": str(path),
                            "line": line_no(text, m.start()),
                            "snippet": snippet(text, m.start(), m.end()),
                            "action": action,
                            "version": version,
                            "rationale": "Workflow uses an old major-version GitHub Action line.",
                            "taudit_rule_candidate": "Add deprecated_or_eol_action_major with action-specific allowlist metadata.",
                            "cve_relevance": "May map to known action-runtime deprecation or action-specific advisories; requires source lookup.",
                        }
                    )
    for m in IMAGE_RE.finditer(text):
        image = m.group(2)
        if "@sha256:" not in image and ":" not in image.rsplit("/", 1)[-1]:
            findings.append(
                {
                    "id": "image_without_tag_or_digest",
                    "severity": "medium",
                    "platform": platform,
                    "path": str(path),
                    "line": line_no(text, m.start()),
                    "snippet": snippet(text, m.start(), m.end()),
                    "image": image,
                    "rationale": "Container image has no explicit immutable digest or version tag.",
                    "taudit_rule_candidate": "Ensure floating_image covers every platform/image syntax in corpus.",
                    "cve_relevance": "Can silently pick up vulnerable image versions after disclosure.",
                }
            )
    return findings


def write_json(path: Path, obj: object) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--platform", action="append", choices=PLATFORMS)
    parser.add_argument("--limit-per-platform", type=int)
    parser.add_argument("--max-examples", type=int, default=25)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    platforms = args.platform or list(PLATFORMS)
    files = files_for(args.root, platforms, args.limit_per_platform)
    out_dir = args.root / "analysis"
    out_dir.mkdir(parents=True, exist_ok=True)

    all_findings: list[dict] = []
    for platform, path in files:
        all_findings.extend(scan_file(platform, path))

    counts_by_id: collections.Counter[str] = collections.Counter(f["id"] for f in all_findings)
    counts_by_platform: dict[str, collections.Counter[str]] = {p: collections.Counter() for p in platforms}
    examples: dict[str, list[dict]] = collections.defaultdict(list)
    for f in all_findings:
        counts_by_platform.setdefault(f["platform"], collections.Counter())[f["id"]] += 1
        if len(examples[f["id"]]) < args.max_examples:
            examples[f["id"]].append(f)

    summary = {
        "root": str(args.root),
        "platforms": platforms,
        "files_scanned": len(files),
        "finding_count": len(all_findings),
        "counts_by_id": dict(counts_by_id.most_common()),
        "counts_by_platform": {p: dict(c.most_common()) for p, c in counts_by_platform.items()},
        "top_rule_candidates": summarize_candidates(all_findings),
        "examples": examples,
    }

    write_json(out_dir / "vuln_scan_summary.json", summary)
    with (out_dir / "vuln_scan_findings.jsonl").open("w", encoding="utf-8") as f:
        for item in all_findings:
            f.write(json.dumps(item, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def summarize_candidates(findings: list[dict]) -> list[dict]:
    grouped: dict[str, dict] = {}
    for f in findings:
        key = f["taudit_rule_candidate"]
        entry = grouped.setdefault(
            key,
            {
                "candidate": key,
                "hits": 0,
                "max_severity": f["severity"],
                "pattern_ids": set(),
                "platforms": set(),
            },
        )
        entry["hits"] += 1
        entry["pattern_ids"].add(f["id"])
        entry["platforms"].add(f["platform"])
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        if order.get(f["severity"], 0) > order.get(entry["max_severity"], 0):
            entry["max_severity"] = f["severity"]
    out = []
    for entry in grouped.values():
        out.append(
            {
                "candidate": entry["candidate"],
                "hits": entry["hits"],
                "max_severity": entry["max_severity"],
                "pattern_ids": sorted(entry["pattern_ids"]),
                "platforms": sorted(entry["platforms"]),
            }
        )
    return sorted(out, key=lambda x: ({"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x["max_severity"], 0), x["hits"]), reverse=True)


if __name__ == "__main__":
    raise SystemExit(main())
