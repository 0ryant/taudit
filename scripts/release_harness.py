#!/usr/bin/env python3
"""Standardize taudit release validation and GitHub release creation."""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHANGELOG = ROOT / "CHANGELOG.md"
CLI_MANIFEST = ROOT / "crates" / "taudit-cli" / "Cargo.toml"
TAG_RE = re.compile(r"^v(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$")
CONFORMANCE_INCOMPLETE_EXIT_CODE = 3


class ReleaseHarnessError(RuntimeError):
    """Raised when the requested release shape is invalid."""


@dataclass(frozen=True)
class ConformanceGateResult:
    command: tuple[str, ...]
    exit_code: int
    status: str
    full_conformance: bool
    counts: dict[str, int]

    @property
    def pending_count(self) -> int:
        return self.counts.get("pending", 0)

    @property
    def is_full_pass(self) -> bool:
        return self.exit_code == 0 and self.status == "pass" and self.full_conformance

    @property
    def is_incomplete_pending(self) -> bool:
        return (
            self.exit_code == CONFORMANCE_INCOMPLETE_EXIT_CODE
            and self.status == "incomplete"
            and not self.full_conformance
        )


@dataclass(frozen=True)
class ReleasePlan:
    tag: str
    version: str
    prerelease: bool
    title: str
    notes: str
    conformance: ConformanceGateResult | None = None


def read_toml(path: pathlib.Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def parse_toml_text(text: str, display_name: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ReleaseHarnessError(f"failed to parse TOML from {display_name}: {exc}") from exc


def read_text_at_ref(root: pathlib.Path, ref: str, relative_path: pathlib.Path) -> str:
    result = subprocess.run(
        ["git", "show", f"{ref}:{relative_path.as_posix()}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        detail = f": {stderr}" if stderr else ""
        raise ReleaseHarnessError(
            f"failed to read {relative_path.as_posix()} at {ref!r}{detail}"
        )
    return result.stdout


def parse_tag(tag: str) -> tuple[str, bool]:
    match = TAG_RE.fullmatch(tag.strip())
    if match is None:
        raise ReleaseHarnessError(
            f"invalid release tag {tag!r}; expected vX.Y.Z or vX.Y.Z-suffix"
        )
    version = match.group("version")
    return version, "-" in version


def cli_version(root: pathlib.Path, source_ref: str | None = None) -> str:
    if source_ref:
        manifest = parse_toml_text(
            read_text_at_ref(root, source_ref, pathlib.Path("crates/taudit-cli/Cargo.toml")),
            f"crates/taudit-cli/Cargo.toml at {source_ref}",
        )
    else:
        manifest = read_toml(root / "crates" / "taudit-cli" / "Cargo.toml")
    package = manifest.get("package", {})
    version = package.get("version")
    if not isinstance(version, str) or not version:
        raise ReleaseHarnessError("crates/taudit-cli/Cargo.toml has no package.version")
    return version


def extract_changelog_section(changelog_text: str, tag: str) -> str:
    header_prefix = f"## {tag}"
    header_re = re.compile(rf"^##\s+{re.escape(tag)}(?:\s|$)")
    lines = changelog_text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if header_re.match(line):
            start = index
            break
    if start is None:
        raise ReleaseHarnessError(f"CHANGELOG.md is missing a section headed {header_prefix!r}")

    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("## "):
            end = index
            break

    section = "\n".join(lines[start:end]).strip()
    if not section:
        raise ReleaseHarnessError(f"CHANGELOG.md section {header_prefix!r} is empty")
    return section + "\n"


def build_release_plan(root: pathlib.Path, tag: str, source_ref: str | None = None) -> ReleasePlan:
    version, prerelease = parse_tag(tag)
    manifest_version = cli_version(root, source_ref=source_ref)
    if manifest_version != version:
        raise ReleaseHarnessError(
            f"taudit CLI version {manifest_version!r} does not match tag version {version!r}"
        )

    if source_ref:
        changelog_text = read_text_at_ref(root, source_ref, pathlib.Path("CHANGELOG.md"))
    else:
        changelog_text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    notes = extract_changelog_section(changelog_text, tag)
    return ReleasePlan(
        tag=tag,
        version=version,
        prerelease=prerelease,
        title=f"taudit {tag}",
        notes=notes,
    )


def run_checked(argv: list[str], root: pathlib.Path) -> None:
    subprocess.run(argv, cwd=root, check=True)


def conformance_harness_command(root: pathlib.Path) -> list[str]:
    return [
        sys.executable,
        str(root / "scripts" / "conformance_harness.py"),
        "--root",
        str(root),
        "--format",
        "json",
    ]


def _parse_conformance_counts(payload: dict) -> dict[str, int]:
    counts = payload.get("counts", {})
    if not isinstance(counts, dict):
        raise ReleaseHarnessError("ADR 0020 conformance output has invalid counts")
    parsed: dict[str, int] = {}
    for key in ("pass", "fail", "pending"):
        value = counts.get(key, 0)
        if not isinstance(value, int):
            raise ReleaseHarnessError(
                f"ADR 0020 conformance output has invalid counts.{key}"
            )
        parsed[key] = value
    return parsed


def run_conformance_gate(root: pathlib.Path) -> ConformanceGateResult:
    command = conformance_harness_command(root)
    result = subprocess.run(
        command,
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        stderr = result.stderr.strip()
        detail = f"; stderr: {stderr}" if stderr else ""
        raise ReleaseHarnessError(
            f"ADR 0020 conformance harness did not emit valid JSON: {exc}{detail}"
        ) from exc
    if not isinstance(payload, dict):
        raise ReleaseHarnessError("ADR 0020 conformance output must be a JSON object")
    status = payload.get("status")
    if not isinstance(status, str):
        raise ReleaseHarnessError("ADR 0020 conformance output has invalid status")
    full_conformance = payload.get("full_conformance")
    if not isinstance(full_conformance, bool):
        raise ReleaseHarnessError(
            "ADR 0020 conformance output has invalid full_conformance"
        )
    return ConformanceGateResult(
        command=tuple(command),
        exit_code=result.returncode,
        status=status,
        full_conformance=full_conformance,
        counts=_parse_conformance_counts(payload),
    )


def validate_conformance_gate(root: pathlib.Path, plan: ReleasePlan) -> ConformanceGateResult:
    gate = run_conformance_gate(root)
    if gate.is_full_pass:
        return gate
    command = " ".join(gate.command)
    if gate.is_incomplete_pending:
        readiness_target = "release-ready" if plan.prerelease else "stable-release-ready"
        raise ReleaseHarnessError(
            "ADR 0020 conformance harness is incomplete "
            f"(exit {gate.exit_code}, pending={gate.pending_count}); "
            f"{command} is not {readiness_target}"
        )
    raise ReleaseHarnessError(
        "ADR 0020 conformance harness failed release gate "
        f"(exit {gate.exit_code}, status={gate.status!r}, "
        f"full_conformance={gate.full_conformance})"
    )


def check_release(
    root: pathlib.Path,
    tag: str,
    require_local_tag: bool,
    source_ref: str | None = None,
    validate_publish_metadata: bool = True,
    validate_conformance: bool = True,
) -> ReleasePlan:
    plan = build_release_plan(root, tag, source_ref=source_ref)
    if require_local_tag:
        run_checked(["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"], root)
    if source_ref and validate_publish_metadata:
        raise ReleaseHarnessError(
            "publish metadata validation only supports the checked-out working tree; "
            "re-run with --skip-publish-metadata when using --source-ref"
        )
    if source_ref and validate_conformance:
        raise ReleaseHarnessError(
            "conformance validation only supports the checked-out working tree; "
            "re-run with --skip-conformance when using --source-ref"
        )
    if validate_publish_metadata:
        run_checked(
            [
                sys.executable,
                str(root / "scripts" / "check-crates-publish-metadata.py"),
                "--expected-release-version",
                plan.version,
            ],
            root,
        )
    if validate_conformance:
        plan = dataclasses.replace(
            plan,
            conformance=validate_conformance_gate(root, plan),
        )
    return plan


def gh_release_exists(root: pathlib.Path, tag: str, repo: str | None) -> bool:
    command = ["gh", "release", "view", tag]
    if repo:
        command.extend(["--repo", repo])
    result = subprocess.run(
        command,
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0
def ensure_github_release(
    root: pathlib.Path,
    tag: str,
    repo: str | None,
    source_ref: str | None = None,
    validate_publish_metadata: bool = True,
    validate_conformance: bool = True,
) -> ReleasePlan:
    plan = check_release(
        root,
        tag,
        require_local_tag=False,
        source_ref=source_ref,
        validate_publish_metadata=validate_publish_metadata,
        validate_conformance=validate_conformance,
    )
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".md", delete=False
    ) as handle:
        handle.write(plan.notes)
        notes_path = pathlib.Path(handle.name)

    try:
        if gh_release_exists(root, tag, repo):
            command = ["gh", "release", "edit", tag]
            if not plan.prerelease:
                command.append("--latest")
            else:
                command.append("--prerelease")
                command.append("--latest=false")
        else:
            command = ["gh", "release", "create", tag, "--verify-tag"]
            if plan.prerelease:
                command.extend(["--prerelease", "--latest=false"])
            else:
                command.append("--latest")

        command.extend(["--title", plan.title, "--notes-file", str(notes_path)])
        if repo:
            command.extend(["--repo", repo])
        run_checked(command, root)

        verify = ["gh", "release", "view", tag]
        if repo:
            verify.extend(["--repo", repo])
        run_checked(verify, root)
        return plan
    finally:
        notes_path.unlink(missing_ok=True)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=ROOT,
        help="Repository root to validate and operate on.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser(
        "check", help="Validate tag, changelog, and publish metadata for a release."
    )
    check_parser.add_argument("--tag", required=True, help="Release tag, e.g. v1.1.2")
    check_parser.add_argument(
        "--source-ref",
        default=None,
        help="Optional git ref used to read CHANGELOG.md and Cargo.toml for historical validation.",
    )
    check_parser.add_argument(
        "--require-local-tag",
        action="store_true",
        help="Fail unless the tag exists locally under refs/tags/.",
    )
    check_parser.add_argument(
        "--skip-publish-metadata",
        action="store_true",
        help="Skip the working-tree publish metadata check. Required for historical source refs.",
    )
    check_parser.add_argument(
        "--skip-conformance",
        action="store_true",
        help="Skip the ADR 0020 conformance harness check. Required for historical source refs.",
    )

    notes_parser = subparsers.add_parser(
        "notes", help="Print the changelog-backed notes body for a release tag."
    )
    notes_parser.add_argument("--tag", required=True, help="Release tag, e.g. v1.1.2")
    notes_parser.add_argument(
        "--source-ref",
        default=None,
        help="Optional git ref used to read CHANGELOG.md and Cargo.toml for historical notes.",
    )

    release_parser = subparsers.add_parser(
        "ensure-github-release",
        help="Create or normalize the GitHub release object from the changelog.",
    )
    release_parser.add_argument("--tag", required=True, help="Release tag, e.g. v1.1.2")
    release_parser.add_argument(
        "--source-ref",
        default=None,
        help="Optional git ref used to read CHANGELOG.md and Cargo.toml for historical backfill.",
    )
    release_parser.add_argument(
        "--repo",
        default=None,
        help="Optional OWNER/REPO override for gh commands. Defaults to gh context.",
    )
    release_parser.add_argument(
        "--skip-publish-metadata",
        action="store_true",
        help="Skip the working-tree publish metadata check. Use this for historical backfill.",
    )
    release_parser.add_argument(
        "--skip-conformance",
        action="store_true",
        help="Skip the ADR 0020 conformance harness check. Use this for historical backfill.",
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    root = args.root.resolve()
    try:
        if args.command == "check":
            plan = check_release(
                root,
                args.tag,
                args.require_local_tag,
                source_ref=args.source_ref,
                validate_publish_metadata=not args.skip_publish_metadata,
                validate_conformance=not args.skip_conformance,
            )
            print(f"release check passed for {plan.tag}")
            return 0
        if args.command == "notes":
            plan = build_release_plan(root, args.tag, source_ref=args.source_ref)
            sys.stdout.write(plan.notes)
            return 0
        if args.command == "ensure-github-release":
            plan = ensure_github_release(
                root,
                args.tag,
                args.repo,
                source_ref=args.source_ref,
                validate_publish_metadata=not args.skip_publish_metadata,
                validate_conformance=not args.skip_conformance,
            )
            print(f"GitHub release standardized for {plan.tag}")
            return 0
        raise ReleaseHarnessError(f"unknown command: {args.command}")
    except ReleaseHarnessError as exc:
        print(f"release harness error: {exc}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"release harness command failed: {' '.join(exc.cmd)}", file=sys.stderr)
        return exc.returncode or 1


if __name__ == "__main__":
    raise SystemExit(main())
