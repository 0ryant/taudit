#!/usr/bin/env python3
"""Generate a pinned arXiv workflow-corpus manifest.

The manifest records workflow relative paths plus SHA-256 digests without
vendoring the upstream corpus into this repository. It can read either a normal
checkout or a local git object database, including bare/partial clones used to
avoid NTFS-invalid upstream paths on Windows.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal


DEFAULT_UPSTREAM_URL = "https://github.com/sparkrew/github-actions-security.git"
DEFAULT_WORKFLOW_DIR = "dataset/workflows"
WORKFLOW_SUFFIXES = {".yml", ".yaml"}
Mode = Literal["auto", "filesystem", "git-tree"]


class ManifestError(Exception):
    """Raised when a manifest cannot be generated from the provided corpus."""


CorpusManifestError = ManifestError


def normalize_relpath(value: str | Path) -> str:
    return Path(str(value).replace("\\", "/")).as_posix().strip("/")


def git_text(root: Path, args: list[str]) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return proc.stdout.strip()


def git_bytes(root: Path, args: list[str]) -> bytes:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
        )
    except OSError as exc:
        raise ManifestError(f"cannot run git: {exc}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else str(exc)
        raise ManifestError(f"git command failed: {stderr.strip()}") from exc
    return proc.stdout


def git_commit(root: Path) -> str | None:
    return git_text(root, ["rev-parse", "--verify", "HEAD"])


def git_upstream_url(root: Path) -> str | None:
    return git_text(root, ["remote", "get-url", "origin"])


def workflow_entry(relative_path: str, content: bytes) -> dict[str, str | int]:
    return {
        "relative_path": relative_path,
        "sha256": hashlib.sha256(content).hexdigest(),
        "byte_size": len(content),
    }


def validate_limit(limit: int | None) -> None:
    if limit is not None and limit < 1:
        raise ManifestError("limit must be at least 1")


def workflow_file_candidates(root: Path, workflow_dir: str) -> list[Path]:
    base = root / Path(workflow_dir)
    if not base.is_dir():
        base = root
    if not base.is_dir():
        return []
    return sorted(
        path
        for path in base.rglob("*")
        if path.is_file() and path.suffix.lower() in WORKFLOW_SUFFIXES
    )


def filesystem_entries(
    root: Path,
    workflow_dir: str,
    limit: int | None = None,
) -> tuple[int, list[dict[str, str | int]]]:
    candidates = workflow_file_candidates(root, workflow_dir)
    entries = []
    for path in candidates[:limit]:
        resolved_path = path.resolve()
        resolved_root = root.resolve()
        try:
            relative_path = resolved_path.relative_to(resolved_root).as_posix()
        except ValueError as exc:
            raise ManifestError(f"workflow path is outside corpus root: {path}") from exc
        if not relative_path.startswith(f"{workflow_dir}/") and root.name == "workflows":
            relative_path = f"{workflow_dir}/{resolved_path.relative_to(resolved_root).as_posix()}"
        entries.append(workflow_entry(relative_path, path.read_bytes()))
    return len(candidates), entries


def parse_ls_tree(stdout: str) -> list[str]:
    paths: list[str] = []
    for line in stdout.splitlines():
        if "\t" not in line:
            continue
        _, relative_path = line.split("\t", 1)
        paths.append(relative_path)
    return paths


def git_tree_paths(root: Path, workflow_dir: str) -> list[str]:
    workflow_dir = normalize_relpath(workflow_dir)
    stdout = git_text(root, ["ls-tree", "-r", "--full-tree", "HEAD", "--", workflow_dir])
    if stdout is None:
        return []
    paths = []
    for relative_path in parse_ls_tree(stdout):
        if Path(relative_path).suffix.lower() in WORKFLOW_SUFFIXES:
            paths.append(relative_path)
    return sorted(paths)


def git_tree_entries(
    root: Path,
    workflow_dir: str,
    limit: int | None = None,
) -> tuple[int, list[dict[str, str | int]]]:
    paths = git_tree_paths(root, workflow_dir)
    entries: list[dict[str, str | int]] = []
    for relative_path in paths[:limit]:
        content = git_bytes(root, ["show", f"HEAD:{relative_path}"])
        entries.append(workflow_entry(relative_path, content))
    return len(paths), entries


def manifest_entries(
    root: Path,
    workflow_dir: str,
    mode: Mode,
    limit: int | None = None,
) -> tuple[str, int, list[dict[str, str | int]]]:
    validate_limit(limit)
    if mode in {"auto", "filesystem"}:
        discovered_count, entries = filesystem_entries(root, workflow_dir, limit)
        if entries or mode == "filesystem":
            return "filesystem", discovered_count, entries

    if mode in {"auto", "git-tree"}:
        discovered_count, entries = git_tree_entries(root, workflow_dir, limit)
        if entries or mode == "git-tree":
            return "git-tree", discovered_count, entries

    raise ManifestError(f"no workflow files found under {workflow_dir}")


def compatibility_entries(workflows: list[dict[str, str | int]]) -> list[dict[str, str | int]]:
    return [
        {
            "path": str(row["relative_path"]),
            "sha256": str(row["sha256"]),
            "bytes": int(row["byte_size"]),
        }
        for row in workflows
    ]


def build_manifest(
    corpus_root: Path,
    workflow_dir: str = DEFAULT_WORKFLOW_DIR,
    limit: int | None = None,
    upstream_url: str | None = None,
    commit: str | None = None,
    mode: Mode = "auto",
) -> dict:
    root = corpus_root.resolve()
    if not root.exists():
        raise ManifestError(f"corpus root does not exist: {root}")

    normalized_workflow_dir = normalize_relpath(workflow_dir)
    source_mode, discovered_count, workflows = manifest_entries(root, normalized_workflow_dir, mode, limit)
    if not workflows:
        raise ManifestError(f"no workflow files found under {normalized_workflow_dir}")

    resolved_upstream_url = upstream_url or git_upstream_url(root)
    resolved_commit = commit or git_commit(root)
    return {
        "report_kind": "taudit.arxiv_corpus_manifest.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "upstream_url": resolved_upstream_url,
        "commit": resolved_commit,
        "corpus_root": str(root),
        "workflow_root": str(root / normalized_workflow_dir),
        "workflow_dir": normalized_workflow_dir,
        "source_mode": source_mode,
        "workflow_count": len(workflows),
        "discovered_workflow_count": discovered_count,
        "limit": limit,
        "workflows": workflows,
        "entries": compatibility_entries(workflows),
        "claim_ceiling": "corpus identity and digest manifest only",
    }


def make_manifest(
    root: Path,
    *,
    upstream_url: str = DEFAULT_UPSTREAM_URL,
    commit: str | None = None,
    limit: int | None = None,
) -> dict:
    return build_manifest(root, upstream_url=upstream_url, commit=commit, limit=limit)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus_root", nargs="?", type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--workflow-dir", default=DEFAULT_WORKFLOW_DIR)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--upstream-url")
    parser.add_argument("--commit")
    parser.add_argument("--mode", choices=["auto", "filesystem", "git-tree"], default="auto")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    corpus_root = args.corpus_root or args.root
    if corpus_root is None:
        print("error: corpus root is required", file=sys.stderr)
        return 2

    try:
        manifest = build_manifest(
            corpus_root,
            workflow_dir=args.workflow_dir,
            limit=args.limit,
            upstream_url=args.upstream_url,
            commit=args.commit,
            mode=args.mode,
        )
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
