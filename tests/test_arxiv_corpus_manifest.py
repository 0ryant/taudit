from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "research" / "generate_arxiv_corpus_manifest.py"
SPEC = importlib.util.spec_from_file_location("generate_arxiv_corpus_manifest", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
manifest_tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = manifest_tool
SPEC.loader.exec_module(manifest_tool)


def test_filesystem_manifest_hashes_dataset_workflows(tmp_path: pathlib.Path) -> None:
    workflows = tmp_path / "dataset" / "workflows"
    workflows.mkdir(parents=True)
    first = workflows / "a.yml"
    second = workflows / "nested" / "b.yaml"
    second.parent.mkdir()
    first.write_bytes(b"name: a\n")
    second.write_bytes(b"name: b\n")

    manifest = manifest_tool.build_manifest(tmp_path, commit="abc123")

    assert manifest["commit"] == "abc123"
    assert manifest["source_mode"] == "filesystem"
    assert manifest["workflow_count"] == 2
    assert [entry["relative_path"] for entry in manifest["workflows"]] == [
        "dataset/workflows/a.yml",
        "dataset/workflows/nested/b.yaml",
    ]
    assert manifest["workflows"][0]["sha256"] == hashlib.sha256(b"name: a\n").hexdigest()
    assert manifest["entries"][0]["path"] == "dataset/workflows/a.yml"


def test_manifest_limit_is_deterministic(tmp_path: pathlib.Path) -> None:
    for name in ["c.yml", "a.yml", "b.yaml"]:
        (tmp_path / name).write_bytes(f"name: {name}\n".encode("utf-8"))

    manifest = manifest_tool.build_manifest(
        tmp_path,
        workflow_dir=".",
        commit="abc123",
        limit=2,
        mode="filesystem",
    )

    assert [pathlib.Path(entry["relative_path"]).name for entry in manifest["workflows"]] == [
        "a.yml",
        "b.yaml",
    ]
    assert manifest["discovered_workflow_count"] == 3


def test_git_tree_mode_handles_workflows_without_checkout(tmp_path: pathlib.Path) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    workflows = tmp_path / "dataset" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_bytes(b"name: ci\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "fixture"], cwd=tmp_path, check=True, capture_output=True)

    manifest = manifest_tool.build_manifest(tmp_path, mode="git-tree")

    assert manifest["source_mode"] == "git-tree"
    assert manifest["workflow_count"] == 1
    assert manifest["workflows"][0]["relative_path"] == "dataset/workflows/ci.yml"
