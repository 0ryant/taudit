from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "corpus_runner.py"
SCHEMA_PATH = ROOT / "schemas" / "corpus-manifest.v1.json"
SPEC = importlib.util.spec_from_file_location("corpus_runner", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
corpus_runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = corpus_runner
SPEC.loader.exec_module(corpus_runner)


def write_manifest(tmp_path: pathlib.Path, entries: list[dict]) -> pathlib.Path:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "$schema": "https://taudit.dev/schemas/corpus-manifest.v1.json",
                "schema_version": "1.0.0",
                "name": "test corpus",
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )
    return manifest_path


def entry(
    entry_id: str,
    provider: str,
    parser: str,
    completeness: str,
    gap_kinds: list[str] | None = None,
) -> dict:
    return {
        "id": entry_id,
        "provider": provider,
        "source": {
            "url": f"https://example.test/{entry_id}.yml",
            "commit": "0123456789abcdef0123456789abcdef01234567",
            "path": ".github/workflows/ci.yml",
        },
        "license": {
            "basis": "repo_license",
            "name": "MIT",
            "url": "https://example.test/LICENSE",
        },
        "expected": {
            "parser": parser,
            "completeness": completeness,
            "gap_kinds": gap_kinds or [],
        },
        "local": {
            "path": f"corpus/cache/{entry_id}.yml",
            "cache": {
                "mode": "fetch_cache",
                "key": entry_id,
                "digest": "sha256:" + ("a" * 64),
            },
        },
        "tags": ["unit", provider],
    }


def test_schema_file_is_valid_json() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["$id"] == "https://taudit.dev/schemas/corpus-manifest.v1.json"
    assert schema["$defs"]["CorpusEntry"]["required"] == [
        "id",
        "provider",
        "source",
        "license",
        "expected",
        "local",
        "tags",
    ]


def test_validate_manifest_emits_deterministic_expected_histograms(tmp_path: pathlib.Path) -> None:
    manifest_path = write_manifest(
        tmp_path,
        [
            entry("partial-a", "gitlab_ci", "taudit-parse-gitlab", "partial", ["structural"]),
            entry("complete-a", "github_actions", "taudit-parse-gha", "complete"),
            entry("unknown-a", "azure_pipelines", "taudit-parse-ado", "unknown", ["opaque"]),
        ],
    )

    manifest = corpus_runner.load_manifest(manifest_path)
    summary = corpus_runner.summarize_expected(manifest, manifest_path)

    assert summary["entry_count"] == 3
    assert summary["histograms"]["completeness"] == {
        "complete": 1,
        "failure": 0,
        "partial": 1,
        "unknown": 1,
    }
    assert summary["histograms"]["gap_kinds"] == {
        "expression": 0,
        "opaque": 1,
        "structural": 1,
        "unknown": 0,
    }
    assert [item["id"] for item in summary["entries"]] == [
        "complete-a",
        "partial-a",
        "unknown-a",
    ]


def test_release_evidence_summary_contract_is_validated(tmp_path: pathlib.Path) -> None:
    manifest_path = write_manifest(
        tmp_path,
        [
            entry("complete-a", "github_actions", "taudit-parse-gha", "complete"),
            entry("partial-a", "gitlab_ci", "taudit-parse-gitlab", "partial", ["structural"]),
            entry("unknown-a", "azure_pipelines", "taudit-parse-ado", "unknown", ["opaque"]),
        ],
    )

    manifest = corpus_runner.load_manifest(manifest_path)
    summary = corpus_runner.summarize_expected(manifest, manifest_path)

    assert summary["report_kind"] == "taudit.corpus.summary"
    assert summary["release_evidence"] == {
        "contract": "taudit-corpus-report.v1",
        "claim_ceiling": "parser-completeness-counts-only",
        "network_mode": "offline",
        "fetch_performed": False,
    }
    corpus_runner.validate_release_summary(summary)


def test_release_summary_validation_rejects_missing_histogram_bucket(tmp_path: pathlib.Path) -> None:
    manifest_path = write_manifest(
        tmp_path,
        [entry("complete-a", "github_actions", "taudit-parse-gha", "complete")],
    )
    manifest = corpus_runner.load_manifest(manifest_path)
    summary = corpus_runner.summarize_expected(manifest, manifest_path)
    del summary["histograms"]["completeness"]["failure"]

    with pytest.raises(corpus_runner.CorpusManifestError, match=r"completeness.failure"):
        corpus_runner.validate_release_summary(summary)


def test_check_report_command_validates_existing_summary(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest_path = write_manifest(
        tmp_path,
        [entry("complete-a", "github_actions", "taudit-parse-gha", "complete")],
    )
    manifest = corpus_runner.load_manifest(manifest_path)
    summary = corpus_runner.summarize_expected(manifest, manifest_path)
    report_path = tmp_path / "corpus-report.json"
    report_path.write_text(json.dumps(summary), encoding="utf-8")

    rc = corpus_runner.main(["check-report", "--report", str(report_path)])

    assert rc == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["status"] == "pass"
    assert receipt["checked_report"] == str(report_path.resolve())
    assert receipt["entry_count"] == 1
    assert receipt["histograms"]["completeness"]["complete"] == 1


def test_invalid_manifest_is_rejected_with_path_context(tmp_path: pathlib.Path) -> None:
    bad = entry("bad-a", "github_actions", "taudit-parse-gha", "complete")
    del bad["license"]
    manifest_path = write_manifest(tmp_path, [bad])

    with pytest.raises(corpus_runner.CorpusManifestError, match=r"entries\[0\]\.license"):
        corpus_runner.load_manifest(manifest_path)


def test_invalid_schema_version_is_rejected(tmp_path: pathlib.Path) -> None:
    manifest_path = write_manifest(
        tmp_path,
        [entry("complete-a", "github_actions", "taudit-parse-gha", "complete")],
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema_version"] = "banana"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(corpus_runner.CorpusManifestError, match=r"schema_version"):
        corpus_runner.load_manifest(manifest_path)


def test_run_manifest_records_timeout_as_failure(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    local_file = tmp_path / "ci.yml"
    local_file.write_text("name: ci\n", encoding="utf-8")
    manifest_entry = entry("slow-a", "github_actions", "taudit-parse-gha", "complete")
    manifest_entry["local"]["path"] = str(local_file)
    manifest_path = write_manifest(tmp_path, [manifest_entry])
    manifest = corpus_runner.load_manifest(manifest_path)

    def fake_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["taudit"], timeout=2.0)

    monkeypatch.setattr(corpus_runner.subprocess, "run", fake_run)

    summary = corpus_runner.run_manifest(
        manifest,
        manifest_path,
        corpus_runner.RunConfig(taudit="taudit", timeout_seconds=2.0),
    )

    assert summary["histograms"]["completeness"] == {
        "complete": 0,
        "failure": 1,
        "partial": 0,
        "unknown": 0,
    }
    assert summary["entries"][0]["failure_kind"] == "timeout"


def test_run_manifest_uses_scan_output_for_completeness_and_gap_kinds(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    local_file = tmp_path / "gitlab-ci.yml"
    local_file.write_text("stages: [test]\n", encoding="utf-8")
    manifest_entry = entry("scan-a", "gitlab_ci", "taudit-parse-gitlab", "complete")
    manifest_entry["local"]["path"] = str(local_file)
    manifest_path = write_manifest(tmp_path, [manifest_entry])
    manifest = corpus_runner.load_manifest(manifest_path)

    report = {
        "graph": {
            "completeness": "partial",
            "completeness_gap_kinds": ["expression", "structural"],
        },
        "summary": {"total_findings": 4},
    }

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["taudit"],
            returncode=0,
            stdout=json.dumps(report),
            stderr="",
        )

    monkeypatch.setattr(corpus_runner.subprocess, "run", fake_run)

    summary = corpus_runner.run_manifest(
        manifest,
        manifest_path,
        corpus_runner.RunConfig(taudit="taudit", timeout_seconds=5.0),
    )

    assert summary["histograms"]["completeness"] == {
        "complete": 0,
        "failure": 0,
        "partial": 1,
        "unknown": 0,
    }
    assert summary["histograms"]["gap_kinds"]["expression"] == 1
    assert summary["histograms"]["gap_kinds"]["structural"] == 1
    assert summary["entries"][0]["findings"] == 4


def test_main_rejects_non_positive_timeout(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest_path = write_manifest(
        tmp_path,
        [entry("complete-a", "github_actions", "taudit-parse-gha", "complete")],
    )

    rc = corpus_runner.main(
        [
            "--manifest",
            str(manifest_path),
            "run",
            "--timeout-seconds",
            "0",
        ]
    )

    assert rc == 2
    assert "timeout-seconds must be positive" in capsys.readouterr().err
