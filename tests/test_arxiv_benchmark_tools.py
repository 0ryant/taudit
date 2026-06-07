from __future__ import annotations

import csv
import importlib.util
import json
import pathlib
import re
import sys

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[1]
NORMALIZER_PATH = ROOT / "scripts" / "research" / "normalize_taudit_arxiv_findings.py"
RUNNER_PATH = ROOT / "scripts" / "research" / "run_arxiv_taudit_benchmark.py"
RULE_MAP_PATH = ROOT / "docs" / "research" / "arxiv-taudit-rule-map.csv"


def load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


normalizer = load_module("normalize_taudit_arxiv_findings", NORMALIZER_PATH)
runner = load_module("run_arxiv_taudit_benchmark", RUNNER_PATH)


def report_with_findings(*findings: dict) -> dict:
    return {
        "schema_version": "1.0.0",
        "graph": {
            "source": {"file": ".github/workflows/ci.yml"},
            "nodes": [],
            "edges": [],
            "completeness": "complete",
        },
        "findings": list(findings),
        "summary": {"total_findings": len(findings), "completeness": "complete"},
    }


def finding(rule_id: str, severity: str = "high") -> dict:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "category": rule_id,
        "nodes_involved": [1, 2],
        "message": f"{rule_id} message",
        "fingerprint": "a" * 32,
        "source": "built-in",
    }


def test_rule_map_loads_and_preserves_upstream_ptw_alias() -> None:
    rule_map = normalizer.load_rule_map(RULE_MAP_PATH)

    assert rule_map["trigger_context_mismatch"].arxiv_weakness == "PTW"
    assert rule_map["trigger_context_mismatch"].upstream_raw_weakness == "TMW"
    assert rule_map["unpinned_action"].arxiv_weakness == "UDW"


def test_rule_map_covers_indexed_gha_rules_and_runtime_only_rules() -> None:
    index = (ROOT / "docs" / "rules" / "index.md").read_text(encoding="utf-8")
    indexed_rules = set()
    for line in index.splitlines():
        match = re.match(r"\| \[([^\]]+)\].*\| ([^|]+) \| ([^|]+) \|$", line)
        if not match:
            continue
        platform = match.group(3).strip()
        if "GHA" in platform and "ADO only" not in platform and "GitLab only" not in platform:
            indexed_rules.add(match.group(1))

    runtime_only = {
        "oidc_identity_in_untrusted_context",
        "action_major_version_pin_without_sha",
        "known_compromised_action_ref",
        "docker_socket_exposed_to_ci_step",
        "privileged_container_in_ci_step",
    }
    mapped = set(normalizer.load_rule_map(RULE_MAP_PATH))

    assert sorted((indexed_rules | runtime_only) - mapped) == []


def test_normalizer_maps_findings_and_skips_out_of_scope_by_default() -> None:
    rule_map = normalizer.load_rule_map(RULE_MAP_PATH)
    rows = normalizer.normalize_report(
        report_with_findings(
            finding("unpinned_action"),
            finding("trigger_context_mismatch"),
            finding("gha_toolcache_absolute_path_downgrade", "info"),
        ),
        rule_map,
    )

    assert [row["arxiv_weakness"] for row in rows] == ["UDW", "PTW"]
    assert rows[1]["upstream_raw_weakness"] == "TMW"
    assert rows[0]["line"] == "unknown"


def test_normalizer_fails_closed_on_unmapped_rule() -> None:
    rule_map = normalizer.load_rule_map(RULE_MAP_PATH)

    with pytest.raises(normalizer.ArxivNormalizationError, match="not_in_map"):
        normalizer.normalize_report(report_with_findings(finding("not_in_map")), rule_map)


def test_normalizer_wraps_missing_input_as_contract_error(tmp_path: pathlib.Path) -> None:
    rule_map = normalizer.load_rule_map(RULE_MAP_PATH)

    with pytest.raises(normalizer.ArxivNormalizationError, match="cannot read input"):
        normalizer.normalize_paths([tmp_path / "missing.json"], rule_map)


def test_runner_records_raw_timing_and_normalized_findings(tmp_path: pathlib.Path) -> None:
    workflow = tmp_path / "ci.yml"
    workflow.write_text("name: ci\non: push\njobs: {}\n", encoding="utf-8")
    fake = tmp_path / "fake_taudit.py"
    fake.write_text(
        """
import json
import sys

workflow = sys.argv[2]
print(json.dumps({
  "schema_version": "1.0.0",
  "graph": {"source": {"file": workflow}, "nodes": [], "edges": [], "completeness": "complete"},
  "findings": [{
    "rule_id": "unpinned_action",
    "severity": "high",
    "category": "unpinned_action",
    "nodes_involved": [1],
    "message": "mutable action ref",
    "fingerprint": "b" * 32,
    "source": "built-in"
  }],
  "summary": {"total_findings": 1, "completeness": "complete"}
}))
""".strip(),
        encoding="utf-8",
    )

    config = runner.RunConfig(
        taudit_cmd=[sys.executable, str(fake)],
        output_dir=tmp_path / "out",
        rule_map=RULE_MAP_PATH,
        repeat=2,
        timeout_seconds=5,
    )
    summary = runner.run_benchmark([workflow], tmp_path, config)

    assert summary["workflow_count"] == 1
    assert summary["status_counts"] == {"ok": 2}
    assert summary["by_weakness"] == {"UDW": 1}
    assert (tmp_path / "out" / "timings.csv").exists()
    assert (tmp_path / "out" / "findings.jsonl").read_text(encoding="utf-8").count("\n") == 1


def test_runner_preserves_artifacts_for_nonzero_repeats(tmp_path: pathlib.Path) -> None:
    workflow = tmp_path / "ci.yml"
    workflow.write_text("name: ci\non: push\njobs: {}\n", encoding="utf-8")
    fake = tmp_path / "fake_taudit.py"
    fake.write_text(
        """
import sys

print('{"partial": true}')
print("scanner exploded", file=sys.stderr)
sys.exit(7)
""".strip(),
        encoding="utf-8",
    )

    config = runner.RunConfig(
        taudit_cmd=[sys.executable, str(fake)],
        output_dir=tmp_path / "out",
        rule_map=RULE_MAP_PATH,
        repeat=2,
        timeout_seconds=5,
    )
    summary = runner.run_benchmark([workflow], tmp_path, config)

    assert summary["status_counts"] == {"nonzero_exit": 2}
    assert summary["finding_count"] == 0
    summary_path = tmp_path / "out" / "summary.json"
    timings_path = tmp_path / "out" / "timings.csv"
    assert json.loads(summary_path.read_text(encoding="utf-8"))["status_counts"] == {"nonzero_exit": 2}

    timing_rows = list(csv.DictReader(timings_path.open(encoding="utf-8", newline="")))
    assert [row["status"] for row in timing_rows] == ["nonzero_exit", "nonzero_exit"]
    assert [row["exit_code"] for row in timing_rows] == ["7", "7"]
    assert pathlib.Path(timing_rows[0]["stdout_path"]).read_text(encoding="utf-8") == '{"partial": true}\n'
    assert pathlib.Path(timing_rows[0]["stderr_path"]).read_text(encoding="utf-8") == "scanner exploded\n"


def test_runner_records_launch_errors_without_aborting(tmp_path: pathlib.Path) -> None:
    workflow = tmp_path / "ci.yml"
    workflow.write_text("name: ci\non: push\njobs: {}\n", encoding="utf-8")
    missing_taudit = tmp_path / "missing-taudit"

    config = runner.RunConfig(
        taudit_cmd=[str(missing_taudit)],
        output_dir=tmp_path / "out",
        rule_map=RULE_MAP_PATH,
        repeat=1,
        timeout_seconds=5,
    )
    summary = runner.run_benchmark([workflow], tmp_path, config)

    assert summary["status_counts"] == {"launch_error": 1}
    timing_rows = list(csv.DictReader((tmp_path / "out" / "timings.csv").open(encoding="utf-8", newline="")))
    stderr_text = pathlib.Path(timing_rows[0]["stderr_path"]).read_text(encoding="utf-8")
    assert timing_rows[0]["exit_code"] == ""
    assert "Error" in stderr_text
    assert (tmp_path / "out" / "summary.json").exists()


def test_runner_writes_summary_when_normalization_fails(tmp_path: pathlib.Path) -> None:
    workflow = tmp_path / "ci.yml"
    workflow.write_text("name: ci\non: push\njobs: {}\n", encoding="utf-8")
    fake = tmp_path / "fake_taudit.py"
    fake.write_text(
        """
import json
import sys

workflow = sys.argv[2]
print(json.dumps({
  "schema_version": "1.0.0",
  "graph": {"source": {"file": workflow}, "nodes": [], "edges": [], "completeness": "complete"},
  "findings": [{
    "rule_id": "not_in_map",
    "severity": "high",
    "category": "not_in_map",
    "nodes_involved": [1],
    "message": "unknown rule",
    "fingerprint": "c" * 32,
    "source": "built-in"
  }],
  "summary": {"total_findings": 1, "completeness": "complete"}
}))
""".strip(),
        encoding="utf-8",
    )

    config = runner.RunConfig(
        taudit_cmd=[sys.executable, str(fake)],
        output_dir=tmp_path / "out",
        rule_map=RULE_MAP_PATH,
        repeat=1,
        timeout_seconds=5,
    )
    summary = runner.run_benchmark([workflow], tmp_path, config)

    assert summary["status_counts"] == {"ok": 1}
    assert summary["normalization_status"] == "error"
    assert summary["normalization_error_count"] == 1
    assert "not_in_map" in summary["normalization_errors"][0]["error"]
    assert (tmp_path / "out" / "timings.csv").exists()
    assert (tmp_path / "out" / "summary.json").exists()


def test_runner_main_returns_one_when_any_repeat_fails(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow = tmp_path / "ci.yml"
    workflow.write_text("name: ci\non: push\njobs: {}\n", encoding="utf-8")

    def fake_run_benchmark(
        workflows: list[pathlib.Path],
        workflow_root: pathlib.Path | None,
        config: runner.RunConfig,
    ) -> dict:
        assert workflows == [workflow.resolve()]
        assert workflow_root == tmp_path
        assert config.repeat == 1
        return {"status_counts": {"nonzero_exit": 1}}

    monkeypatch.setattr(runner, "run_benchmark", fake_run_benchmark)

    code = runner.main(
        [
            "--workflows-root",
            str(tmp_path),
            "--output-dir",
            str(tmp_path / "out"),
            "--taudit",
            str(tmp_path / "taudit"),
            "--repeat",
            "1",
        ]
    )

    assert code == 1


def test_runner_main_returns_one_when_normalization_fails(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow = tmp_path / "ci.yml"
    workflow.write_text("name: ci\non: push\njobs: {}\n", encoding="utf-8")

    def fake_run_benchmark(
        workflows: list[pathlib.Path],
        workflow_root: pathlib.Path | None,
        config: runner.RunConfig,
    ) -> dict:
        assert workflows == [workflow.resolve()]
        assert workflow_root == tmp_path
        assert config.repeat == 1
        return {"status_counts": {"ok": 1}, "normalization_error_count": 1}

    monkeypatch.setattr(runner, "run_benchmark", fake_run_benchmark)

    code = runner.main(
        [
            "--workflows-root",
            str(tmp_path),
            "--output-dir",
            str(tmp_path / "out"),
            "--taudit",
            str(tmp_path / "taudit"),
            "--repeat",
            "1",
        ]
    )

    assert code == 1


def test_runner_decodes_timeout_output_bytes() -> None:
    assert runner.process_output_text(b"hello") == "hello"
    assert runner.process_output_text(None, "timeout") == "timeout"
