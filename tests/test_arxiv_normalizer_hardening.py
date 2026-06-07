from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[1]
NORMALIZER_PATH = ROOT / "scripts" / "research" / "normalize_taudit_arxiv_findings.py"

MAP_COLUMNS = [
    "taudit_rule_id",
    "arxiv_weakness",
    "upstream_raw_weakness",
    "benchmark_scope",
    "enabled_by_default",
    "mapping_status",
    "rationale",
    "evidence",
]


def load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


normalizer = load_module("normalize_taudit_arxiv_findings_hardening", NORMALIZER_PATH)


def write_rule_map(
    tmp_path: pathlib.Path,
    *,
    rule_id: str = "unpinned_action",
    arxiv_weakness: str = "UDW",
    upstream_raw_weakness: str = "UDW",
) -> pathlib.Path:
    row = [
        rule_id,
        arxiv_weakness,
        upstream_raw_weakness,
        "gha_default",
        "yes",
        "proposed",
        "rationale",
        "evidence",
    ]
    path = tmp_path / "rule-map.csv"
    path.write_text(
        ",".join(MAP_COLUMNS) + "\n" + ",".join(row) + "\n",
        encoding="utf-8",
    )
    return path


def report_json(rule_id: str = "unpinned_action") -> dict:
    return {
        "graph": {"source": {"file": ".github/workflows/ci.yml"}},
        "findings": [
            {
                "rule_id": rule_id,
                "category": rule_id,
                "severity": "high",
                "nodes_involved": [{"b": 2, "a": 1}],
            }
        ],
    }


def test_rule_map_fails_closed_on_unknown_arxiv_taxonomy_label(tmp_path: pathlib.Path) -> None:
    rule_map = write_rule_map(tmp_path, arxiv_weakness="NOT_A_CLASS", upstream_raw_weakness="UDW")

    with pytest.raises(normalizer.ArxivNormalizationError, match="unknown arXiv weakness"):
        normalizer.load_rule_map(rule_map)


def test_rule_map_fails_closed_on_unknown_upstream_taxonomy_label(tmp_path: pathlib.Path) -> None:
    rule_map = write_rule_map(tmp_path, upstream_raw_weakness="NOT_A_CLASS")

    with pytest.raises(normalizer.ArxivNormalizationError, match="unknown upstream raw weakness"):
        normalizer.load_rule_map(rule_map)


def test_main_reports_missing_rule_map_without_traceback(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report_json()), encoding="utf-8")

    exit_code = normalizer.main([str(report_path), "--rule-map", str(tmp_path / "missing.csv")])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.err.startswith("error:")
    assert "Traceback" not in captured.err


def test_main_reports_invalid_report_shape_without_traceback(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rule_map = write_rule_map(tmp_path)
    report_path = tmp_path / "report.json"
    report_path.write_text("[]\n", encoding="utf-8")

    exit_code = normalizer.main([str(report_path), "--rule-map", str(rule_map)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "report must be a JSON object" in captured.err
    assert "Traceback" not in captured.err


def test_normalized_rows_and_csv_output_are_deterministic(tmp_path: pathlib.Path) -> None:
    rule_map = normalizer.load_rule_map(write_rule_map(tmp_path))

    rows = normalizer.normalize_report(report_json(), rule_map)
    assert rows[0]["nodes_involved"] == '[{"a":1,"b":2}]'

    output = tmp_path / "findings.csv"
    normalizer.write_csv(output, rows)
    data = output.read_bytes()
    assert b"\r\n" not in data
    assert data.endswith(b"\n")
