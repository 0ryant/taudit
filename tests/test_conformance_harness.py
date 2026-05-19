from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "conformance_harness.py"
SPEC = importlib.util.spec_from_file_location("conformance_harness", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
conformance_harness = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = conformance_harness
SPEC.loader.exec_module(conformance_harness)


def write_minimal_harness_repo(root: pathlib.Path) -> None:
    for relative in conformance_harness.DEFAULT_REQUIRED_PATHS:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix == ".json":
            path.write_text('{"ok": true}\n', encoding="utf-8")
        else:
            path.write_text("placeholder\n", encoding="utf-8")


class ConformanceHarnessTests(unittest.TestCase):
    def test_real_harness_fails_stale_minimal_current_profile_examples(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            write_minimal_harness_repo(root)

            summary = conformance_harness.run_harness(root, run_generated=False)

        self.assertEqual(summary["status"], "fail")
        self.assertFalse(summary["full_conformance"])
        self.assertGreater(summary["counts"]["pass"], 0)
        self.assertGreater(summary["counts"]["fail"], 0)
        self.assertEqual(summary["counts"]["pending"], 0)
        self.assertNotIn("placeholder", {check["kind"] for check in summary["checks"]})

    def test_checked_in_offline_contract_gates_have_no_pending_placeholders(self) -> None:
        summary = conformance_harness.run_harness(ROOT, run_generated=False)

        self.assertEqual(summary["status"], "pass")
        self.assertFalse(summary["full_conformance"])
        self.assertGreater(summary["counts"]["pass"], 0)
        self.assertEqual(summary["counts"]["fail"], 0)
        self.assertEqual(summary["counts"]["pending"], 0)
        self.assertNotIn("placeholder", {check["kind"] for check in summary["checks"]})
        self.assertIn(
            "current_profile.report_json",
            {check["id"] for check in summary["checks"] if check["status"] == "pass"},
        )

    def test_offline_skeleton_fails_when_configured_path_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            write_minimal_harness_repo(root)
            missing_path = root / "contracts" / "schemas" / "taudit-report.schema.json"
            missing_path.unlink()

            summary = conformance_harness.run_harness(root, run_generated=False)

        self.assertEqual(summary["status"], "fail")
        self.assertGreaterEqual(summary["counts"]["fail"], 1)
        failed = [check for check in summary["checks"] if check["status"] == "fail"]
        self.assertEqual(failed[0]["id"], "presence.contracts/schemas/taudit-report.schema.json")
        self.assertEqual(failed[0]["path"], "contracts/schemas/taudit-report.schema.json")

    def test_offline_skeleton_fails_invalid_contract_example_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            write_minimal_harness_repo(root)
            bad_example = root / "contracts" / "examples" / "clean-report.json"
            bad_example.write_text('{"broken": true\n', encoding="utf-8")

            summary = conformance_harness.run_harness(root, run_generated=False)

        self.assertEqual(summary["status"], "fail")
        failed = [check for check in summary["checks"] if check["status"] == "fail"]
        self.assertEqual(failed[0]["id"], "json.contracts/examples/clean-report.json")
        self.assertIn("invalid JSON", failed[0]["message"])

    def test_main_prints_json_summary_and_returns_nonzero_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            write_minimal_harness_repo(root)
            (root / "contracts" / "examples" / "clean-report.json").write_text(
                "not json\n",
                encoding="utf-8",
            )
            stdout = StringIO()

            with redirect_stdout(stdout):
                exit_code = conformance_harness.main(
                    ["--root", str(root), "--format", "json", "--skip-generated"]
                )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["status"], "fail")
        self.assertGreaterEqual(payload["counts"]["fail"], 1)

    def test_main_returns_distinct_nonzero_when_pending_checks_remain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            write_minimal_harness_repo(root)
            stdout = StringIO()

            with redirect_stdout(stdout):
                exit_code = conformance_harness.main(
                    ["--root", str(root), "--format", "json", "--skip-generated"]
                )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["counts"]["pending"], 0)


if __name__ == "__main__":
    unittest.main()
