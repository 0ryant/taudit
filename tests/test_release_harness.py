from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "release_harness.py"
SPEC = importlib.util.spec_from_file_location("release_harness", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
release_harness = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_harness
SPEC.loader.exec_module(release_harness)


class ReleaseHarnessTests(unittest.TestCase):
    def test_parse_tag_identifies_prerelease(self) -> None:
        version, prerelease = release_harness.parse_tag("v1.1.2-rc.1")
        self.assertEqual(version, "1.1.2-rc.1")
        self.assertTrue(prerelease)

    def test_parse_tag_rejects_invalid_prefix(self) -> None:
        with self.assertRaises(release_harness.ReleaseHarnessError):
            release_harness.parse_tag("1.1.2")

    def test_extract_changelog_section_uses_exact_heading(self) -> None:
        changelog = textwrap.dedent(
            """
            # Changelog

            ## Unreleased

            ## v1.1.2 — 2026-05-13
            
            ### Fixed
            - thing

            ## v1.1.1 — 2026-05-12
            - older
            """
        ).strip()
        section = release_harness.extract_changelog_section(changelog, "v1.1.2")
        self.assertIn("## v1.1.2 — 2026-05-13", section)
        self.assertIn("### Fixed", section)
        self.assertNotIn("v1.1.1", section)

    def test_build_release_plan_requires_matching_cli_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            (root / "crates" / "taudit-cli").mkdir(parents=True)
            (root / "CHANGELOG.md").write_text(
                "## v1.1.2\n\n- release body\n",
                encoding="utf-8",
            )
            (root / "crates" / "taudit-cli" / "Cargo.toml").write_text(
                "[package]\nname = \"taudit\"\nversion = \"1.1.2\"\n",
                encoding="utf-8",
            )

            plan = release_harness.build_release_plan(root, "v1.1.2")
            self.assertEqual(plan.title, "taudit v1.1.2")
            self.assertFalse(plan.prerelease)
            self.assertIn("release body", plan.notes)

    def test_build_release_plan_can_read_historical_source_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            (root / "crates" / "taudit-cli").mkdir(parents=True)
            subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
            subprocess.run(
                ["git", "config", "user.name", "Release Harness Test"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "release-harness@example.com"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            (root / "CHANGELOG.md").write_text(
                "## v1.1.2\n\n- release body\n",
                encoding="utf-8",
            )
            (root / "crates" / "taudit-cli" / "Cargo.toml").write_text(
                "[package]\nname = \"taudit\"\nversion = \"1.1.2\"\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
            subprocess.run(
                ["git", "commit", "-m", "release snapshot"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            subprocess.run(["git", "tag", "v1.1.2"], cwd=root, check=True, capture_output=True)

            (root / "CHANGELOG.md").write_text(
                "## v9.9.9\n\n- different body\n",
                encoding="utf-8",
            )
            (root / "crates" / "taudit-cli" / "Cargo.toml").write_text(
                "[package]\nname = \"taudit\"\nversion = \"9.9.9\"\n",
                encoding="utf-8",
            )

            plan = release_harness.build_release_plan(root, "v1.1.2", source_ref="v1.1.2")
            self.assertEqual(plan.version, "1.1.2")
            self.assertIn("release body", plan.notes)


if __name__ == "__main__":
    unittest.main()