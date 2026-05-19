from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock


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

    def test_extract_changelog_section_requires_complete_tag_boundary(self) -> None:
        changelog = textwrap.dedent(
            """
            # Changelog

            ## v1.2.0-rc.10
            - wrong prerelease

            ## v1.2.0-rc.1
            - right prerelease

            ## v1.2.0
            - stable release
            """
        ).strip()

        prerelease = release_harness.extract_changelog_section(changelog, "v1.2.0-rc.1")
        self.assertIn("right prerelease", prerelease)
        self.assertNotIn("wrong prerelease", prerelease)

        stable = release_harness.extract_changelog_section(changelog, "v1.2.0")
        self.assertIn("stable release", stable)
        self.assertNotIn("right prerelease", stable)

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

    def test_conformance_command_uses_adr_0020_json_shape(self) -> None:
        root = pathlib.Path("C:/work/taudit")

        command = release_harness.conformance_harness_command(root)

        self.assertEqual(command[0], sys.executable)
        self.assertEqual(
            command[1],
            str(root / "scripts" / "conformance_harness.py"),
        )
        self.assertEqual(command[2:], ["--root", str(root), "--format", "json"])

    def test_check_release_blocks_rc_when_conformance_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            self._write_minimal_release_tree(root, "1.2.0-rc.1", "v1.2.0-rc.1")

            with (
                mock.patch.object(
                    release_harness.subprocess,
                    "run",
                    return_value=self._conformance_process("incomplete", False, 3, pending=10),
                ),
                self.assertRaisesRegex(
                    release_harness.ReleaseHarnessError,
                    "not release-ready",
                ),
            ):
                release_harness.check_release(
                    root,
                    "v1.2.0-rc.1",
                    require_local_tag=False,
                    validate_publish_metadata=False,
                )

    def test_check_release_blocks_stable_when_conformance_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            self._write_minimal_release_tree(root, "1.2.0", "v1.2.0")

            with (
                mock.patch.object(
                    release_harness.subprocess,
                    "run",
                    return_value=self._conformance_process("incomplete", False, 3, pending=10),
                ),
                self.assertRaisesRegex(
                    release_harness.ReleaseHarnessError,
                    "not stable-release-ready",
                ),
            ):
                release_harness.check_release(
                    root,
                    "v1.2.0",
                    require_local_tag=False,
                    validate_publish_metadata=False,
                )

    def test_check_release_accepts_stable_full_conformance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            self._write_minimal_release_tree(root, "1.2.0", "v1.2.0")

            with mock.patch.object(
                release_harness.subprocess,
                "run",
                return_value=self._conformance_process("pass", True, 0, pending=0),
            ):
                plan = release_harness.check_release(
                    root,
                    "v1.2.0",
                    require_local_tag=False,
                    validate_publish_metadata=False,
                )

            self.assertFalse(plan.prerelease)
            self.assertIsNotNone(plan.conformance)
            self.assertTrue(plan.conformance.full_conformance)

    def test_ensure_github_release_creates_prerelease_with_latest_false(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            (root / "crates" / "taudit-cli").mkdir(parents=True)
            (root / "CHANGELOG.md").write_text(
                "## v1.2.0-rc.1\n\n- release body\n",
                encoding="utf-8",
            )
            (root / "crates" / "taudit-cli" / "Cargo.toml").write_text(
                "[package]\nname = \"taudit\"\nversion = \"1.2.0-rc.1\"\n",
                encoding="utf-8",
            )
            commands: list[list[str]] = []

            with (
                mock.patch.object(release_harness, "gh_release_exists", return_value=False),
                mock.patch.object(
                    release_harness,
                    "run_checked",
                    side_effect=lambda argv, _root: commands.append(argv),
                ),
            ):
                plan = release_harness.ensure_github_release(
                    root,
                    "v1.2.0-rc.1",
                    repo="owner/taudit",
                    validate_publish_metadata=False,
                    validate_conformance=False,
                )

            self.assertTrue(plan.prerelease)
            self.assertEqual(commands[0][:5], ["gh", "release", "create", "v1.2.0-rc.1", "--verify-tag"])
            self.assertIn("--prerelease", commands[0])
            self.assertIn("--latest=false", commands[0])
            self.assertNotIn("--latest", commands[0])
            self.assertEqual(commands[0][-2:], ["--repo", "owner/taudit"])
            self.assertEqual(commands[1], ["gh", "release", "view", "v1.2.0-rc.1", "--repo", "owner/taudit"])

    def test_ensure_github_release_normalizes_existing_prerelease_with_latest_false(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = pathlib.Path(tmp_dir)
            (root / "crates" / "taudit-cli").mkdir(parents=True)
            (root / "CHANGELOG.md").write_text(
                "## v1.2.0-rc.1\n\n- release body\n",
                encoding="utf-8",
            )
            (root / "crates" / "taudit-cli" / "Cargo.toml").write_text(
                "[package]\nname = \"taudit\"\nversion = \"1.2.0-rc.1\"\n",
                encoding="utf-8",
            )
            commands: list[list[str]] = []

            with (
                mock.patch.object(release_harness, "gh_release_exists", return_value=True),
                mock.patch.object(
                    release_harness,
                    "run_checked",
                    side_effect=lambda argv, _root: commands.append(argv),
                ),
            ):
                plan = release_harness.ensure_github_release(
                    root,
                    "v1.2.0-rc.1",
                    repo=None,
                    validate_publish_metadata=False,
                    validate_conformance=False,
                )

            self.assertTrue(plan.prerelease)
            self.assertEqual(commands[0][:4], ["gh", "release", "edit", "v1.2.0-rc.1"])
            self.assertIn("--prerelease", commands[0])
            self.assertIn("--latest=false", commands[0])
            self.assertNotIn("--latest", commands[0])
            self.assertEqual(commands[1], ["gh", "release", "view", "v1.2.0-rc.1"])

    def _write_minimal_release_tree(self, root: pathlib.Path, version: str, tag: str) -> None:
        (root / "crates" / "taudit-cli").mkdir(parents=True)
        (root / "CHANGELOG.md").write_text(
            f"## {tag}\n\n- release body\n",
            encoding="utf-8",
        )
        (root / "crates" / "taudit-cli" / "Cargo.toml").write_text(
            f"[package]\nname = \"taudit\"\nversion = \"{version}\"\n",
            encoding="utf-8",
        )

    def _conformance_process(
        self,
        status: str,
        full_conformance: bool,
        exit_code: int,
        *,
        pending: int,
    ) -> subprocess.CompletedProcess[str]:
        stdout = textwrap.dedent(
            f"""
            {{
              "schema": "taudit.conformance-harness.summary.v0",
              "harness": "adr-0020-offline-skeleton",
              "status": "{status}",
              "full_conformance": {str(full_conformance).lower()},
              "counts": {{
                "pass": 18,
                "fail": 0,
                "pending": {pending}
              }},
              "checks": []
            }}
            """
        ).strip()
        return subprocess.CompletedProcess(
            ["python", "scripts/conformance_harness.py"],
            exit_code,
            stdout=stdout,
            stderr="",
        )


if __name__ == "__main__":
    unittest.main()
