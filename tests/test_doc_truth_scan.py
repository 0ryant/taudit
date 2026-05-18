from __future__ import annotations

import importlib.util
import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "doc_truth_scan.py"
SPEC = importlib.util.spec_from_file_location("doc_truth_scan", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
doc_truth_scan = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = doc_truth_scan
SPEC.loader.exec_module(doc_truth_scan)


def write_doc(root: pathlib.Path, rel_path: str, body: str) -> pathlib.Path:
    path = root / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def issue_codes(report: doc_truth_scan.ScanReport) -> list[str]:
    return sorted(issue.code for issue in report.issues)


def test_scan_flags_unqualified_marketplace_publication_claim(tmp_path: pathlib.Path) -> None:
    path = write_doc(
        tmp_path,
        "README.md",
        "The GitHub Marketplace action is published and installable today.\n",
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert issue_codes(report) == ["marketplace-proof-overclaim"]
    assert report.issues[0].line == 1
    assert report.issues[0].path == "README.md"


def test_scan_whitelists_proof_gated_or_planned_marketplace_context(
    tmp_path: pathlib.Path,
) -> None:
    path = write_doc(
        tmp_path,
        "docs/rc/v1.2.0/marketplace-proof-state.md",
        "\n".join(
            [
                "The GitHub Marketplace action publication is planned/pending receipt.",
                "Do not claim it is installable until docs/proof/v1.2.0-rc.1 has a receipt.",
            ]
        ),
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert report.issues == []


def test_scan_flags_stable_v1_2_claim_without_gate(tmp_path: pathlib.Path) -> None:
    path = write_doc(
        tmp_path,
        "USERGUIDE.md",
        "v1.2.0 is the stable production-ready release for all operators.\n",
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert issue_codes(report) == ["stable-rc-overclaim"]


def test_scan_allows_gated_stable_promotion_context(tmp_path: pathlib.Path) -> None:
    path = write_doc(
        tmp_path,
        "docs/rc/v1.2.0/release-readiness-checklist.md",
        "Stable promotion to v1.2.0 remains blocked until conformance and proof receipts pass.\n",
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert report.issues == []


def test_scan_flags_parser_completeness_overclaim(tmp_path: pathlib.Path) -> None:
    path = write_doc(
        tmp_path,
        "docs/parser-feature-matrix.md",
        "taudit now has complete support for all CI providers.\n",
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert issue_codes(report) == ["parser-completeness-overclaim"]


def test_scan_allows_evidence_bound_parser_completeness_context(
    tmp_path: pathlib.Path,
) -> None:
    path = write_doc(
        tmp_path,
        "docs/parser-feature-matrix.md",
        "Complete only when the parser matrix, corpus evidence, and gap histogram agree.\n",
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert report.issues == []


def test_scan_flags_stale_install_pin_and_current_cycle_language(
    tmp_path: pathlib.Path,
) -> None:
    path = write_doc(
        tmp_path,
        "docs/golden-paths.md",
        "\n".join(
            [
                "Install with cargo install taudit --version 1.0.12 --locked.",
                "v1.1.0-rc.1 is the current release candidate for this cycle.",
            ]
        ),
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert issue_codes(report) == [
        "stale-current-cycle-version",
        "stale-install-version",
    ]


def test_scan_allows_historical_changelog_version_context(tmp_path: pathlib.Path) -> None:
    path = write_doc(
        tmp_path,
        "CHANGELOG.md",
        "\n".join(
            [
                "## v1.1.0-rc.2 - 2026-05-05 (release candidate)",
                "> Superseded release candidate; stable consumers on v1.0.12 were unaffected.",
                "`v1.1.0-rc.1` is the first release candidate after the beta cycle.",
            ]
        ),
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert report.issues == []


def test_scan_allows_replaced_stale_install_pin_context(tmp_path: pathlib.Path) -> None:
    path = write_doc(
        tmp_path,
        "TODOS.md",
        "- [x] Replace stale `cargo install taudit --version 1.0.12 --locked` examples.\n",
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert report.issues == []


def test_scan_allows_marketplace_media_planning_context(tmp_path: pathlib.Path) -> None:
    path = write_doc(
        tmp_path,
        "docs/integrations/marketplace-media-shot-list.md",
        "\n".join(
            [
                "### ADO-02 - Successful task run summary",
                "- Use in:",
                "  - Azure DevOps Marketplace hero screenshot",
                "- Prerequisites:",
                "  - one real pipeline run with `Taudit@1` completed successfully",
            ]
        ),
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert report.issues == []


def test_scan_allows_future_contract_marketplace_context(tmp_path: pathlib.Path) -> None:
    path = write_doc(
        tmp_path,
        "docs/integrations/visual-studio-marketplace-extension-contract.md",
        "\n".join(
            [
                "Status: proposed v1 product contract for a future `taudit` VS Code extension",
                "published through Visual Studio Marketplace under publisher `algol`.",
            ]
        ),
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert report.issues == []


def test_scan_does_not_treat_listing_heading_as_live_claim(tmp_path: pathlib.Path) -> None:
    path = write_doc(
        tmp_path,
        "docs/integrations/marketplace-media-shot-list.md",
        "### VS Code listing\n",
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert report.issues == []


def test_scan_allows_only_after_hosted_smoke_marketplace_context(
    tmp_path: pathlib.Path,
) -> None:
    path = write_doc(
        tmp_path,
        "docs/rc/v1.2.0/workstreams/marketplace-trust-pack.md",
        "Only after hosted SHA smoke passes, publish the Marketplace listing.\n",
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert report.issues == []


def test_scan_allows_parser_completeness_where_supported(tmp_path: pathlib.Path) -> None:
    path = write_doc(
        tmp_path,
        "docs/jobs-phased-lanes.md",
        "**Goal:** three-platform parity at `Complete` where supported.\n",
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert report.issues == []


def test_scan_allows_multiline_negated_marketplace_claim(tmp_path: pathlib.Path) -> None:
    path = write_doc(
        tmp_path,
        "docs/rc/v1.2.0/charter.md",
        "\n".join(
            [
                "- The adoption layer is the marketplace trust pack: no wrapper or listing should",
                "  claim readiness until hosted runs, receipts, media, and release assets prove it.",
            ]
        ),
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert report.issues == []


def test_scan_does_not_treat_second_pass_as_conformance_pass(
    tmp_path: pathlib.Path,
) -> None:
    path = write_doc(
        tmp_path,
        "docs/rc/v1.2.0/current-output-profile-checks.md",
        "QA-04/ADR 0020 can wire the checker as the second pass after schema validation.\n",
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert report.issues == []


def test_scan_allows_internal_witness_boundary(tmp_path: pathlib.Path) -> None:
    path = write_doc(
        tmp_path,
        "docs/rules/gha_macos_codesign_cert_security_path.md",
        "It remains a classifier unless a separate internal witness proves runtime helper selection.\n",
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert report.issues == []


def test_scan_ignores_fenced_code_examples(tmp_path: pathlib.Path) -> None:
    path = write_doc(
        tmp_path,
        "docs/rc/v1.2.0/doc-truth-scan.md",
        "\n".join(
            [
                "```text",
                "The GitHub Marketplace action is published and installable today.",
                "```",
            ]
        ),
    )

    report = doc_truth_scan.scan_paths(tmp_path, [path])

    assert report.issues == []


def test_default_file_collection_excludes_historical_research_and_proof(
    tmp_path: pathlib.Path,
) -> None:
    kept = write_doc(tmp_path, "README.md", "v1.2.0 is stable today.\n")
    write_doc(tmp_path, "docs/adr/0001-history.md", "v1.1.0-rc.1 was current then.\n")
    write_doc(tmp_path, "docs/research/old.md", "Published marketplace notes.\n")
    write_doc(tmp_path, "docs/proof/v1.2.0-rc.1/receipt.md", "Marketplace published receipt.\n")

    paths = doc_truth_scan.collect_default_paths(tmp_path)

    assert paths == [kept]


def test_cli_json_reports_issue_count_and_exit_code(
    tmp_path: pathlib.Path,
    capsys,
) -> None:
    write_doc(tmp_path, "README.md", "v1.2.0 is stable today.\n")

    exit_code = doc_truth_scan.main(["--root", str(tmp_path), "--format", "json"])

    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "issues"
    assert payload["issue_count"] == 1
    assert payload["files_scanned"] == 1
    assert payload["issues"][0]["code"] == "stable-rc-overclaim"
