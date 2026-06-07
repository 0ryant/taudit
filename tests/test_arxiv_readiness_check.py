from __future__ import annotations

import importlib.util
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "research" / "check_arxiv_readiness.py"
SPEC = importlib.util.spec_from_file_location("check_arxiv_readiness", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
check_arxiv_readiness = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_arxiv_readiness
SPEC.loader.exec_module(check_arxiv_readiness)


def rule_entry(
    rule_id: str,
    *,
    benchmark_scope: str = "gha_default",
    enabled_by_default: str = "yes",
) -> object:
    return check_arxiv_readiness.RuleMapEntry(
        rule_id=rule_id,
        arxiv_weakness="UDW",
        upstream_raw_weakness="UDW",
        benchmark_scope=benchmark_scope,
        enabled_by_default=enabled_by_default,
        mapping_status="proposed",
        rationale="test",
        evidence="test",
    )


def test_readiness_check_passes_current_source_local_assets() -> None:
    report = check_arxiv_readiness.run_checks(ROOT)

    assert report["status"] == "pass"
    assert report["claim_ceiling"] == "source-local readiness only"
    checks = {item["id"]: item for item in report["checks"]}
    assert checks["assets-present"]["status"] == "pass"
    assert checks["rule-map-loads"]["status"] == "pass"
    assert checks["gha-rules-mapped"]["status"] == "pass"
    assert checks["current-binary-default-rules"]["status"] == "pass"
    assert checks["unsupported-claims-absent"]["status"] == "pass"
    assert "run full corpus benchmark and retain raw artifacts" in report["human_gates_remaining"]


def test_extract_explain_rule_ids_reads_current_binary_table() -> None:
    output = """
taudit - 2 rules

  unpinned_action                                                high        mutable action ref
  gha_toolcache_absolute_path_downgrade                          info        precision guard

Use 'taudit explain <rule>' for full description.
""".strip()

    assert check_arxiv_readiness.extract_explain_rule_ids(output) == {
        "gha_toolcache_absolute_path_downgrade",
        "unpinned_action",
    }


def test_current_binary_check_surfaces_absent_candidates_as_publish_gate() -> None:
    rule_map = {
        "present_default": rule_entry("present_default"),
        "future_candidate": rule_entry(
            "future_candidate",
            benchmark_scope="gha_candidate",
            enabled_by_default="no",
        ),
    }

    check, human_gates = check_arxiv_readiness.current_binary_default_check(
        rule_map,
        {"present_default"},
        "path=fake-taudit; rules=1",
    )

    assert check.status == "pass"
    assert "future_candidate" in check.evidence
    assert human_gates == [
        "release-enable or remove non-current candidate rule-map rows before "
        "claiming current-binary/default benchmark coverage: future_candidate"
    ]


def test_current_binary_check_fails_hidden_default_drift() -> None:
    rule_map = {
        "missing_default": rule_entry("missing_default"),
        "future_candidate": rule_entry(
            "future_candidate",
            benchmark_scope="gha_candidate",
            enabled_by_default="no",
        ),
    }

    check, human_gates = check_arxiv_readiness.current_binary_default_check(
        rule_map,
        set(),
        "path=fake-taudit; rules=0",
    )

    assert check.status == "fail"
    assert '"missing_default_rows": ["missing_default"]' in check.evidence
    assert human_gates == [
        "release-enable or remove non-current candidate rule-map rows before "
        "claiming current-binary/default benchmark coverage: future_candidate"
    ]


def test_current_rule_map_marks_known_non_current_rows_as_candidates() -> None:
    rule_map = check_arxiv_readiness.load_rule_map(
        ROOT / "docs" / "research" / "arxiv-taudit-rule-map.csv"
    )
    non_current = {
        "gha_crossforge_mirror_checkout_with_token_push",
        "gha_crossrepo_org_credential_multiplexing",
        "gha_floating_remote_script_before_publish_sink",
        "gha_identity_cosign_certificate_identity_repo_only_no_ref",
        "gha_runner_lifecycle_self_hosted_pr_no_isolation",
        "gha_temporal_oidc_freshness_across_multistep_build",
        "gha_token_remote_url_with_trace_or_process_exposure",
        "gha_verifier_gh_attestation_missing_source_digest_check",
        "gha_workflow_run_artifact_metadata_to_privileged_api",
        "gha_workflow_run_artifact_report_to_pr_comment",
        "gha_workflow_run_artifact_to_build_scan_publish",
    }

    assert {
        rule_id
        for rule_id, entry in rule_map.items()
        if entry.benchmark_scope == "gha_candidate" and entry.enabled_by_default == "no"
    } == non_current


def test_unsupported_claim_scan_flags_unbounded_claim(tmp_path: pathlib.Path) -> None:
    research = tmp_path / "docs" / "research"
    research.mkdir(parents=True)
    path = research / "arxiv-bad.md"
    path.write_text("taudit is externally benchmarked now.\n", encoding="utf-8")

    findings = check_arxiv_readiness.unsupported_claim_findings(tmp_path)

    assert findings == ["docs\\research\\arxiv-bad.md:1: taudit is externally benchmarked now."]
