from __future__ import annotations

import json
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "action-intelligence-catalog.v1.json"
EXAMPLE_PATH = ROOT / "data" / "action-intelligence-catalog.example.json"
DOC_PATH = ROOT / "docs" / "rc" / "v1.2.0" / "action-intelligence-catalog.md"


HELPER_RESOLUTION_VALUES = {
    "bare_command",
    "shell_string",
    "toolkit_which",
    "absolute_path",
    "toolcache_path",
    "action_owned_path",
    "user_supplied_absolute_path",
    "ambient_path_by_explicit_mode",
    "unknown",
}
AUTHORITY_TRANSPORT_VALUES = {
    "argv",
    "stdin",
    "env",
    "credential_file_path",
    "config_file_path",
    "workspace_file",
    "oidc_request_env",
}
AUTHORITY_ORIGIN_VALUES = {
    "caller_provided_secret",
    "action_input_secret",
    "github_token",
    "oidc_request_capability",
    "cloud_credential_minted_by_action",
    "registry_credential_minted_by_action",
    "generated_credential_file",
    "derived_secret_payload",
}


def load_json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_with_jsonschema_if_available(schema: dict, document: dict) -> None:
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        structural_validate_catalog(document)
        return

    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    assert errors == []


def structural_validate_catalog(catalog: dict) -> None:
    assert catalog["schema_version"].startswith("1.")
    assert catalog["schema_uri"] == "https://taudit.dev/schemas/action-intelligence-catalog.v1.json"
    assert isinstance(catalog["entries"], list)
    assert 2 <= len(catalog["entries"]) <= 3

    ids = set()
    for entry in catalog["entries"]:
        required = {
            "id",
            "action",
            "version_ref",
            "helper_resolution",
            "helper_invocations",
            "authority_transport",
            "authority_origin",
            "confidence",
            "evidence_tier",
            "source_evidence",
            "deferred",
        }
        assert required <= set(entry)
        assert entry["id"] not in ids
        ids.add(entry["id"])
        assert entry["action"]["ecosystem"] == "github_actions"
        assert entry["action"]["name"]
        assert entry["version_ref"]["kind"] in {"major_ref", "pinned_tag", "sha", "unversioned", "unknown"}
        assert entry["helper_resolution"] in HELPER_RESOLUTION_VALUES
        assert isinstance(entry["helper_invocations"], list)
        assert entry["helper_invocations"]
        for helper in entry["helper_invocations"]:
            assert helper["helper"]
            assert helper["helper_resolution"] in HELPER_RESOLUTION_VALUES
            assert set(helper["authority_transport"]) <= AUTHORITY_TRANSPORT_VALUES
        assert set(entry["authority_transport"]) <= AUTHORITY_TRANSPORT_VALUES
        assert set(entry["authority_origin"]) <= AUTHORITY_ORIGIN_VALUES
        assert entry["confidence"] in {"high", "medium", "low"}
        assert entry["evidence_tier"] in {"static", "inferred", "catalog", "witness_label", "observed"}
        assert isinstance(entry["deferred"], bool)
        assert_source_evidence(entry["source_evidence"])
        if entry["deferred"]:
            assert entry["deferred_reason"]


def assert_source_evidence(source_evidence: dict) -> None:
    anchors = source_evidence.get("source_anchors", [])
    witness_status = source_evidence.get("witness_status")
    assert anchors or witness_status
    if anchors:
        for anchor in anchors:
            assert anchor["kind"] in {"public_source", "public_docs", "taudit_doc", "taudit_fixture"}
            assert anchor.get("path") or anchor.get("url")
    if witness_status:
        assert witness_status["status"] in {
            "not_started",
            "public_source_only",
            "local_witness",
            "runner_faithful_witness",
            "hosted_witness",
            "deferred",
        }
        assert witness_status["explanation"]


def test_schema_file_defines_catalog_entry_contract() -> None:
    schema = load_json(SCHEMA_PATH)

    assert schema["$id"] == "https://taudit.dev/schemas/action-intelligence-catalog.v1.json"
    assert schema["required"] == ["schema_version", "schema_uri", "catalog_version", "entries"]
    entry_schema = schema["$defs"]["CatalogEntry"]
    assert entry_schema["required"] == [
        "id",
        "action",
        "version_ref",
        "helper_resolution",
        "helper_invocations",
        "authority_transport",
        "authority_origin",
        "confidence",
        "evidence_tier",
        "source_evidence",
        "deferred",
    ]


def test_example_catalog_validates_schema_and_catalog_seed_bounds() -> None:
    schema = load_json(SCHEMA_PATH)
    example = load_json(EXAMPLE_PATH)

    validate_with_jsonschema_if_available(schema, example)
    structural_validate_catalog(example)
    assert example["non_exhaustive"] is True


def test_docs_mark_catalog_as_l4_03_seed_not_l4_04_full_catalog() -> None:
    text = DOC_PATH.read_text(encoding="utf-8")

    assert "L4-03" in text
    assert "L4-04" in text
    assert "non-exhaustive" in text.lower()
    assert "action-intelligence-catalog.v1.json" in text
