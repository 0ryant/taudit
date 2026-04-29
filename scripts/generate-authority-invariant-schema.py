#!/usr/bin/env python3
"""Generate contracts/schemas/authority-invariant-v1.schema.json from this repo's Rust types.

Run after changing FindingCategory in crates/taudit-core/src/finding.rs:
  python3 scripts/generate-authority-invariant-schema.py --write

CI uses --check to ensure the committed schema matches the generator output.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contracts/schemas/authority-invariant-v1.schema.json"
EXTRACT = ROOT / "scripts/extract_finding_categories.py"


def finding_categories() -> list[str]:
    out = subprocess.check_output([sys.executable, str(EXTRACT)], text=True)
    cats = [line.strip() for line in out.splitlines() if line.strip()]
    return sorted(set(cats))


def build_schema(categories: list[str]) -> dict:
    node_kind = ["step", "secret", "artifact", "identity", "image"]
    trust_zone = ["first_party", "third_party", "untrusted"]
    severity = ["critical", "high", "medium", "low", "info"]

    defs: dict = {
        "severity": {"type": "string", "enum": severity},
        "findingCategory": {"type": "string", "enum": sorted(categories)},
        "nodeKindEnum": {"type": "string", "enum": node_kind},
        "trustZoneEnum": {"type": "string", "enum": trust_zone},
        "nodeTypeOrList": {
            "oneOf": [
                {"$ref": "#/$defs/nodeKindEnum"},
                {
                    "type": "array",
                    "items": {"$ref": "#/$defs/nodeKindEnum"},
                    "minItems": 1,
                },
            ]
        },
        "trustZoneOrList": {
            "oneOf": [
                {"$ref": "#/$defs/trustZoneEnum"},
                {
                    "type": "array",
                    "items": {"$ref": "#/$defs/trustZoneEnum"},
                    "minItems": 1,
                },
            ]
        },
        "metadataOp": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "equals": {"type": "string"},
                "not_equals": {"type": "string"},
                "contains": {"type": "string"},
                "in": {"type": "array", "items": {"type": "string"}},
            },
        },
        "metadataPredicate": {
            "oneOf": [
                {"type": "string"},
                {"$ref": "#/$defs/metadataOp"},
            ]
        },
        "metadataMatcher": {
            "type": "object",
            "properties": {"not": {"$ref": "#/$defs/metadataMatcher"}},
            "additionalProperties": {"$ref": "#/$defs/metadataPredicate"},
        },
        "nodeMatcher": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "node_type": {"$ref": "#/$defs/nodeTypeOrList"},
                "trust_zone": {"$ref": "#/$defs/trustZoneOrList"},
                "metadata": {"$ref": "#/$defs/metadataMatcher"},
                "not": {"$ref": "#/$defs/nodeMatcher"},
            },
        },
        "pathMatcher": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "crosses_to": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/trustZoneEnum"},
                }
            },
        },
        "matchSpec": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "source": {"$ref": "#/$defs/nodeMatcher"},
                "sink": {"$ref": "#/$defs/nodeMatcher"},
                "path": {"$ref": "#/$defs/pathMatcher"},
                "graph_metadata": {"$ref": "#/$defs/metadataMatcher"},
                "standalone": {"$ref": "#/$defs/nodeMatcher"},
            },
        },
    }

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://taudit.dev/schemas/authority-invariant-v1.schema.json",
        "title": "taudit authority invariant (custom invariant YAML) v1",
        "description": "Invariant documents loaded via --invariants-dir / --rules-dir. "
        "Matches serde deserialization in crates/taudit-core/src/custom_rules.rs. "
        "Regenerate this file with scripts/generate-authority-invariant-schema.py --write.",
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "name", "severity", "category"],
        "properties": {
            "id": {"type": "string", "minLength": 1},
            "name": {"type": "string", "minLength": 1},
            "description": {"type": "string"},
            "severity": {"$ref": "#/$defs/severity"},
            "category": {"$ref": "#/$defs/findingCategory"},
            "match": {"$ref": "#/$defs/matchSpec"},
        },
        "$defs": defs,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--write",
        action="store_true",
        help=f"Write {SCHEMA_PATH.relative_to(ROOT)}",
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if on-disk schema differs from generator output",
    )
    args = ap.parse_args()
    cats = finding_categories()
    schema = build_schema(cats)
    text = json.dumps(schema, indent=2, sort_keys=True) + "\n"

    if args.check:
        if not SCHEMA_PATH.is_file():
            print(f"Missing {SCHEMA_PATH}", file=sys.stderr)
            sys.exit(1)
        existing = SCHEMA_PATH.read_text()
        if existing != text:
            print(
                "authority-invariant-v1.schema.json is out of date.\n"
                "Run: python3 scripts/generate-authority-invariant-schema.py --write",
                file=sys.stderr,
            )
            sys.exit(1)
        print("Schema matches generator output.")
        return

    if args.write:
        SCHEMA_PATH.parent.mkdir(parents=True, exist_ok=True)
        SCHEMA_PATH.write_text(text)
        print(f"Wrote {SCHEMA_PATH}")
        return

    print(text)


if __name__ == "__main__":
    main()
