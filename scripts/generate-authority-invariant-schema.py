#!/usr/bin/env python3
"""Generate / drift-check the four schemas that mirror ``FindingCategory``.

Run after changing FindingCategory in crates/taudit-core/src/finding.rs:
  python3 scripts/generate-authority-invariant-schema.py --write

CI uses ``--check`` to ensure every committed schema matches the generator
output.

Schemas covered
---------------

INPUT side — describes what taudit accepts as user-loaded YAML, so the
*reserved* categories (``EgressBlindspot``, ``MissingAuditTrail``) are
EXCLUDED. These cannot be detected from pipeline YAML alone (they need
runtime telemetry / external audit-sink data) so a custom rule attempting
to emit them would be lying. The Rust types also carry
``#[serde(skip_deserializing)]`` on the two reserved variants so the YAML
loader rejects them at deserialise time with a clear ``unknown variant``
error.

  * ``contracts/schemas/authority-invariant-v1.schema.json``
    (regenerated from scratch — single source of truth, no hand-edits)

OUTPUT side — describes what taudit EMITS. Reserved categories CAN appear
on the output side because the Rust enum can construct them in code (e.g.
future runtime-enrichment paths). They are sealed against deserialisation
input only.

  * ``contracts/schemas/taudit-report.schema.json``
    (``#/$defs/Finding/properties/category/enum``)
  * ``contracts/schemas/taudit-cloudevent-finding-v1.schema.json``
    (``properties/data/properties/category/enum``)
  * ``schemas/finding.v1.json``
    (``$defs/FindingCategory/enum``)

The three output schemas are surgically patched in-place: only the ``enum``
array is rewritten. Whitespace, key order, em-dashes, and inline shorthand
in the rest of the document are preserved byte-identically — full
re-serialisation would force massive churn unrelated to the category fix.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INPUT_SCHEMA_PATH = ROOT / "contracts/schemas/authority-invariant-v1.schema.json"
EXTRACT = ROOT / "scripts/extract_finding_categories.py"

# Categories that exist in the Rust enum (so output schemas list them) but
# cannot be produced from pipeline YAML alone (so the YAML-input schema
# must reject them, AND ``finding.rs`` carries ``#[serde(skip_deserializing)]``
# so attempts to load them via custom-rule YAML error out at deserialise time).
RESERVED_INPUT_CATEGORIES: set[str] = {"egress_blindspot", "missing_audit_trail"}


# ── Output-schema patch targets ────────────────────────────────────────
#
# Each entry pairs a schema file path with a regex that captures the
# ``enum`` array embedded in its category property. Group 1 is the prefix
# (everything up to and including ``"enum": ``); group 2 is the array body
# between ``[`` and ``]``. Replacing group 2 with a freshly-rendered list
# (using the indent that matches the file's existing convention) preserves
# every other byte of the schema, so churn is bounded to the enum lines
# we intend to change.

OUTPUT_SCHEMA_TARGETS: list[tuple[Path, re.Pattern[str], int]] = [
    # taudit-report.schema.json — Finding/properties/category/enum.
    # Anchor on ``"category": { … "enum": [ … ]``. The enum is the only
    # ``"category"`` property in the file, so the first match is correct.
    (
        ROOT / "contracts/schemas/taudit-report.schema.json",
        re.compile(r'("category"\s*:\s*\{[^}]*?"enum"\s*:\s*)\[([^\]]*?)\]', re.DOTALL),
        12,  # 12-space indent for enum items (matches existing file).
    ),
    # taudit-cloudevent-finding-v1.schema.json — data.properties.category.enum.
    (
        ROOT / "contracts/schemas/taudit-cloudevent-finding-v1.schema.json",
        re.compile(r'("category"\s*:\s*\{[^}]*?"enum"\s*:\s*)\[([^\]]*?)\]', re.DOTALL),
        12,
    ),
    # schemas/finding.v1.json — $defs/FindingCategory/enum. Anchor on the
    # ``"FindingCategory"`` def name so we do not accidentally hit any
    # other ``"enum"`` array elsewhere in the document.
    (
        ROOT / "schemas/finding.v1.json",
        re.compile(r'("FindingCategory"\s*:\s*\{[^}]*?"enum"\s*:\s*)\[([^\]]*?)\]', re.DOTALL),
        8,  # 8-space indent (this file is shallower).
    ),
]


def finding_categories() -> list[str]:
    """All FindingCategory variants, in serialized snake_case form."""
    out = subprocess.check_output([sys.executable, str(EXTRACT)], text=True)
    cats = [line.strip() for line in out.splitlines() if line.strip()]
    return sorted(set(cats))


def build_input_schema(categories: list[str]) -> dict:
    """Build the authority-invariant (custom-rule INPUT) schema document.

    Reserved categories are filtered OUT — see module docstring.
    """
    accepted = sorted(c for c in categories if c not in RESERVED_INPUT_CATEGORIES)

    node_kind = ["step", "secret", "artifact", "identity", "image"]
    trust_zone = ["first_party", "third_party", "untrusted"]
    severity = ["critical", "high", "medium", "low", "info"]

    defs: dict = {
        "severity": {"type": "string", "enum": severity},
        "findingCategory": {"type": "string", "enum": accepted},
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


def render_enum_body(categories: list[str], indent: int) -> str:
    """Render an enum array body (the substring BETWEEN the brackets) at
    the given item indent. Closing-bracket indent is two less (matches
    JSON pretty-print convention used in the existing files).

    Output shape::

        \n<indent>"item_a",
        \n<indent>"item_b"
        \n<indent-2>

    The trailing dedent line aligns the closing ``]`` with the opening
    bracket's containing key.
    """
    pad = " " * indent
    closer_pad = " " * (indent - 2) if indent >= 2 else ""
    if not categories:
        return f"\n{closer_pad}"
    lines = [f"{pad}{json.dumps(c)}" for c in categories]
    return "\n" + ",\n".join(lines) + f"\n{closer_pad}"


def patch_output_schema(text: str, pattern: re.Pattern[str], categories: list[str], indent: int) -> str:
    """Return ``text`` with the matched enum array body replaced. Raises
    ``ValueError`` if the pattern does not match (catches refactors that
    would silently skip a schema)."""
    m = pattern.search(text)
    if not m:
        raise ValueError("category enum pattern did not match — schema may have been restructured")
    new_body = render_enum_body(categories, indent)
    start, end = m.span(2)
    return text[:start] + new_body + text[end:]


def render_input_schema_text(categories: list[str]) -> str:
    schema = build_input_schema(categories)
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--write",
        action="store_true",
        help="Write all four schemas (input + three output) in place.",
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if any of the four on-disk schemas differs from generator output.",
    )
    args = ap.parse_args()

    cats = finding_categories()
    # Output-side: keep reserved variants. They are valid in serialised
    # output (the Rust enum can construct them) — only YAML INPUT rejects
    # them via skip_deserializing.
    output_categories = sorted(set(cats))

    input_text = render_input_schema_text(cats)

    # Pre-render each output schema's expected text by patching the
    # currently-on-disk file. This preserves every non-enum byte.
    output_renders: list[tuple[Path, str]] = []
    for path, pattern, indent in OUTPUT_SCHEMA_TARGETS:
        if not path.is_file():
            print(f"Missing output schema: {path}", file=sys.stderr)
            sys.exit(1)
        existing = path.read_text()
        patched = patch_output_schema(existing, pattern, output_categories, indent)
        output_renders.append((path, patched))

    if args.check:
        ok = True
        if not INPUT_SCHEMA_PATH.is_file():
            print(f"Missing {INPUT_SCHEMA_PATH}", file=sys.stderr)
            sys.exit(1)
        if INPUT_SCHEMA_PATH.read_text() != input_text:
            print(
                f"{INPUT_SCHEMA_PATH.relative_to(ROOT)} is out of date.\n"
                "Run: python3 scripts/generate-authority-invariant-schema.py --write",
                file=sys.stderr,
            )
            ok = False
        for path, patched in output_renders:
            if path.read_text() != patched:
                print(
                    f"{path.relative_to(ROOT)} category enum is out of date.\n"
                    "Run: python3 scripts/generate-authority-invariant-schema.py --write",
                    file=sys.stderr,
                )
                ok = False
        if not ok:
            sys.exit(1)
        print("All four schemas match generator output.")
        return

    if args.write:
        INPUT_SCHEMA_PATH.parent.mkdir(parents=True, exist_ok=True)
        if INPUT_SCHEMA_PATH.read_text() != input_text if INPUT_SCHEMA_PATH.is_file() else True:
            INPUT_SCHEMA_PATH.write_text(input_text)
            print(f"Wrote {INPUT_SCHEMA_PATH.relative_to(ROOT)}")
        else:
            print(f"{INPUT_SCHEMA_PATH.relative_to(ROOT)} already up to date")
        for path, patched in output_renders:
            if path.read_text() != patched:
                path.write_text(patched)
                print(f"Wrote {path.relative_to(ROOT)} (category enum)")
            else:
                print(f"{path.relative_to(ROOT)} already up to date")
        return

    # Default (no flag): print the input schema (back-compat with the
    # original behaviour — useful for piping into a diff tool).
    sys.stdout.write(input_text)


if __name__ == "__main__":
    main()
