#!/usr/bin/env python3
"""Validate authority invariant YAML files against authority-invariant-v1.schema.json.

Supports multi-document YAML (---). Exits non-zero on first validation error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import jsonschema
    import yaml
except ImportError as e:
    print("Install pyyaml and jsonschema: pip install pyyaml jsonschema", file=sys.stderr)
    raise SystemExit(2) from e


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA = ROOT / "contracts/schemas/authority-invariant-v1.schema.json"


def load_schema(path: Path) -> dict:
    return json.loads(path.read_text())


def validate_file(schema: dict, path: Path) -> list[str]:
    errs: list[str] = []
    text = path.read_text()
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as e:
        return [f"{path}: YAML parse error: {e}"]
    for i, doc in enumerate(docs):
        if doc is None:
            continue
        if not isinstance(doc, dict):
            errs.append(f"{path}: document {i + 1} must be a mapping/object, got {type(doc).__name__}")
            continue
        try:
            jsonschema.validate(instance=doc, schema=schema)
        except jsonschema.ValidationError as e:
            loc = "/".join(str(p) for p in e.absolute_path) if e.absolute_path else "(root)"
            errs.append(f"{path}: document {i + 1} at {loc}: {e.message}")
    return errs


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA,
        help="JSON Schema path",
    )
    ap.add_argument(
        "paths",
        nargs="+",
        type=Path,
        help="YAML files or directories (recursive for *.yml / *.yaml)",
    )
    args = ap.parse_args()
    schema = load_schema(args.schema)

    files: list[Path] = []
    for p in args.paths:
        if p.is_file():
            if p.suffix.lower() in (".yml", ".yaml"):
                files.append(p)
        elif p.is_dir():
            files.extend(sorted(p.rglob("*.yml")))
            files.extend(sorted(p.rglob("*.yaml")))
        else:
            print(f"Skip (not a file/dir): {p}", file=sys.stderr)

    if not files:
        print("No YAML files to validate.", file=sys.stderr)
        raise SystemExit(1)

    all_errs: list[str] = []
    for f in files:
        all_errs.extend(validate_file(schema, f))

    if all_errs:
        for line in all_errs:
            print(line, file=sys.stderr)
        raise SystemExit(1)
    print(f"OK: validated {len(files)} file(s) against {args.schema.name}")


if __name__ == "__main__":
    main()
