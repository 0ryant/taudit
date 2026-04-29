#!/usr/bin/env python3
"""Emit FindingCategory serde strings from crates/taudit-core/src/finding.rs for tooling."""
from __future__ import annotations

import re
import sys
from pathlib import Path


def to_snake(name: str) -> str:
    out = []
    for i, c in enumerate(name):
        if c.isupper() and i > 0:
            out.append("_")
        out.append(c.lower())
    return "".join(out)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    path = root / "crates/taudit-core/src/finding.rs"
    text = path.read_text()
    m = re.search(
        r"pub enum FindingCategory\s*\{(.*?)\n\}",
        text,
        re.DOTALL,
    )
    if not m:
        print("FindingCategory block not found", file=sys.stderr)
        sys.exit(1)
    body = m.group(1)
    pending_rename: str | None = None
    categories: list[str] = []
    for line in body.splitlines():
        rm = re.search(r'serde\(rename\s*=\s*"([^"]+)"\)', line)
        if rm:
            pending_rename = rm.group(1)
            continue
        vm = re.match(r"\s{4}([A-Za-z0-9_]+)\s*,\s*$", line)
        if vm:
            variant = vm.group(1)
            if pending_rename:
                categories.append(pending_rename)
                pending_rename = None
            else:
                categories.append(to_snake(variant))
            continue
    for c in sorted(set(categories)):
        print(c)


if __name__ == "__main__":
    main()
