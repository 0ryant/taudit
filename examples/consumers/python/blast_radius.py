#!/usr/bin/env python3
"""Blast-radius reference consumer for taudit's authority graph.

Targets schema: authority-graph v1.0.0
  https://github.com/0ryant/taudit/schemas/authority-graph.v1.json

What this script proves:
    The authority graph is consumable from a third-party tool using only
    the documented schema. taudit's own CLI does not directly answer
    "if this secret leaks, how many steps could have used it?" — but the
    graph contains everything needed to compute it.

Question answered:
    For every Secret node, what is the BLAST RADIUS = the count of Step
    nodes that can transitively reach it via has_access_to edges, plus
    the set of trust zones those steps live in?

Usage:
    taudit graph path/to/pipeline.yml --format json > g.json
    python3 blast_radius.py g.json

Stdlib only. No jsonschema dependency on purpose: this file should be
copy-pasteable into any Python 3.8+ environment.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict, deque


def load_graph(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if doc.get("schema_version", "").split(".")[0] != "1":
        sys.exit(f"unsupported schema_version: {doc.get('schema_version')!r} (need 1.x)")
    return doc["graph"]


def build_reverse_index(edges: list[dict]) -> dict[int, list[int]]:
    """Map target_node_id -> list of source_node_ids for has_access_to edges.

    has_access_to direction is step -> secret/identity, so reversing it lets
    us walk from any secret/identity back to every step that can reach it.
    """
    rev: dict[int, list[int]] = defaultdict(list)
    for e in edges:
        if e["kind"] == "has_access_to":
            rev[e["to"]].append(e["from"])
    return rev


def reachable_steps(start: int, rev: dict[int, list[int]], nodes: list[dict]) -> set[int]:
    """BFS from a secret backwards through has_access_to. Return step ids."""
    seen: set[int] = set()
    queue: deque[int] = deque([start])
    while queue:
        nid = queue.popleft()
        for src in rev.get(nid, []):
            if src in seen:
                continue
            seen.add(src)
            # An identity can itself be has_access_to'd; keep walking.
            queue.append(src)
    return {nid for nid in seen if nodes[nid]["kind"] == "step"}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0] if argv else 'blast_radius.py'} <graph.json>", file=sys.stderr)
        return 2
    graph = load_graph(argv[1])
    nodes = graph["nodes"]
    rev = build_reverse_index(graph["edges"])

    rows: list[tuple[str, int, set[str]]] = []
    for node in nodes:
        if node["kind"] != "secret":
            continue
        steps = reachable_steps(node["id"], rev, nodes)
        zones = {nodes[s]["trust_zone"] for s in steps}
        rows.append((node["name"], len(steps), zones))

    rows.sort(key=lambda r: (-r[1], r[0]))
    if not rows:
        print("(no secret nodes in this graph)")
        return 0

    width = max(len(r[0]) for r in rows)
    print(f"{'SECRET'.ljust(width)}  RADIUS  TRUST_ZONES_CROSSED")
    for name, radius, zones in rows:
        zone_str = ",".join(sorted(zones)) if zones else "-"
        print(f"{name.ljust(width)}  {radius:>6}  {zone_str}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
