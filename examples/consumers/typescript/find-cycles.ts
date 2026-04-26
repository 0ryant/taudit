#!/usr/bin/env -S deno run --allow-read
/**
 * find-cycles: reference consumer for taudit's authority graph.
 *
 * Targets schema: authority-graph v1.0.0
 *   https://github.com/0ryant/taudit/schemas/authority-graph.v1.json
 *
 * Question answered:
 *   Are there any AUTHORITY CYCLES in this pipeline? A cycle is a closed
 *   loop NodeId -> NodeId -> ... -> NodeId formed by has_access_to edges.
 *
 * In a healthy taudit graph today, has_access_to is acyclic
 * (step -> secret/identity), so this tool should print `[]` on every
 * fixture. A non-empty result indicates either a parser bug, a future
 * additive edge semantic, or — for a downstream consumer building
 * derived edges — a logic error in their own augmentation pass.
 *
 * Output: JSON array of `{cycle: string[], length: number}` objects,
 * one per simple cycle found (Tarjan's SCC, then expansion of SCCs with
 * size > 1 or self-loops).
 *
 * Usage:
 *   taudit graph pipeline.yml --format json > g.json
 *   deno run --allow-read find-cycles.ts g.json
 *
 * Deno standard library only — no npm imports, no remote modules.
 */

interface Node {
  id: number;
  kind: string;
  name: string;
  trust_zone: string;
  metadata: Record<string, string>;
}

interface Edge {
  id: number;
  from: number;
  to: number;
  kind: string;
}

interface Document {
  schema_version: string;
  schema_uri: string;
  graph: { nodes: Node[]; edges: Edge[] };
}

if (Deno.args.length !== 1) {
  console.error("usage: find-cycles.ts <graph.json>");
  Deno.exit(2);
}

const raw = await Deno.readTextFile(Deno.args[0]);
const doc = JSON.parse(raw) as Document;
if (!doc.schema_version.startsWith("1.")) {
  console.error(`unsupported schema_version: ${doc.schema_version} (need 1.x)`);
  Deno.exit(1);
}

const { nodes, edges } = doc.graph;
const adj: number[][] = nodes.map(() => []);
for (const e of edges) {
  if (e.kind === "has_access_to") adj[e.from].push(e.to);
}

// Tarjan's strongly connected components.
type Frame = { v: number; iter: number };
const index = new Array<number>(nodes.length).fill(-1);
const lowlink = new Array<number>(nodes.length).fill(0);
const onStack = new Array<boolean>(nodes.length).fill(false);
const stack: number[] = [];
const sccs: number[][] = [];
let nextIndex = 0;

function strongconnect(v0: number) {
  const callStack: Frame[] = [{ v: v0, iter: 0 }];
  index[v0] = nextIndex;
  lowlink[v0] = nextIndex;
  nextIndex++;
  stack.push(v0);
  onStack[v0] = true;

  while (callStack.length) {
    const top = callStack[callStack.length - 1];
    const { v } = top;
    if (top.iter < adj[v].length) {
      const w = adj[v][top.iter++];
      if (index[w] === -1) {
        index[w] = nextIndex;
        lowlink[w] = nextIndex;
        nextIndex++;
        stack.push(w);
        onStack[w] = true;
        callStack.push({ v: w, iter: 0 });
      } else if (onStack[w]) {
        lowlink[v] = Math.min(lowlink[v], index[w]);
      }
    } else {
      if (lowlink[v] === index[v]) {
        const scc: number[] = [];
        while (true) {
          const w = stack.pop()!;
          onStack[w] = false;
          scc.push(w);
          if (w === v) break;
        }
        sccs.push(scc);
      }
      callStack.pop();
      if (callStack.length) {
        const parent = callStack[callStack.length - 1];
        lowlink[parent.v] = Math.min(lowlink[parent.v], lowlink[v]);
      }
    }
  }
}

for (let v = 0; v < nodes.length; v++) {
  if (index[v] === -1) strongconnect(v);
}

const cycles: { cycle: string[]; length: number }[] = [];
for (const scc of sccs) {
  if (scc.length > 1) {
    const names = scc.map((id) => nodes[id].name);
    cycles.push({ cycle: names, length: scc.length });
  } else {
    const v = scc[0];
    if (adj[v].includes(v)) {
      cycles.push({ cycle: [nodes[v].name], length: 1 });
    }
  }
}

console.log(JSON.stringify(cycles, null, 2));
