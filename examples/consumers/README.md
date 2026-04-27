# Authority-graph reference consumers

Three small programs that consume the JSON emitted by
`taudit graph <pipeline.yml> --format json`. Each one is single-file,
stdlib-only, and answers a question that the taudit CLI does **not**
answer directly — proving that the schema is a sufficient contract for
downstream tooling.

## Why this directory exists

The v1 ratification council flagged that publishing a stable schema
without a reference consumer makes the semver promise a liability:
nothing exercises the contract end-to-end, so a "minor" change can
silently break unknown downstream tools. These examples are the
counterweight. If any of them stops working without a major-version
bump on the schema, taudit broke its promise.

## Schema this code targets

- File:  `schemas/authority-graph.v1.json`
- `$id`: `https://github.com/0ryant/taudit/schemas/authority-graph.v1.json`
- Version: `1.0.0`

## Semver guarantee taudit makes

- `1.x.y`  — additive only. New optional fields, new metadata keys, new
  enum variants on extension points may appear. **Existing field names,
  types, and required-ness will not change.** A consumer written for
  `1.0.0` MUST keep working against any later `1.x.y`.
- `2.0.0`  — breaking. Field renames, removals, type changes, semantic
  shifts. Consumers must be updated.

The check every consumer in this directory performs:

```
schema_version.split(".")[0] == "1"   →   proceed
otherwise                              →   exit non-zero with clear error
```

## The examples

| Language   | Question answered                                                | File |
|------------|------------------------------------------------------------------|------|
| Python 3   | Per Secret: how many Steps can transitively reach it?            | [`python/blast_radius.py`](python/blast_radius.py) |
| Go         | Which OIDC identities are reachable by a `third_party` Step?     | [`go/main.go`](go/main.go) ([build](go/README.md)) |
| TypeScript | Are there authority cycles via `has_access_to` edges?            | [`typescript/find-cycles.ts`](typescript/find-cycles.ts) |

## Try it

```sh
cargo build --release
./target/release/taudit graph tests/fixtures/propagation-leaky.yml --format json > /tmp/g.json

python3   examples/consumers/python/blast_radius.py        /tmp/g.json
go run    ./examples/consumers/go                          /tmp/g.json
deno run  --allow-read examples/consumers/typescript/find-cycles.ts /tmp/g.json
```

**Mermaid (diagram view only):** these examples consume **JSON**. For a GitHub-flavoured Markdown `flowchart` with no Graphviz install, use `taudit graph … --format mermaid` and paste into a fenced `mermaid` block — same graph model, not a separate consumer contract.

## Principles for your own consumer

If you build a tool on top of the taudit authority graph, follow these:

- **Pin the major version.** Read `schema_version`, refuse to run if the
  major component is not the one you tested against. Do not silently
  trust a future `2.x`.
- **Treat unknown metadata keys as opaque, never as errors.** `1.x.y`
  may add new keys to any node's `metadata` map. Ignore what you don't
  recognise; never assert exhaustiveness.
- **Use `kind` and `trust_zone` enums defensively.** New variants can
  appear in `1.x.y` only on documented extension points; even so, prefer
  `switch` with a default branch over panicking.
- **Walk edges by `kind`, not by node-shape assumptions.** Edge
  semantics are documented in the schema (`EdgeKind`); a step you reach
  via `delegates_to` is materially different from one reached via
  `uses_image`.
- **Don't mutate node ids.** They are dense indices into `graph.nodes`
  and `graph.edges` — every consumer in this directory exploits that.
  Preserve the property if you serialize a derived graph.
