# Custom Rules → Authority Invariants

> **This page has moved.** Custom rules have been renamed to **authority
> invariants** — same mechanism, sharper framing. The full reference now
> lives at [`docs/authority-invariants.md`](./authority-invariants.md).

## TL;DR

- The mechanism is unchanged: YAML files in a directory, one invariant per
  file, evaluated against propagation paths alongside the 17 built-ins.
- The CLI flag has been renamed: `--invariants-dir` is the new spelling.
  `--rules-dir` is preserved as an alias and will keep working
  indefinitely.
- A new subcommand, `taudit invariants list [--invariants-dir <path>]`,
  prints every loaded invariant (built-in plus custom) so you can verify
  your policy is wired up.
- A starter library of five real, copy-and-edit invariants ships in
  [`invariants/starter/`](../invariants/starter/).

## Where to read

- **Concept and schema** → [`docs/authority-invariants.md`](./authority-invariants.md)
- **Examples to copy** → [`invariants/starter/`](../invariants/starter/)
- **Built-in invariants** → [`docs/rules/index.md`](./rules/index.md)

## Why the rename

CI/CD is an untyped authority system. "Authority invariants" names what
these declarations actually are — properties the authority graph must
satisfy — rather than the generic-engineering term "rules." The new name
also sharpens the relationship to the built-in checks: every check, custom
or shipped, is an invariant the graph either satisfies or violates.

The underlying file format, evaluation semantics, and SARIF output are all
unchanged. Existing `--rules-dir` invocations and existing YAML files keep
working without modification.
