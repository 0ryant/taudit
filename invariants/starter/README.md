# Starter Authority Invariants

A copy-and-edit library of five real authority invariants you can drop into
any taudit scan. They complement the 17 built-in invariants — they do not
replace them.

## What's in here

| File | Severity | What it asserts |
|---|---|---|
| `no-untrusted-with-prod-secret.yml` | Critical | A Secret tagged `environment: production` never reaches an Untrusted node. |
| `no-broad-identity-to-untrusted.yml` | Critical | A broad-scope Identity never reaches an Untrusted step. |
| `no-untrusted-image-with-secret.yml` | Critical | A Secret never propagates into an Untrusted (floating) image or action. |
| `prefer-oidc-over-static-secrets.yml` | High | Production-tagged Secrets should be migrated to OIDC. |
| `no-third-party-step-with-identity.yml` | High | An Identity never reaches a third-party Step (stricter than the built-in baseline). |

Each file has a leading comment block explaining the invariant, why it
matters, and how to customise it. They are deliberately small — they are
templates to copy, not a complete policy library.

## Run them

```bash
# Apply the starter invariants alongside the 17 built-ins
taudit scan --invariants-dir invariants/starter .github/workflows/

# Verify they loaded
taudit invariants list --invariants-dir invariants/starter
```

`--invariants-dir` is the new spelling; `--rules-dir` is accepted as an
alias for backward compatibility.

## Customising

The biggest customisation lever is metadata. Two of these invariants assume
your Secret nodes are tagged with `environment: production`. taudit does
not infer that tag — you set it via your pipeline parser, an upstream
labelling step, or a fork of the parser crate. If your tagging scheme
differs, edit the `metadata:` block in the YAML to match.

Beyond that, every field documented in
[`docs/authority-invariants.md`](../../docs/authority-invariants.md) is
fair game: change `severity`, narrow `node_type`, broaden `crosses_to`,
or remove predicates entirely to widen the invariant.

## Adding your own

1. Copy any file in this directory to a new `.yml` file with a unique `id`.
2. Edit the comment block, the `name`, the `description`, and the
   `match:` predicates.
3. Re-run `taudit invariants list --invariants-dir <your-dir>` to confirm
   the file parses.
4. Run `taudit scan --invariants-dir <your-dir> <pipeline.yml>` to see it
   fire (or stay silent — silence is success for an invariant).

See the full schema and predicate reference in
[`docs/authority-invariants.md`](../../docs/authority-invariants.md).
