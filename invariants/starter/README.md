# Starter Authority Invariants

A copy-and-edit library of real authority invariants you can drop into any
taudit scan. They complement the 31 built-in invariants — they do not
replace them.

The library is split into two generations:

* **Original five (pre-v0.9.0)** — show the simple-form DSL: a `source:` /
  `sink:` / `path:` triplet with bare-string metadata predicates. These are
  still the right shape for most propagation-style invariants.
* **v0.9.0+ extensions** — show every new DSL feature: `graph_metadata:`,
  `standalone:`, `not:`, typed metadata operators (`equals`, `not_equals`,
  `contains`, `in`), multi-value `node_type` / `trust_zone` lists, and
  multi-doc YAML loading.

## What's in here

| File | Severity | What it asserts |
|---|---|---|
| `no-untrusted-with-prod-secret.yml` | Critical | A Secret tagged `environment: production` never reaches an Untrusted node. |
| `no-broad-identity-to-untrusted.yml` | Critical | A broad-scope Identity never reaches an Untrusted step. |
| `no-untrusted-image-with-secret.yml` | Critical | A Secret never propagates into an Untrusted (floating) image or action. |
| `prefer-oidc-over-static-secrets.yml` | High | Production-tagged Secrets should be migrated to OIDC. |
| `no-third-party-step-with-identity.yml` | High | An Identity never reaches a third-party Step (stricter than the built-in baseline). |
| `no-untrusted-with-secret.yml` | Critical | Any Secret reaching the Untrusted zone (broader than the prod-secret variant). |
| `no-pr-trigger-with-broad-identity.yml` | Critical | A broad-scope Identity exists in any PR-triggered pipeline. |
| `no-untrusted-image-anywhere.yml` | High | Any Untrusted (unpinned) Image exists in the pipeline (strict, no Secret needed). |
| `only-oidc-identities.yml` | High | A first-party Identity is not OIDC-capable. |
| `no-non-first-party-images.yml` | Medium | An Image is in `third_party` OR `untrusted` zone (vendoring policy). |
| `no-write-permissions-on-pr.yml` | High | An Identity in a PR-triggered pipeline has any `write` scope (substring match). |
| `no-script-step-without-env-approval.yml` | High | An ADO Step with an inline script body runs without an `environment:` approval gate. |
| `bundled-strict-policy.yml` | High/Crit | Multi-doc bundle of the three strictest invariants in one file. |

Each file has a leading comment block explaining the invariant, why it
matters, the DSL features it demonstrates, and a corpus file the
invariant fires on. They are deliberately small — they are templates to
copy, not a complete policy library.

## DSL features demonstrated

| File | `graph_metadata:` | `standalone:` | `not:` | `equals` / bare | `not_equals` | `contains` | `in` | multi-value list | multi-doc |
|---|---|---|---|---|---|---|---|---|---|
| `no-untrusted-with-prod-secret.yml` | | | | bare | | | | | |
| `no-broad-identity-to-untrusted.yml` | | | | bare | | | | | |
| `no-untrusted-image-with-secret.yml` | | | | | | | | | |
| `prefer-oidc-over-static-secrets.yml` | | | | bare | | | | | |
| `no-third-party-step-with-identity.yml` | | | | bare | | | | | |
| `no-untrusted-with-secret.yml` | | | | | | | | | |
| `no-pr-trigger-with-broad-identity.yml` | yes | | | bare | | | yes | | |
| `no-untrusted-image-anywhere.yml` | | yes | yes | | | yes | | | |
| `only-oidc-identities.yml` | | yes | yes | bare | | | | | |
| `no-non-first-party-images.yml` | | yes | | | | | | yes (`trust_zone`) | |
| `no-write-permissions-on-pr.yml` | yes | | | | | yes | yes | | |
| `no-script-step-without-env-approval.yml` | | yes | | | yes | yes | | | |
| `bundled-strict-policy.yml` | yes | yes | yes | bare | | | yes | yes | yes |

## Choosing your first invariant

| You are... | Start with these |
|---|---|
| **A strict org / regulated industry** | `bundled-strict-policy.yml` (one file, three rules), then layer `no-untrusted-with-prod-secret.yml`, `no-script-step-without-env-approval.yml`. Adopt OIDC-only via `only-oidc-identities.yml`. |
| **A permissive org getting started** | `no-untrusted-with-prod-secret.yml` (loudest signal, lowest false-positive rate), then `no-broad-identity-to-untrusted.yml`. Skip the `*-anywhere` and `non-first-party` rules until you have green pipelines. |
| **An OSS project** | `no-pr-trigger-with-broad-identity.yml` (catches the `pull_request_target` foot-gun) and `no-untrusted-image-with-secret.yml`. Avoid `only-oidc-identities.yml` if you accept community contributions that need PAT-based access. |
| **An enterprise platform team** | `bundled-strict-policy.yml` as the org-wide default, plus `no-non-first-party-images.yml` if you have a vendoring pipeline. Make `no-script-step-without-env-approval.yml` a merge gate on production-tagged repos. |

## Run them

```bash
# Apply the starter invariants alongside the 31 built-ins
taudit scan --invariants-dir invariants/starter .github/workflows/

# Verify they loaded (multi-doc files expand to one row per invariant)
taudit invariants list --invariants-dir invariants/starter

# Use as a hard CI gate (exit non-zero on any violation)
taudit verify --policy invariants/starter/bundled-strict-policy.yml \
  --platform github-actions .github/workflows/release.yml
```

`--invariants-dir` is the canonical spelling; `--rules-dir` is accepted as
a deprecated alias.

## Customising

The biggest customisation lever is metadata. Two of the original
invariants assume your Secret nodes are tagged with `environment:
production`. taudit does not infer that tag — you set it via your
pipeline parser, an upstream labelling step, or a fork of the parser
crate. If your tagging scheme differs, edit the `metadata:` block in the
YAML to match.

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
4. Run `taudit verify --policy <file> <pipeline.yml>` to see it fire (or
   stay silent — silence is success for an invariant).

See the full schema and predicate reference in
[`docs/authority-invariants.md`](../../docs/authority-invariants.md).
