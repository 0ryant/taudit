# v1 Authority Graph Schema — Lock Decisions

**Status:** Reviewed for v1.0.0 lock. The canonical schema lives on branch `worktree-agent-aa6235bddd31e5d9d` at `schemas/authority-graph.v1.json` (not yet merged to main).

**Method:** Each open question from the v1 contract review was decided against three constraints:

1. **Lock once, evolve additively.** A v1 lock means future changes ship as additive 1.x.y minor versions; renames force a v2.0.0 schema bump per `engineering-doctrine/principles/semantic-versioning.md`.
2. **Stable contract per `type`** (`engineering-doctrine/principles/event-contracts.md` §3): payload field names, enum string values, and identifiers must be stable across the v1 line.
3. **Convention over novelty** (`engineering-doctrine/principles/naming-and-repo-layout.md` §2): when two names are equivalent, choose the one a domain reader will already understand.

The decisions below are the v1 lock contract. Items flagged **ACTION → schema worktree owner** must land in `worktree-agent-aa6235bddd31e5d9d` before that branch merges.

---

## Decision summary

| # | Question | Decision |
|---|----------|----------|
| 1 | `EdgeKind::PersistsTo` verb | **KEEP** — `persists_to` |
| 2 | `TrustZone` count | **KEEP 3** + use metadata for finer distinctions |
| 3 | `Job` as its own `NodeKind` | **KEEP collapsed** — promote `META_JOB_NAME` to documented public key |
| 4 | Schema `$id` URL | **KEEP** current GitHub URL as a logical identifier |
| 5 | Missing fields the schema doesn't enumerate | **`parameters` is missing — schema must add it; `META_*` keys stay parser-private** |
| 6 | `commit_sha` on `PipelineSource` | **ADD** as optional |

---

## 1. `EdgeKind::PersistsTo` — KEEP

**Question:** Is "persists" the right verb? Alternatives: `WritesTo`, `OutputsTo`, `Materializes`.

**Decision:** Keep `persists_to`.

**Rationale:** First-principles deconstruction confirms `persists_to` is the only candidate that carries the lifetime semantic the edge is asserting — the credential outlives the step that created it. `WritesTo` and `OutputsTo` collide with `Produces` (which already models step→artifact data flow) and would force the schema to express the lifetime distinction in metadata instead of the edge kind itself. `Materializes` is borrowed from database-view terminology where it means "compute and store a derived form" — it does not foreground lifetime. Persistence is also a well-understood OS / storage term, satisfying the doctrine's "convention over novelty" rule. Lock as `persists_to`.

---

## 2. `TrustZone` cardinality — KEEP 3

**Question:** Add `Internal` (org-internal cross-tenant) or split `ThirdParty` into `VendorTrusted` vs `ThirdParty` for vendor-supplied-but-pinned actions like Azure-published tasks?

**Decision:** Keep the existing three zones (`first_party`, `third_party`, `untrusted`). Express finer distinctions via additive metadata keys on the `Node`.

**Rationale:** Adding zones now is non-additive: every consumer pattern-match (`switch (zone) { ... }`) must grow new branches. The trust dimensions the user identified — "org-internal cross-tenant" and "vendor-trusted-with-different-blast-radius" — are real, but they are *attributes* of an entity rather than fundamentally different trust semantics. The graph already supports per-node `metadata: { string → string }` with `additionalProperties` open, so a future `META_ORG_INTERNAL` or `META_VENDOR_PUBLISHED` key is a 1.x.y additive change while a new `TrustZone` enum value is structural. Per `event-contracts.md` §3 ("one schema per `type` for a given major version"), the conservative move is to keep the enum minimal and let metadata absorb the variance until consumer demand forces a v2.

---

## 3. `Job` as `NodeKind` — KEEP COLLAPSED

**Question:** Should `Job` be its own `NodeKind`, or remain modelled as parent-of-step via `META_JOB_NAME`?

**Decision:** Keep `Job` collapsed into `Step`. Promote `META_JOB_NAME` (already stamped by both GHA and ADO parsers — `crates/taudit-core/src/graph.rs:52`) to a documented public metadata key in the schema docstring.

**Rationale:** Adding a `Job` node kind means every existing consumer's BFS / authority-propagation logic must grow a new edge type (`Step → Job`) and a new traversal rule. The current model — Job is a logical grouping of Steps, surfaced as a metadata attribute — already supports the only consumer use case the user identified ("this Job has authority X"): walk every Step where `metadata.job_name == X` and union their authority edges. That is a 5-line consumer query. Promoting Job to a NodeKind solves the same problem with a 5-line consumer query plus a v2 schema bump. The cost-benefit is firmly against. Lock with `META_JOB_NAME` documented as a stable public key.

**ACTION → schema worktree owner:** add a paragraph to the `Node.metadata` schema description that names `job_name` as a publicly stable key on `step` nodes.

---

## 4. Schema `$id` URL — KEEP

**Question:** The current `$id` is `https://github.com/0ryant/taudit/schemas/authority-graph.v1.json` — a GitHub blob URL. Better candidates: `taudit.dev` (requires DNS), `raw.githubusercontent.com/...` (more durable than blob).

**Decision:** Keep the current `$id`. Treat it as a logical URI, not a fetch URL. Defer hosted schema distribution to a separate, additive future ADR.

**Rationale:** JSON Schema draft-07 explicitly permits `$id` to be a non-resolvable URI used as an identifier rather than a URL the validator must fetch. Three options were considered:

- **`raw.githubusercontent.com/...`** is more cacheable than the blob URL but couples the identifier to the *branch* (`/main/...`). If the default branch is renamed (a real industry pattern — `master` → `main` migrations), every embedded reference 404s.
- **`taudit.dev/schemas/...`** is the long-term right answer but requires DNS we do not yet own. Gating v1 schema lock on procuring a domain delays the lock for non-technical reasons.
- **The current GitHub blob URL** is stable as long as the GitHub username and repository name do not change. It is no worse than the raw URL on durability and avoids the branch-coupling failure mode.

The cost of "wrong" here is bounded: we can ship a 1.x.y minor that *adds* a `schema_uri` alongside `$id` later, or publish a redirect from `taudit.dev` to whichever blob URL is canonical at the time. None of these futures require a v2 bump. Lock as-is.

**ACTION → schema worktree owner:** add a one-line comment to the schema description: "$id is a stable logical identifier, not necessarily a fetch URL."

---

## 5. Fields the schema does not enumerate

The Rust struct `AuthorityGraph` (`crates/taudit-core/src/graph.rs:273-291`) serializes fields the schema does not describe. Audit:

| Rust field | Schema enumerated? | Verdict |
|------------|-------------------|---------|
| `source` | ✓ yes | OK |
| `nodes` | ✓ yes | OK |
| `edges` | ✓ yes | OK |
| `completeness` | ✓ yes | OK |
| `completeness_gaps` | ✓ yes (omitted when empty) | OK |
| `metadata` | ✓ yes (graph-level open map) | OK |
| **`parameters`** | **✗ NO** | **schema gap — must add** |

The `parameters: HashMap<String, ParamSpec>` field on `AuthorityGraph` is `#[serde(default, skip_serializing_if = "HashMap::is_empty")]`, so it appears in the JSON output for any ADO pipeline with declared parameters. External consumers will see a field the schema does not document.

**Decision:** **ACTION → schema worktree owner:** add a `parameters` definition to `AuthorityGraph` and a `ParamSpec` definition with the two fields `param_type: string` and `has_values_allowlist: boolean` before v1 lock. This is a schema-completeness fix, not a logic change.

### `META_*` constants (parser-private extension keys)

`crates/taudit-core/src/graph.rs` defines 22 `META_*` string constants used as keys inside the open `Node.metadata` map. The schema describes the map as `additionalProperties: { type: "string" }`, which already permits all of them additively. Decision: do **not** enumerate them in the schema. They are documented in source as an extension surface; promoting them to the schema would freeze their names at v1 and force every parser-internal bookkeeping field into the public contract.

Two exceptions are stable enough to deserve a schema docstring callout (not enumeration):

- `job_name` — already covered under decision (3) above.
- `digest`, `permissions`, `identity_scope` — appear in the schema docstring already as illustrative examples; keep that informal listing.

---

## 6. `commit_sha` on `PipelineSource` — ADD

**Question:** Should `PipelineSource` carry `commit_sha` for reproducibility alongside `file`, `repo`, `git_ref`?

**Decision:** Add `commit_sha: string` as an optional field to `PipelineSource`.

**Rationale:** Cost is one schema field plus one Rust struct field with `Option<String>`. Benefit is reproducibility: a downstream consumer (e.g. SARIF artifact attribution, a graph diff tool, a compliance log) can pin findings to an exact tree state even when `git_ref` is a mutable branch. Adding it now under v1 is a free additive change. Adding it after v1 lock is also additive but pollutes the 1.x.y series with a "we should have done this at lock" minor bump.

**ACTION → schema worktree owner:** add `commit_sha: { type: string, description: "Optional 40-char SHA the file was read from." }` to `PipelineSource` and the matching `Option<String>` field to the Rust struct (with `#[serde(skip_serializing_if = "Option::is_none")]`).

---

## Summary of actions for the schema worktree owner

Before merging `worktree-agent-aa6235bddd31e5d9d`, apply these schema edits in that worktree (NOT in this one — see [§Cross-worktree edit hygiene](#cross-worktree-edit-hygiene)):

1. Add `parameters` definition referencing a new `ParamSpec` definition with `param_type: string` and `has_values_allowlist: boolean`.
2. Add `commit_sha: { type: string }` (optional) to `PipelineSource` and matching field in `crates/taudit-core/src/graph.rs::PipelineSource`.
3. Add a schema-description note: `Node.metadata.job_name` is a stable public key on `step` nodes.
4. Add a schema-description note: `$id` is a logical identifier, not necessarily a fetch URL.

No other changes. Verbs, zones, node kinds, and the `$id` value are locked.

---

## Cross-worktree edit hygiene

This decision document was authored in `worktree-agent-aaa164f5c62ae268f` (the contract-review worktree). The schema file itself lives only on branch `worktree-agent-aa6235bddd31e5d9d` and was deliberately NOT edited from this worktree to avoid merge collisions with the canonical schema author. The four ACTION items above are scoped so that the schema-worktree owner can apply them locally before merging.

---

## References

- `engineering-doctrine/principles/event-contracts.md` — stable `type`, additive evolution
- `engineering-doctrine/principles/semantic-versioning.md` — major bump on rename, deprecation before removal
- `engineering-doctrine/principles/naming-and-repo-layout.md` — convention over novelty
- `crates/taudit-core/src/graph.rs` — canonical Rust types and `META_*` constants
- `schemas/authority-graph.v1.json` (on `worktree-agent-aa6235bddd31e5d9d`) — schema under review
