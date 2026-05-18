# Action Intelligence Catalog Contract Seed

L4-03 defines the schema and validation surface for action intelligence catalog
entries. It is intentionally non-exhaustive and does not seed the full L4-04
catalog.

## Artifacts

- Schema: `schemas/action-intelligence-catalog.v1.json`
- Example: `data/action-intelligence-catalog.example.json`
- Test: `tests/test_action_intelligence_catalog.py`

## Entry Shape

Each entry records:

- `id`: stable catalog-local id.
- `action`: ecosystem and action name without the `@ref` suffix.
- `version_ref`: classified version/ref marker such as `major_ref`, `pinned_tag`,
  `sha`, `unversioned`, or `unknown`.
- `helper_resolution`: schema/API-backed helper resolution value aligned with the
  exploit graph contract.
- `helper_invocations`: concrete helper facts that can feed
  `HelperExecution.helper`, including helper name, resolution, authority
  transport, and optional sanitized argument-pattern hints.
- `authority_transport`: one or more public authority transport values.
- `authority_origin`: one or more public authority origin values.
- `source_evidence`: either `source_anchors` or a `witness_status` explanation.
- `confidence` and `evidence_tier`: public confidence and evidence-strength
  labels.
- `deferred`: marker for incomplete source or witness work, with
  `deferred_reason` required when true.

## Source And Witness Rule

Every entry must have at least one public/source anchor or a witness-status
explanation. Source anchors may point to public upstream source, public docs,
taudit docs, or taudit fixtures. Witness status is a public label only; private
witness commands, canaries, run ids, hosted artifacts, and source-scan internals
remain outside this public catalog contract.

## Scope Boundary

This file is the L4-03 contract seed. The checked-in example has 2-3 entries to
exercise the shape and the deferred marker. It is not the seeded catalog for
Firebase, Azure, Cloudflare, Docker, npm, ECR, setup-gcloud, GoReleaser,
Codecov, or Teleport.

L4-04 can now populate reviewed entries against this schema, add stronger source
anchors, and decide which deferred examples become catalog facts.
