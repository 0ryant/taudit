# Operator Evidence Output Guide

This guide is the L6-11 operator-facing companion to
[ADR 0013](../../adr/0013-evidence-rendering-and-output-ceiling.md), the
[current output profile](current-output-profile.md), and the
[output ceiling matrix](output-ceiling-matrix.md). It explains how to read
taudit evidence in JSON, SARIF, CloudEvents, and terminal output during the
v1.2.0 release-candidate window.

The short version: taudit reports static and inferred CI/CD authority facts. It
does not make public disclosure, CVE, exploit-observed, or witness-next-action
claims in default output.

## Operator Contract

Treat taudit output as an authority-graph triage surface:

- `static` facts come from parsed pipeline source, schemas, and public catalog
  data.
- `inferred` facts are graph or ordering conclusions over those source facts.
- `witness_label` is only an evidence-strength label. It is not a witness plan,
  a disclosure route, or proof that a sink was exercised.
- `observed` is allowed only when an explicit observed-evidence input exists.
  A static workflow shape, known action behavior, or catalog entry must not be
  read as observed behavior.
- CVE, vendor-disclosure, private hosted-run, canary, and witness-spec workflow
  metadata are outside public default and public verbose output.

When a finding says a helper, credential, or authority path is risky, read it as
"the workflow source and graph support this authority path" unless the artifact
explicitly marks observed evidence. Do not rewrite that into "this was
exploited" or "this has a CVE."

## Surface Selection

| Need | Prefer | Why |
| --- | --- | --- |
| Human triage in a shell or CI log | terminal default, then terminal verbose | Concise and sanitized for reading. |
| Stable joins across scans, baselines, suppressions, and SIEM | JSON, SARIF, or CloudEvents identity fields | They preserve `rule_id`, `fingerprint`, `suppression_key`, and `finding_group_id`. |
| Code scanning ingestion | SARIF | SARIF carries taudit identity in `result.ruleId`, `partialFingerprints`, and `result.properties`. |
| Event pipelines and SIEM ingestion | CloudEvents JSONL | One event per finding with CloudEvents envelope and taudit extension attributes. |
| Contract or release proof | current-profile fixtures plus conformance harness | Compatibility schemas alone may accept older documents. |

## JSON Report

JSON is the richest operator-facing machine report for one scan. Current RC
profile checks expect:

- root `schema_version` and `schema_uri`;
- graph source, nodes, edges, completeness, and typed completeness gaps when
  the graph is partial;
- finding identity: `rule_id`, `fingerprint`, `suppression_key`, and
  `finding_group_id`;
- public finding extras when emitted, including `confidence_scope`,
  `runtime_preconditions`, `portal_control_dependency`, `authority_kinds`,
  `attacker_surface_kinds`, `template_resolution_strength`, `time_to_fix`, and
  `compensating_controls`;
- suppression metadata when a suppression or downgrade matched.

JSON should be the first place an operator checks whether a finding is
complete, partial, suppressed, or downgraded. It preserves structured values
through normal JSON encoding; rendered terminal or SARIF text must not be used
to recompute identity.

Current RC boundary: `ordered_authority_evidence` has a core skeleton, but the
current profile still treats cross-sink projection as a pending dependency
until L2/L4/L5 wiring and fixtures land.

## SARIF

SARIF is for code-scanning systems and SARIF-aware dashboards. Operators should
join SARIF back to JSON or CloudEvents with:

- `result.ruleId` for the taudit rule id;
- `result.partialFingerprints.primaryLocationLineHash` and
  `result.partialFingerprints["taudit/v1"]` for the finding fingerprint;
- `result.properties.suppressionKey` for the operator waiver key;
- `result.properties.findingGroupId` for finding grouping;
- public evidence properties such as `confidenceScope`,
  `runtimePreconditions`, `portalControlDependency`, `authorityKinds`,
  `attackerSurfaceKinds`, and `templateResolutionStrength` when present.

SARIF text is safe to render in SARIF consumers, but it is still a rendering
surface. Use structured SARIF fields for automation. Do not infer disclosure
state, exploitability, or CVE status from SARIF severity, rule text, or
advisory-class wording.

## CloudEvents

CloudEvents JSONL is the event-pipeline and SIEM surface. Each line is one
finding event. The useful operator join fields are:

- envelope: `specversion`, `id`, `source`, `type`, `subject`,
  `datacontenttype`, and `time`;
- provenance: `correlationid`, `tauditpipelineid`, `tauditscanrunid`,
  `provenancerepo`, `provenanceproducer`, `provenanceversion`, and
  `provenancekind`;
- identity: `tauditruleid`, `tauditfindingfingerprint`,
  `tauditsuppressionkey`, and `tauditfindinggroup`;
- graph completeness: `tauditcompleteness` and, for typed partial graphs,
  `tauditcompletenessgaps`;
- platform: `tauditplatform` when the parser and current profile define a
  normalized platform token for the event.

CloudEvents `type` is a routing category, not the precise rule id. Use
`tauditruleid` for rule-level filtering. Do not add disclosure route, canary,
private hosted-run artifact, or witness-spec data to public extensions.

## Terminal Output

Terminal output is the human triage surface, not the durable contract surface.

Default terminal output may show the finding severity, message, path or
involved nodes, recommendation, partial-completeness warnings, and concise
authority-route language. It intentionally stays compact for CI logs.

Verbose terminal output may add public node details such as node kind, trust
zone, identity scope, permissions, digest prefix, inferred markers, and typed
gap labels. It remains public output. It must not expose disclosure scores,
CVE workflow metadata, witness-spec next actions, canary values, private hosted
run artifacts, or observed sink claims without explicit observed evidence.

Current RC boundary: terminal verbose identity and evidence rendering is still
owned by L5-05 in the current-output profile. Until that lane lands, use JSON,
SARIF, or CloudEvents for stable identity joins.

## Evidence Language

Recommended operator wording:

| Evidence shape | Say | Do not say |
| --- | --- | --- |
| Static source fact | "The workflow declares..." | "The run executed..." |
| Inferred path fact | "taudit infers an authority path..." | "The secret was exfiltrated..." |
| Helper-authority finding | "A mutable helper path can receive authority under these source facts..." | "The helper was exploited..." |
| Witness status label | "Evidence strength is labelled..." | "The witness proved disclosure..." |
| Explicit observed evidence | "Observed evidence input marks..." | "Observed because the static graph resembles..." |
| CVE/advisory relationship | "This resembles or maps to a known class when documented..." | "This finding is a CVE..." |

If a ticket, PR comment, or incident note needs stronger wording than the
artifact provides, attach the explicit observed evidence or witness output that
supports that stronger claim.

## Suppressions And Baselines

Suppressions and baselines are identity-sensitive. Operators should key on:

- `fingerprint` for exact finding identity;
- `suppression_key` for reviewed waivers that should survive unrelated
  surrounding workflow edits;
- `rule_id` for rule-level reporting and dashboards;
- `finding_group_id` for grouping related findings against a shared authority
  root.

When suppression changes severity or hides a finding in a human surface,
machine outputs must still preserve identity and the configured suppression
metadata. A suppression is an operator decision, not evidence that the path is
safe in the abstract.

## Sanitization Boundary

The sink owns rendering safety:

- terminal strips control bytes before rendering;
- SARIF escapes Markdown-sensitive text before SARIF rendering;
- JSON and CloudEvents preserve structured values through JSON encoding;
- sanitized or rendered text must not feed `fingerprint`, `suppression_key`, or
  `finding_group_id`.

For automation, consume structured fields. For humans, prefer terminal or SARIF
rendering. Do not scrape colored terminal text to make policy decisions.

## Release Candidate Checklist

Before treating evidence rendering as release-ready, the RC needs proof that:

- JSON, SARIF, CloudEvents, and terminal verbose do not leak ADR 0013
  internal-gated fields by default;
- JSON, SARIF, and CloudEvents preserve public identity byte-for-byte;
- SARIF and CloudEvents projection maps list every public evidence field or
  document an intentional non-projection;
- terminal verbose rendering is sanitized and public-only;
- observed sink claims appear only with explicit observed evidence input;
- ordered authority evidence is either projected consistently or remains
  explicitly pending in the current profile;
- hostile rendering cases preserve identity across raw and rendered sinks.

## Next Dependency Unblocked

This guide gives L5 output workers and QA conformance workers the operator
language to use in docs, snapshots, and release notes without inventing
disclosure, CVE, witness-plan, or observed-exploit semantics.

## Residual Risk

This is RC operator documentation, not proof that every sink projection is
already code complete. It is grounded in ADR 0013, ADR 0019, the current output
profile, the output ceiling matrix, and current reporter/sink code observed
during Wave 6D. Re-run the conformance harness and projection tests after
parallel L5/L6 changes before using it as release evidence.
