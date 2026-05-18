# v1.2.0-rc.1 Evidence Rendering And Output Ceiling Matrix

Source decisions: [ADR 0013](../../adr/0013-evidence-rendering-and-output-ceiling.md), [ADR 0005](../../adr/0005-authority-edge-classifier-and-witness-handoff.md), [ADR 0006](../../adr/0006-exploit-path-view-and-ruleset.md), [ADR 0011](../../adr/0011-ordered-authority-evidence-model.md), [ADR 0017](../../adr/0017-current-output-profile-and-contract-examples.md), and [ADR 0019](../../adr/0019-reporter-sink-sanitization-boundary.md).

Lane links: [L2-05](code-complete-lanes.md#l2-api-schemas-contracts) defines this projection ceiling. [L5-02, L5-03, L5-04, L5-05, and L5-10](code-complete-lanes.md#l5-cli-reports-sinks-output-identity) consume it for JSON, SARIF, CloudEvents, terminal, and optional witness/observed-evidence behavior. [L6-11](code-complete-lanes.md#l6-docs-operator-evidence-adoption-proof) consumes the same ceiling for operator docs.

## Classification Values

| Value | Meaning |
| --- | --- |
| `public-default` | Safe for default customer output when the field exists and the claim is supported by static, inferred, or explicit observed evidence. Terminal default may summarize. |
| `public-verbose` | Safe for public opt-in verbose output, explain output, or expanded human triage, but not required in terse terminal default. |
| `sink-visible structured` | Public machine-sink field. JSON, SARIF, and CloudEvents must preserve a structured value when the current public contract includes the field. |
| `internal-gated` | May be emitted only behind an explicit internal feature gate, internal build, or internal CLI mode. It is absent from all default and public verbose output. |
| `forbidden/default-absent` | Must not appear in default output. If the claim depends on unavailable evidence, the claim is forbidden rather than downgraded into prose. |

## Global Ceiling Rules

- Public output may distinguish `static/source`, `inferred`, and explicit `observed` evidence. It must not collapse them into a stronger claim.
- Public output may say an evidence path is inferred from ordered source facts. It must not say the path was exploited, accepted for disclosure, assigned a CVE, or observed at a sink unless explicit observed evidence input exists.
- Terminal default may summarize public evidence; machine sinks preserve structured public fields once L2 freezes the current profile.
- Public verbose mode expands only public evidence and identity. It is not an internal gate.
- Internal-gated fields must be opt-in, testable, and absent from default JSON, SARIF, CloudEvents, terminal default, and terminal verbose snapshots.
- Sanitization is sink-local. Rendered or sanitized text must not feed `fingerprint`, `suppression_key`, or `finding_group_id`.

## Field And Claim Matrix

| Field or claim family | Ceiling | JSON obligation | SARIF obligation | CloudEvents obligation | Terminal default obligation | Terminal verbose obligation | Required guardrail |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Static source facts: workflow file, job, step, action reference, source span, parsed command, public catalog fact | `public-default`; detailed spans may be `public-verbose` | Preserve as structured fields when in the report/current profile. | Preserve public values in locations, message text, or `result.properties`; document any non-projection. | Preserve as `data` fields or extensions when in the event profile. | Summarize the source location and affected step safely. | Render public file, job, step, action, and command context needed for triage. | Do not expose private hosted-run anchors or internal catalog source notes. |
| Inferred path facts: prior mutable state reaches later authority-bearing helper path | `public-default` for the finding claim; `sink-visible structured` for graph/path facts | Preserve evidence strength and path facts as structured data where the schema includes them. | Map public path facts into `properties` or document non-projection. | Preserve public path facts in `data` or extensions when in the event profile. | May summarize as inferred authority path, not observed exploit. | Render ordered path details enough to explain the inference. | Must not emit from generic PATH mutation, generic helper use, or candidate identity alone. |
| Helper resolution | `sink-visible structured` | Preserve schema/API-backed enum or value. | Preserve in `result.properties` or documented non-projection. | Preserve in `data` or extension when in profile. | May summarize as bare command, shell, toolkit lookup, trusted absolute path, or downgraded mode. | Render exact public value. | Must not be ad hoc message-only text once promoted by L2/L4. |
| Authority transport | `sink-visible structured` | Preserve transport such as argv, stdin, env, credential/config file path, workspace file, or OIDC request env. | Preserve in `result.properties` or documented non-projection. | Preserve in `data` or extension when in profile. | May summarize the authority route. | Render exact public value. | Do not imply the helper received authority unless ordered evidence supports the transport. |
| Authority origin | `sink-visible structured` | Preserve origin such as caller-provided secret, action input secret, GitHub token, OIDC capability, action-minted credential, generated credential file, or derived payload. | Preserve in `result.properties` or documented non-projection. | Preserve in `data` or extension when in profile. | May summarize direct, action-minted, OIDC, generated, or derived authority. | Render exact public value. | Keep direct forwarding distinct from action-minted or generated authority. |
| Confidence | `public-default`; `sink-visible structured` when numeric or enum profile exists | Preserve public confidence enum/score when in current profile. | Preserve in `result.properties` or documented non-projection. | Preserve in `data` or extension when in profile. | May summarize high/medium/low or confidence-limited. | Render exact public value and reason when available. | Unknown resolution must be confidence-limited, not silently promoted. |
| Witness status label | `public-default` as evidence-strength label only | Preserve public status label when in current profile. | Preserve in `result.properties` or documented non-projection. | Preserve in `data` or extension when in profile. | May show evidence strength such as none, local, runner-faithful, or hosted. | Render the label and public meaning. | Label must not expose canaries, run IDs, private artifacts, witness-spec next action, or disclosure route. |
| Same-job caveat | `public-default` for affected helper-authority findings | Preserve caveat flag/text when in current profile. | Preserve in `properties` or safe message text. | Preserve in `data` or extension when in profile. | Include concise caveat when same-job reasoning is material. | Render full public caveat text. | Must state the claim is about earlier helper-resolution mutation before later authority materialization, not arbitrary same-job isolation. |
| Remediation and hardening labels | `public-default` | Preserve public labels and remediation category when in current profile. | Preserve in `properties` or rule/help text. | Preserve in `data` or extension when in profile. | Summarize the operator action. | Render labels and public remediation/hardening detail. | Do not mix product vulnerability labels with workflow misconfiguration or hardening labels. |
| Technical score | `public-default` only when defined as static technical priority; otherwise `public-verbose` | Preserve only if the score is deterministic/static and documented. | Preserve in `properties` or document non-projection. | Preserve in `data` or extension when in profile. | May show severity/priority summary. | Render score and static inputs when public. | Must not include vendor-acceptance, disclosure, CVE, or private witness inputs unless internally gated. |
| Disclosure score | `internal-gated` | Absent from default/public JSON. | Absent from default/public SARIF. | Absent from default/public events. | Absent. | Absent in public verbose. | Negative tests must distinguish allowed technical score from forbidden disclosure score. |
| Recommended disclosure route | `internal-gated` | Absent from default/public JSON. | Absent from default/public SARIF. | Absent from default/public events. | Absent. | Absent in public verbose. | No public route names, vendor-routing hints, embargo hints, or acceptance language. |
| CVE workflow metadata | `internal-gated` | Absent from default/public JSON. | Absent from default/public SARIF. | Absent from default/public events. | Absent. | Absent in public verbose. | No CVE claim, CVE workflow state, CVSS-like projection, or vulnerability-assignment language. |
| Witness-spec next actions | `internal-gated` | Absent unless an explicit internal witness-spec mode is enabled. | Absent unless an explicit internal witness-spec mode is enabled and mapped intentionally. | Absent unless an explicit internal witness-spec mode is enabled and mapped intentionally. | Absent. | Absent in public verbose. | L5-10 must prove default CLI omits and rejects accidental exposure. |
| Canary values | `internal-gated` and default-absent | Absent from default/public JSON. | Absent from default/public SARIF. | Absent from default/public events. | Absent. | Absent in public verbose. | No secret marker, fake credential, project ID, token, or canary payload may leak. |
| Private hosted-run artifacts | `internal-gated` and default-absent | Absent from default/public JSON. | Absent from default/public SARIF. | Absent from default/public events. | Absent. | Absent in public verbose. | No private run ID, artifact URL, private log URL, private source anchor, or internal witness attachment. |
| Observed sink claim or `ObservedSink` edge | `sink-visible structured` only with explicit observed evidence input; otherwise `forbidden/default-absent` | With explicit evidence, preserve observed status without canary/private detail. Without it, omit observed sink fields or keep observed counts zero. | With explicit evidence, map public observed status to `properties`; without it, omit. | With explicit evidence, preserve public observed status; without it, omit. | Without explicit evidence, do not say observed. With explicit evidence, summarize observed evidence without canary/private detail. | Render observed status and public evidence strength only when explicit observed input exists. | Static shape, action identity, catalog presence, or known candidate status must never invent observed behavior. |

## Per-Sink Obligations

| Sink | Obligation |
| --- | --- |
| JSON report and graph JSON | Preserve public structured fields in the current profile; omit internal-gated and forbidden/default-absent fields by default; keep static, inferred, and observed evidence strengths distinct; validate examples against compatibility schema and current profile. |
| SARIF | Map every public finding extra to standard SARIF fields or `result.properties`, or document non-projection for L5-03; escape/render SARIF text safely; keep identity and evidence values structured where projected. |
| CloudEvents | Emit one finding event with public evidence in `data` or documented extensions for L5-04; keep event identity stable; do not promote internal metadata into extensions. |
| Terminal default | Provide concise customer-safe text: finding identity, source summary, public evidence strength, core authority route, same-job caveat when material, and remediation/hardening summary. Strip control bytes and never render internal-gated fields. |
| Terminal verbose | Add public triage detail: identity, source facts, helper resolution, authority transport, authority origin, confidence, witness status label, same-job caveat, suppression metadata, and remediation/hardening labels. It must still omit internal-gated fields unless a separate internal mode is explicitly enabled. |

## Negative Test Requirements For L5

L5 must add negative tests that fail on any default/public leakage:

| Requirement | Required proof surface |
| --- | --- |
| Internal fields are absent by default | Default JSON, SARIF, CloudEvents, terminal default, and terminal verbose fixtures contain no `disclosure_score`, disclosure route, CVE workflow metadata, witness-spec next action, canary value, private hosted-run artifact, private source anchor, or private artifact URL. |
| Technical score is not disclosure score | A fixture with public technical priority may render `technical_score`, but default/public outputs must not contain `disclosure_score`, vendor-acceptance scoring, CVE state, or disclosure-routing prose. |
| Observed sink is evidence-gated | A static/inferred helper-authority fixture without observed evidence emits no `ObservedSink`, no observed sink claim, and no positive observed count in JSON/SARIF/CloudEvents/terminal output. A separate explicit-observed fixture may emit public observed status but still omits canary values and private artifacts. |
| Public evidence parity holds | One positive helper-authority fixture proves required public evidence fields appear consistently across JSON, SARIF, CloudEvents, and terminal verbose mode per L5-02. |
| SARIF projection is intentional | L5-03 checks every public finding extra is either in SARIF `properties` or listed as non-projected in docs/snapshots. |
| CloudEvents projection is intentional | L5-04 checks every public event field or extension is documented, schema-valid, and free of internal-gated metadata. |
| Terminal verbose stays public | L5-05 snapshots include identity/evidence/suppression detail but still omit disclosure, CVE, witness-spec, canary, and private artifact data. |
| Witness-spec and observed-evidence modes are gated | L5-10 proves optional internal witness-spec or observed-evidence CLI behavior is disabled by default and requires an explicit gate if shipped. |
| Sanitization does not mutate identity | Hostile rendering corpus cases from ADR 0019 preserve `rule_id`, `fingerprint`, `suppression_key`, and `finding_group_id` across raw JSON/CloudEvents and sanitized terminal/SARIF projections. |
| Same-job caveat is present when material | Positive same-job helper-authority fixtures include the public caveat in terminal verbose and any machine sink that promises the caveat in the current profile. |

## Downstream Dependency Unblocked

This matrix gives L5 enough ceiling detail to implement evidence parity, SARIF and CloudEvents projection maps, terminal verbose rendering, and default-leakage tests without waiting for internal disclosure or witness-spec fields to become public.
