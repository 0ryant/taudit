# gaps

Source: `C:/Users/0ryant/prj/ecosystem-catalog/manager-reports/2026-05-21-ecosystem-synthesis-next-level.md`

## Goal

Land a callable agent-facing `taudit` MCP surface while preserving existing
SARIF, JSON, CloudEvents, DOT, and Mermaid outputs.

## Missing

- Canonical MCP server invocation.
- Tool authority declarations for scan, graph, explain, diff, and remediation
  suggestion flows.
- Proof that SARIF and CloudEvents outputs remain first-class.
- Integration receipt for `taudit -> tsign -> tapprove`.

## Steps

1. Choose native MCP or mcpact-generated MCP as the canonical path.
2. Define the authority class for every exposed tool.
3. Keep remediation apply separate from remediation suggest.
4. Add smoke tests for MCP scan and graph calls.
5. Verify existing SARIF, JSON, CloudEvents, DOT, and Mermaid outputs still
   render for the same fixture.
6. Produce a graph digest that `tsign` can attest.
7. Add a combined proof packet consumed by `tapprove`.

## Acceptance evidence

- MCP smoke transcript.
- Existing output projections remain present.
- Graph digest is stable across repeated runs.
- `tsign` attestation and `tapprove` review reference the same graph digest.

## Stop conditions

- Do not make remediation apply available without explicit mutation authority.
- Do not replace SARIF or CloudEvents with a proprietary-only receipt format.
