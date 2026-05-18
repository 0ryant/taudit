# Hostile Rendering Corpus

Status: L5-09 implemented as a focused CLI/report regression lane.

ADR owner: [ADR 0019](../../adr/0019-reporter-sink-sanitization-boundary.md)

Test artifact: [`crates/taudit-cli/tests/hostile_rendering_corpus.rs`](../../../crates/taudit-cli/tests/hostile_rendering_corpus.rs)

## Scope

The corpus exercises attacker-controlled strings that flow through report and
render boundaries:

- control bytes: ESC clear-screen, BEL, C1 controls, bidi steering, zero-width
  joiners;
- markdown-looking text: links, HTML tags, image/link delimiters;
- SARIF-shaped text payloads: JSON fragments that look like additional SARIF
  `runs[].results[]` entries;
- CRLF and mixed path separators in workflow paths, custom-rule paths, node
  names, metadata, finding messages, and recommendations;
- long fields above normal terminal line length.

## Sink Boundary

The expected boundary is sink-specific:

- JSON preserves raw decoded payloads for machine consumers and keeps control
  bytes JSON-encoded on the wire.
- CloudEvents preserves raw finding data and raw `subject` while surfacing the
  same identity fields as other machine sinks.
- SARIF escapes Markdown/HTML render grammar in result messages and custom-rule
  descriptors without changing identity inputs.
- Terminal output strips control/steering bytes and folds attacker-supplied
  CRLF/tab characters in inline fields so hostile scalar values cannot mint
  forged standalone terminal lines.

The lane found and fixed one terminal-only issue: `strip_control_chars`
correctly preserved newline/tab for renderer-owned layout, but the private
terminal inline-field wrapper reused that behavior for attacker-controlled
scalar fields. The fix keeps the public helper contract unchanged and folds
newlines/tabs only after terminal scalar sanitization.

## Verification

Red evidence:

- `cargo test -p taudit --test hostile_rendering_corpus` failed on
  `terminal_rendering_neutralizes_control_bytes_and_crlf_path_injection`
  because CRLF in hostile paths and messages created
  `TAUDIT_FORGED_CLEAN_LINE` as standalone terminal lines.

Green evidence:

- `cargo test -p taudit --test hostile_rendering_corpus`
  - 3 passed, 0 failed.
- `cargo test -p taudit-report-terminal`
  - 14 passed, 0 failed.

## Residual Risk

This is a synthetic report-sink corpus, not a parser-input corpus. It proves the
sink boundary for hostile strings after a graph/finding exists; it does not
prove every provider parser can construct each hostile field from real YAML.

The terminal renderer still preserves long field content instead of truncating
or wrapping it. That is intentional for this lane: the acceptance gate is safe
rendering and stable identity, not terminal ergonomics.

## Next Dependency Unblocked

L5-11 can include L5-09 in the output conformance harness as the hostile
rendering fixture group. L5-02 and L5-05 can rely on the terminal inline-field
boundary when adding verbose identity/evidence rendering.
