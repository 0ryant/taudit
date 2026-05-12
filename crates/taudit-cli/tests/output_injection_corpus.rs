//! Output-channel injection regression corpus — RC blocker B (v1.1.0-rc.1).
//!
//! Threat model: an attacker who controls pipeline YAML or custom-rule YAML
//! can plant escape sequences, Markdown link syntax, or Unicode steering
//! codepoints in fields that flow into render output:
//!
//!   * `finding.message` — composed from custom-rule `id`/`name`
//!     plus node names, all from YAML.
//!   * `node.name` — directly from YAML keys.
//!   * `graph.source.file` — the workflow filename (PR-controllable).
//!   * `Recommendation::Manual` — sourced from custom-rule `description:`.
//!   * custom rule `name`/`id` — directly from custom-rule YAML.
//!
//! Without sanitisation:
//!
//!   * the **terminal sink** lets a crafted message clear the screen
//!     (`\x1b[2J\x1b[H`), wrap subsequent output in fake colours
//!     (`\x1b[1;32m...\x1b[0m`), emit BEL (`\x07`), or reverse glyph order
//!     with RTL override (`\u{202e}`) — operator sees a forged "no findings"
//!     banner.
//!   * the **SARIF sink** lets a Markdown link (`[click](https://evil)`)
//!     render as a clickable phishing link inside an "authentic" taudit
//!     alert in GitHub Code Scanning UI.
//!   * the **JSON sink** ships raw bytes — that's correct (machine-readable
//!     consumers don't render escapes) — but the test pins that property so
//!     a future "sanitise everywhere" patch doesn't accidentally mutate the
//!     JSON contract.
//!
//! This corpus enforces:
//!
//!   1. JSON sink: hostile bytes appear as-is (raw shipping is the contract).
//!   2. SARIF sink: Markdown link / HTML delimiters are escaped on the
//!      attacker-controllable result.message.text path.
//!   3. Terminal sink (colour OFF): no `\x1b`, `\x07`, `\u{202e}`,
//!      `\u{200d}`, or any C0/C1 control byte appears in the rendered output
//!      (`\n` / `\t` excepted).
//!   4. Cross-sink fingerprint parity: sanitisation must NOT shift the
//!      fingerprint — fingerprint inputs are the RAW pre-sanitisation finding
//!      fields (see `taudit_core::finding::compute_fingerprint`).
//!
//! Per `docs/RELEASE_GATES.md §2.1`, this file landing in CI is the named
//! artifact for RC blocker B promotion.

use std::collections::HashMap;

use taudit_core::custom_rules::{CustomRule, MatchSpec};
use taudit_core::finding::{
    Finding, FindingCategory, FindingExtras, FindingSource, Recommendation, Severity,
};
use taudit_core::graph::{AuthorityGraph, EdgeKind, NodeKind, PipelineSource, TrustZone};
use taudit_core::ports::ReportSink;
use taudit_report_json::JsonReportSink;
use taudit_report_sarif::SarifReportSink;
use taudit_report_terminal::TerminalReport;

// ── Hostile fixture builders ─────────────────────────────────────

/// Hostile string covering every attack class catalogued in the deep audit
/// (Agent 9 / Rook, `/tmp/taudit-deep-review/09-security.md` Findings 2+3):
///   * `\x1b[2J\x1b[H` — clear-screen + cursor-home (impersonates clean run)
///   * `\x1b[1;32m...\x1b[0m` — green-text wrapper (fake "✓" banner)
///   * `\x07` — BEL (audio noise)
///   * `\u{202e}` — RTL override (reverses glyph order to spoof identifiers)
///   * `\u{200d}` — zero-width joiner (defeats copy-paste review)
const HOSTILE_ANSI_AND_UNICODE: &str =
    "\x1b[2J\x1b[H\x1b[1;32m\u{202e}AWS\u{200d}_KEY\x07 reaches deploy\x1b[0m";

/// Markdown / HTML payload that GitHub Code Scanning renders as a clickable
/// link inside an "authentic" taudit alert if shipped verbatim.
const HOSTILE_MARKDOWN: &str = "Click [here](https://attacker.example/?steal=1) for context";

/// Combined attack — the realistic worst case where a custom-rule `name:`
/// carries both an ANSI payload AND a Markdown link.
const HOSTILE_COMBINED: &str =
    "\x1b[2J\x1b[H[click](https://attacker.example) \u{202e}deploy\u{200d}";

fn build_hostile_graph() -> (AuthorityGraph, Vec<Finding>) {
    // graph.source.file carries an ANSI payload — a hostile PR could rename
    // a workflow file. The terminal renderer prints it as part of the
    // section header.
    let mut graph = AuthorityGraph::new(PipelineSource {
        file: format!(".github/workflows/{HOSTILE_ANSI_AND_UNICODE}.yml"),
        repo: None,
        git_ref: None,
        commit_sha: None,
    });

    // Node names — directly attacker-controllable as YAML keys.
    let secret = graph.add_node(
        NodeKind::Secret,
        HOSTILE_ANSI_AND_UNICODE,
        TrustZone::FirstParty,
    );
    let step = graph.add_node(NodeKind::Step, HOSTILE_COMBINED, TrustZone::FirstParty);
    graph.add_edge(step, secret, EdgeKind::HasAccessTo);

    // Verbose-mode metadata also reaches the renderer.
    if let Some(node) = graph.nodes.get_mut(step) {
        let mut meta: HashMap<String, String> = HashMap::new();
        meta.insert("permissions".into(), "\x1b[31mwrite-all\x1b[0m".into());
        meta.insert(
            "identity_scope".into(),
            HOSTILE_ANSI_AND_UNICODE.to_string(),
        );
        node.metadata = meta;
    }

    let custom = Finding {
        severity: Severity::High,
        category: FindingCategory::AuthorityPropagation,
        path: None,
        nodes_involved: vec![secret, step],
        message: format!("[my_custom_rule] {HOSTILE_COMBINED}: {HOSTILE_MARKDOWN}"),
        recommendation: Recommendation::Manual {
            action: HOSTILE_MARKDOWN.to_string(),
        },
        source: FindingSource::Custom {
            source_file: std::path::PathBuf::from("rules/hostile.yaml"),
        },
        extras: FindingExtras::default(),
    };

    let builtin = Finding {
        severity: Severity::Medium,
        category: FindingCategory::UnpinnedAction,
        path: None,
        nodes_involved: vec![step],
        message: HOSTILE_MARKDOWN.to_string(),
        recommendation: Recommendation::Manual {
            action: "review".to_string(),
        },
        source: FindingSource::BuiltIn,
        extras: FindingExtras::default(),
    };

    (graph, vec![custom, builtin])
}

/// Hostile custom rule descriptor — the SARIF sink ships its `name` and
/// `description` in the rules catalogue (`tool.driver.rules[*]`).
fn hostile_custom_rules() -> Vec<CustomRule> {
    vec![CustomRule {
        // `id` is constrained to snake_case + kebab-case + digits at
        // deserialise time, so it cannot carry an ANSI/Markdown payload —
        // the security boundary on the id field is the deserialiser, not
        // the render boundary. Keep the id legitimate.
        id: "my_custom_rule".to_string(),
        // `name` and `description` are free-form — full attacker control.
        name: HOSTILE_COMBINED.to_string(),
        description: HOSTILE_MARKDOWN.to_string(),
        severity: Severity::High,
        category: FindingCategory::AuthorityPropagation,
        match_spec: MatchSpec::default(),
        source_file: None,
    }]
}

// ── Per-sink invariant tests ─────────────────────────────────────

/// JSON sink ships raw bytes. The contract: machine-readable consumers
/// don't render escapes, so passing the bytes through unchanged is correct
/// AND the responsibility of any UI consumer to sanitise. Pin this property
/// so a future "sanitise everywhere" patch can't silently mutate the JSON
/// shape.
#[test]
fn json_sink_ships_hostile_bytes_verbatim() {
    let (graph, findings) = build_hostile_graph();

    let mut buf = Vec::new();
    JsonReportSink.emit(&mut buf, &graph, &findings).unwrap();
    let raw = std::str::from_utf8(&buf).expect("JSON output is utf-8");

    // The hostile Markdown payload appears as-is in the JSON message field.
    // (JSON string escaping turns `\x1b` into `` literally — that's the
    // four-character sequence ``, not the ESC byte. The byte 0x1B
    // itself MUST NOT appear; we'll verify the JSON-escaped form below.)
    assert!(
        raw.contains("[here](https://attacker.example/?steal=1)"),
        "JSON message must ship Markdown payload verbatim (machine-readable contract)"
    );

    // The ESC byte 0x1B is JSON-escaped to the six-char sequence ``
    // by serde_json — that's the JSON contract for control bytes inside
    // string literals. We assert the escaped form survives, which is
    // semantically equivalent to "raw byte preserved through encoding".
    assert!(
        raw.contains("\\u001b"),
        "JSON must preserve ESC bytes via the standard `\\u001b` JSON escape; got:\n{raw}"
    );

    // Parse round-trip: the decoded string must contain the literal ESC byte.
    let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    let msg0 = v["findings"][0]["message"].as_str().unwrap();
    assert!(
        msg0.bytes().any(|b| b == 0x1b),
        "round-tripped JSON message must contain raw ESC byte"
    );
}

/// SARIF sink escapes Markdown link / HTML delimiters in
/// `result.message.text` so the GitHub Code Scanning UI cannot render an
/// attacker's link as clickable.
#[test]
fn sarif_sink_escapes_markdown_link_payload() {
    let (graph, findings) = build_hostile_graph();
    let custom = hostile_custom_rules();

    let mut buf = Vec::new();
    SarifReportSink
        .emit_multi_with_custom_rules(&mut buf, &[(&graph, &findings[..])], &custom)
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&buf).expect("valid SARIF JSON");

    let results = v["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2, "expected two findings (custom + builtin)");

    for (i, r) in results.iter().enumerate() {
        let text = r["message"]["text"].as_str().unwrap();
        // The link wrapper MUST be de-fanged — every `[`, `]`, `(`, `)`
        // that appeared in a Markdown link context must be backslash-
        // escaped. We assert the raw `[here](` substring CANNOT appear,
        // because that's the Markdown link grammar.
        assert!(
            !text.contains("[here]("),
            "result[{i}].message.text contains unescaped Markdown link grammar `[here](`: {text:?}"
        );
        // Stronger: every `[` byte appearing in this text MUST be preceded
        // by `\` (the escape). Same for `(` `)` `]`.
        for (j, b) in text.as_bytes().iter().enumerate() {
            if matches!(*b, b'[' | b']' | b'(' | b')') {
                let is_escaped = j > 0 && text.as_bytes()[j - 1] == b'\\';
                assert!(
                    is_escaped,
                    "result[{i}].message.text[{j}] = {:?} not preceded by backslash escape: {text:?}",
                    *b as char
                );
            }
        }
    }

    // The custom-rule descriptor in the SARIF rules catalogue must also
    // have its `name` (and short/full description) Markdown-escaped.
    let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
    let custom_rule = rules
        .iter()
        .find(|r| r["id"] == "my_custom_rule")
        .expect("custom rule descriptor must appear in SARIF rules catalogue");
    let name = custom_rule["name"].as_str().unwrap();
    assert!(
        !name.contains("[click]("),
        "custom rule descriptor `name` contains unescaped Markdown link grammar: {name:?}"
    );
}

/// Terminal sink (colour off so we get a stable byte-comparable output)
/// MUST emit zero ANSI / control / steering bytes from attacker-controlled
/// fields. This is the headline blocker — without it, a hostile YAML can
/// impersonate a clean run.
#[test]
fn terminal_sink_strips_all_control_bytes_from_hostile_input() {
    let (graph, findings) = build_hostile_graph();

    // colored::control::set_override is a process-global flag. Pin it OFF
    // so any ESC bytes we observe in the output came from attacker input
    // (not from `colored`'s own colouring).
    colored::control::set_override(false);

    let reporter = TerminalReport { verbose: true };
    let mut buf: Vec<u8> = Vec::new();
    reporter.emit(&mut buf, &graph, &findings).unwrap();

    // The headline assertion: NO ESC byte (0x1B) anywhere in the output.
    // We assert by exact byte value, not regex — the regex itself could be
    // fooled by a sufficiently creative payload.
    assert!(
        buf.iter().all(|&b| b != 0x1B),
        "terminal output contains ESC byte (0x1B) from attacker-controlled input — \
         ANSI injection regression. First offending offset: {:?}",
        buf.iter().position(|&b| b == 0x1B)
    );

    // BEL (0x07) — audio noise, also commonly used to terminate ANSI OSC
    // sequences.
    assert!(
        buf.iter().all(|&b| b != 0x07),
        "terminal output contains BEL byte (0x07) — control-char regression"
    );

    // Every byte 0x00..=0x1F EXCEPT \n (0x0A) and \t (0x09) must be absent.
    for b in &buf {
        let cp = *b;
        if cp < 0x20 && cp != 0x0A && cp != 0x09 {
            panic!(
                "terminal output contains forbidden C0 control byte 0x{cp:02x}; \
                 only \\n and \\t are allowed in render-boundary output"
            );
        }
        // DEL (0x7F).
        if cp == 0x7F {
            panic!("terminal output contains DEL byte (0x7F)");
        }
    }

    // Unicode steering codepoints — encoded as multi-byte UTF-8 sequences.
    // We assert by parsing the buffer as UTF-8 and inspecting chars.
    let s = std::str::from_utf8(&buf).expect("terminal output is valid utf-8");
    for c in s.chars() {
        match c {
            '\u{202E}' => panic!("terminal output contains RTL OVERRIDE (U+202E)"),
            '\u{202D}' => panic!("terminal output contains LTR OVERRIDE (U+202D)"),
            '\u{200D}' => panic!("terminal output contains ZERO WIDTH JOINER (U+200D)"),
            '\u{200C}' => panic!("terminal output contains ZERO WIDTH NON-JOINER (U+200C)"),
            '\u{200B}' => panic!("terminal output contains ZERO WIDTH SPACE (U+200B)"),
            '\u{FEFF}' => panic!("terminal output contains BOM / ZWNBSP (U+FEFF)"),
            _ => {}
        }
        // C1 control range (U+0080..=U+009F) — rarely seen in legitimate
        // prose; some terminals interpret them as control sequences.
        let cp = c as u32;
        if (0x80..=0x9F).contains(&cp) {
            panic!("terminal output contains C1 control codepoint U+{cp:04X}");
        }
    }
}

/// Cross-sink fingerprint parity under hostile input. Sanitisation MUST
/// NOT shift fingerprints — `compute_fingerprint` operates on the RAW
/// pre-sanitisation finding fields, so JSON / SARIF / CloudEvents (any
/// sink that emits a fingerprint) all agree on the same 32-hex value
/// regardless of whether downstream rendering sanitises or not.
#[test]
fn fingerprint_unchanged_by_sanitisation() {
    use taudit_sink_cloudevents::CloudEventsJsonlSink;

    let (graph, findings) = build_hostile_graph();
    let custom = hostile_custom_rules();

    // JSON pairs.
    let mut json_buf = Vec::new();
    JsonReportSink
        .emit(&mut json_buf, &graph, &findings)
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&json_buf).unwrap();
    let json_fps: Vec<&str> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["fingerprint"].as_str().unwrap())
        .collect();

    // SARIF pairs.
    let mut sarif_buf = Vec::new();
    SarifReportSink
        .emit_multi_with_custom_rules(&mut sarif_buf, &[(&graph, &findings[..])], &custom)
        .unwrap();
    let sarif: serde_json::Value = serde_json::from_slice(&sarif_buf).unwrap();
    let sarif_fps: Vec<&str> = sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            r["partialFingerprints"]["primaryLocationLineHash"]
                .as_str()
                .unwrap()
        })
        .collect();

    // CloudEvents pairs.
    let mut ce_buf = Vec::new();
    let sink = CloudEventsJsonlSink::with_correlation_id(Some("hostile-corpus".into()));
    sink.emit(&mut ce_buf, &graph, &findings).unwrap();
    let ce_fps: Vec<String> = std::str::from_utf8(&ce_buf)
        .unwrap()
        .lines()
        .map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            v["tauditfindingfingerprint"].as_str().unwrap().to_string()
        })
        .collect();

    assert_eq!(json_fps.len(), 2);
    assert_eq!(sarif_fps.len(), 2);
    assert_eq!(ce_fps.len(), 2);

    for i in 0..2 {
        assert_eq!(
            json_fps[i], sarif_fps[i],
            "finding[{i}] fingerprint diverges between JSON ({}) and SARIF ({}) — \
             sanitisation must NOT shift fingerprint inputs",
            json_fps[i], sarif_fps[i]
        );
        assert_eq!(
            sarif_fps[i],
            ce_fps[i].as_str(),
            "finding[{i}] fingerprint diverges between SARIF ({}) and CloudEvents ({}) — \
             sanitisation must NOT shift fingerprint inputs",
            sarif_fps[i],
            ce_fps[i]
        );
    }
}
