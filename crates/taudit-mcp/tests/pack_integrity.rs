//! Recurrence guard for the mcpact pack integrity gate.
//!
//! taudit-mcp embeds `.mcpact/source.mcpact.toml` via `include_str!` and, at
//! serve time, recomputes its digest and compares it against
//! `source_manifest_*` in the embedded `.mcpact/mcpact.lock`
//! (see `src/server_config.rs::verify_pack_integrity`). If the two diverge the
//! MCP server refuses to start with "embedded manifest hash does not match
//! lockfile" and `tools/list` is never reachable.
//!
//! Two ways that gate can break:
//!   1. `source.mcpact.toml` is edited without re-locking the pack.
//!   2. A checkout reintroduces CRLF line endings, changing the embedded bytes
//!      (the 2026-06 Windows/autocrlf failure). `.gitattributes` pins the pack
//!      to `eol=lf` to prevent this.
//!
//! This test recomputes the digest exactly as the serve-time gate does and is
//! run by `cargo test --workspace` on Ubuntu, macOS, and Windows in CI, so the
//! drift is caught on every platform before a release binary can ship broken.

use sha2::{Digest, Sha256};

/// The embedded manifest — same bytes the binary bakes in via `include_str!`.
const SOURCE_MANIFEST: &str = include_str!("../.mcpact/source.mcpact.toml");
/// The embedded lockfile.
const LOCK: &str = include_str!("../.mcpact/mcpact.lock");

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Mirror of `server_config::lock_source_manifest_digest`: pull the recorded
/// source-manifest digest out of the lockfile, preferring the BLAKE3
/// (`mcpact.lock.v2`) field over the SHA-256 (`mcpact.lock.v1`) field.
enum RecordedDigest {
    Sha256(String),
    Blake3(String),
}

fn recorded_source_manifest_digest(lock: &str) -> Option<RecordedDigest> {
    lock.lines().find_map(|line| {
        if let Some(rest) = line.strip_prefix("source_manifest_blake3 = \"") {
            rest.strip_suffix('"')
                .map(|h| RecordedDigest::Blake3(h.to_string()))
        } else {
            line.strip_prefix("source_manifest_sha256 = \"")
                .and_then(|rest| rest.strip_suffix('"'))
                .map(|h| RecordedDigest::Sha256(h.to_string()))
        }
    })
}

#[test]
fn embedded_source_manifest_digest_matches_lockfile() {
    let recorded = recorded_source_manifest_digest(LOCK)
        .expect("mcpact.lock must record a source_manifest_sha256 or source_manifest_blake3");

    let (actual, expected, algo) = match recorded {
        RecordedDigest::Blake3(h) => (axiom_hash::blake3_hex(SOURCE_MANIFEST.as_bytes()), h, "blake3"),
        RecordedDigest::Sha256(h) => (sha256_hex(SOURCE_MANIFEST.as_bytes()), h, "sha256"),
    };

    assert_eq!(
        actual, expected,
        "embedded source.mcpact.toml {algo} digest drifted from mcpact.lock.\n\
         The taudit-mcp serve-time gate will reject this pack and the MCP server \
         will fail to start.\n\
         Fix: re-lock the pack with mcpact, OR — if the manifest content is \
         unchanged — your checkout has CRLF line endings; ensure .gitattributes \
         pins the pack to `eol=lf` and renormalize."
    );
}
