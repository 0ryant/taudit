//! Generated server configuration.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub static RESOLVED_BINARY: OnceLock<PathBuf> = OnceLock::new();

const SOURCE_MANIFEST: &str = include_str!(concat!("../.mcpact/source.mcpact.toml"));

fn lock_source_manifest_sha256(lock: &str) -> Option<String> {
    lock.lines().find_map(|line| {
        line.strip_prefix("source_manifest_sha256 = \"")
            .and_then(|rest| rest.strip_suffix('"'))
            .map(str::to_string)
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Verify signed/verified trust and lockfile before serving.
pub fn verify_pack_integrity() -> Result<(), String> {
    let manifest: mcpact_manifest::Manifest = toml::from_str(SOURCE_MANIFEST)
        .map_err(|err| format!("embedded manifest parse failed: {err}"))?;
    use mcpact_core::TrustCeiling;
    if matches!(
        manifest.package.trust,
        TrustCeiling::Signed | TrustCeiling::Verified
    ) {
        mcpact_manifest::verify_package_signature(&manifest)
            .map_err(|err| format!("serve-time signature verification failed: {err}"))?;
    }
    let embedded_lock = include_str!(concat!("../.mcpact/mcpact.lock"));
    if !embedded_lock.contains("schema_version = \"mcpact.lock.v1\"") {
        return Err("invalid embedded lockfile".into());
    }
    let on_disk = std::fs::read_to_string(".mcpact/mcpact.lock")
        .map_err(|err| format!("lockfile unreadable: {err}"))?;
    if embedded_lock != on_disk {
        return Err("embedded lockfile does not match on-disk copy (tree tampered)".into());
    }
    if let Some(expected) = lock_source_manifest_sha256(embedded_lock) {
        let actual = sha256_hex(SOURCE_MANIFEST.as_bytes());
        if actual != expected {
            return Err("embedded manifest hash does not match lockfile".into());
        }
    }
    Ok(())
}

/// Resolve and cache the CLI binary path.
pub fn init(binary_name: &str) -> Result<(), String> {
    verify_pack_integrity()?;
    let resolved = mcpact_runtime::resolve_binary(binary_name).map_err(|err| err.to_string())?;
    RESOLVED_BINARY
        .set(resolved)
        .map_err(|_| "server binary already initialized".to_string())
}

/// Resolved binary path for execution plans.
pub fn binary_path() -> &'static Path {
    RESOLVED_BINARY.get().expect("server binary was not resolved at startup")
}

/// Manifest trust ceiling.
pub const TRUST: mcpact_core::TrustCeiling = mcpact_core::TrustCeiling::Reviewed;

/// Manifest `[audit].sink` (ADR-0027).
pub const AUDIT_SINK: &str = "jsonl";

/// Manifest `[audit].url` when set.
pub const AUDIT_CLOUDEVENTS_URL: Option<&str> = None;

/// Resolved JSONL audit path from manifest (supports `audit.xdg_state`).
pub fn audit_jsonl_path() -> PathBuf {
    let manifest: mcpact_manifest::Manifest = toml::from_str(SOURCE_MANIFEST)
        .expect("embedded manifest must parse");
    mcpact_manifest::resolve_audit_jsonl_path(&manifest.audit, &manifest.package.name)
}

/// Runtime audit sinks from manifest settings.
pub fn audit_sink() -> mcpact_audit::MultiAuditSink {
    mcpact_audit::MultiAuditSink::from_manifest_settings(
        AUDIT_SINK,
        audit_jsonl_path(),
        AUDIT_CLOUDEVENTS_URL,
    )
}
