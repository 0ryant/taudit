//! `axiom.audit.v1` BLAKE3-chained audit trail + `axiom.receipt.v1` receipt
//! emission for taudit (pattern 07 + pattern 09, ADR-0003 BLAKE3).
//!
//! taudit's pre-existing evidence stream is a CloudEvents JSONL log and a thin
//! `taudit.scan.receipt` JSON blob (see the CLI `write_runtime_artifacts`) —
//! useful for telemetry, but **not** tamper-evident: rows are independent so a
//! deletion or in-place edit leaves no trace, and the receipt is unsigned. This
//! module adds the doctrine substrate the cohort shares:
//!
//! * an append-only, hash-chained `audit-trail.jsonl` at the repo root
//!   (`seq` / `prev_hash` / `row_hash = BLAKE3(JCS(row))` / genesis), via the
//!   shared [`axiom_audit`] crate, and
//! * a signed `axiom.receipt.v1` receipt carrying BLAKE3 digests of the
//!   artifacts an operation touched plus an `audit_chain` linkage back to the
//!   trail tip, via the shared [`axiom_receipt`] mechanism.
//!
//! The receipt is signed in-process with a **pinned dev Ed25519 seed** (the
//! same RFC-8032 test-vector seed the reference tools — tflip / mcpact — use).
//! It is not a secret: a verifier checks the signature against the pinned public
//! key embedded as [`PINNED_KEY_ID`]. Custody is intentionally simple — taudit
//! does not hold a production key, so a verifier treats the signature as proof
//! the receipt was produced by a taudit build, not as an organizational
//! attestation. The signed bytes are byte-identical to the reference tools by
//! construction (shared [`axiom_canonical`] JCS + [`axiom_receipt`] signer).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use axiom_audit::AuditEntry;
use axiom_receipt::{Ed25519Signer, Jcs};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use axiom_audit::{ChainVerdict, ReceiptLink, AUDIT_SCHEMA, GENESIS_HASH, TRAIL_FILENAME};
pub use axiom_exit::Exit;

/// Receipt schema tag. Verifiers reject anything else.
pub const RECEIPT_SCHEMA: &str = "axiom.receipt.v1";

/// Canonical tool name embedded in every audit row and receipt.
pub const TOOL_NAME: &str = "taudit";

/// taudit version stamped into rows/receipts.
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Identifier of the pinned in-process signing key.
pub const PINNED_KEY_ID: &str = "taudit-pinned-ed25519-v1";

/// RFC-8032 ed25519 test-vector seed. NOT a secret — pinned and public on
/// purpose so any verifier can reconstruct the public key. The same seed the
/// reference tools (tflip / mcpact / axiom-receipt) use.
const PINNED_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// Errors from the audit-trail / receipt path.
#[derive(Debug, Error)]
pub enum ConformanceError {
    /// Underlying audit-chain error (IO, parse, canonicalization).
    #[error("audit-trail error: {0}")]
    Audit(#[from] axiom_audit::AuditError),

    /// Receipt signing / canonicalization error.
    #[error("receipt error: {0}")]
    Receipt(#[from] axiom_receipt::ReceiptError),

    /// Content hashing of an input/output artifact failed.
    #[error("hash error: {0}")]
    Hash(#[from] axiom_hash::HashError),

    /// Receipt JSON (de)serialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, ConformanceError>;

/// The pinned in-process signer.
#[must_use]
fn signer() -> Ed25519Signer {
    Ed25519Signer::from_seed(PINNED_SEED, PINNED_KEY_ID)
}

/// A cross-process advisory lock guarding read-then-append on a single
/// `audit-trail.jsonl`.
///
/// [`axiom_audit::append`] is read-tip-then-append and is **not** atomic across
/// processes: two `taudit scan`/`verify` invocations targeting the same repo
/// root can each read the same tip and then interleave their writes,
/// concatenating two rows onto one physical line — a malformed-JSONL corruption
/// that no later read can parse. Serializing the whole tip-read → receipt-write
/// → row-append critical section behind this lock makes concurrent emission safe
/// without a new dependency.
///
/// The lock is a sibling `audit-trail.jsonl.lock` file created with `create_new`
/// (the portable atomic test-and-set on Windows and Unix). The guard removes it
/// on drop; a bounded spin-retry tolerates a crashed holder by breaking a
/// sufficiently stale lock.
#[derive(Debug)]
pub struct TrailLock {
    path: PathBuf,
}

impl TrailLock {
    /// Acquire the lock guarding `<repo>/audit-trail.jsonl`. Blocks (bounded
    /// spin) until the lock is free or a stale lock is reclaimed.
    ///
    /// # Errors
    /// [`ConformanceError::Audit`] wrapping an IO error if the lock directory
    /// cannot be created or the lock cannot be taken within the deadline.
    pub fn acquire(repo: &Path) -> Result<Self> {
        if let Err(e) = std::fs::create_dir_all(repo) {
            return Err(audit_io(e));
        }
        let path = repo.join(format!("{TRAIL_FILENAME}.lock"));
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Ok(Self { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    Self::reclaim_if_stale(&path);
                    if Instant::now() >= deadline {
                        return Err(audit_io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("audit-trail lock {} held too long", path.display()),
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => return Err(audit_io(e)),
            }
        }
    }

    /// Reclaim a lock whose holder appears to have crashed (file older than the
    /// max critical-section budget). Best-effort: a benign race where another
    /// process removes it first is ignored.
    fn reclaim_if_stale(path: &Path) {
        const STALE_AFTER: Duration = Duration::from_secs(30);
        if let Ok(meta) = std::fs::metadata(path) {
            if let Ok(modified) = meta.modified() {
                if modified.elapsed().map(|d| d > STALE_AFTER).unwrap_or(false) {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }
}

impl Drop for TrailLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Wrap a `std::io::Error` as an [`axiom_audit::AuditError`] so lock failures
/// surface through the same [`ConformanceError::Audit`] channel.
fn audit_io(e: std::io::Error) -> ConformanceError {
    ConformanceError::Audit(axiom_audit::AuditError::Io(e))
}

/// The pinned public key (lowercase hex) a verifier checks receipt signatures
/// against.
#[must_use]
pub fn pinned_public_key_hex() -> String {
    hex::encode(signer().verifying_key_bytes())
}

/// Append one `axiom.audit.v1` row to `<repo>/audit-trail.jsonl`, computing
/// `seq` / `prev_hash` / `row_hash` from the trail tip. Returns the appended
/// row.
///
/// `outcome` is the pattern-07/09 vocabulary (`"ok" | "failed" | "degraded"`);
/// `exit_code` is the pattern-11 process code for the operation. When a receipt
/// was written, pass its repo-relative path and BLAKE3 so the row links it.
///
/// # Errors
/// [`ConformanceError::Audit`] on a read/write/canonicalization failure.
pub fn append_audit(
    repo: &Path,
    operation: &str,
    outcome: &str,
    exit_code: i32,
    timestamp: &str,
    receipt: ReceiptLink,
) -> Result<axiom_audit::AuditRow> {
    let trail = repo.join(TRAIL_FILENAME);
    let row = axiom_audit::append(
        &trail,
        &AuditEntry {
            tool: TOOL_NAME.to_string(),
            tool_version: TOOL_VERSION.to_string(),
            operation: operation.to_string(),
            timestamp: timestamp.to_string(),
            outcome: outcome.to_string(),
            exit_code,
            receipt,
        },
    )?;
    Ok(row)
}

/// Verify the `<repo>/audit-trail.jsonl` chain end to end (pattern 09): schema,
/// monotonic `seq`, genesis-anchored links, and that every `row_hash`
/// recomputes. Fail-closed: returns a typed [`ChainVerdict`], never panics.
///
/// # Errors
/// [`ConformanceError::Audit`] if the trail cannot be read or a row cannot be
/// re-hashed.
pub fn verify_trail(repo: &Path) -> Result<ChainVerdict> {
    Ok(axiom_audit::verify_chain(&repo.join(TRAIL_FILENAME))?)
}

/// A content-addressed artifact: a kind, a path, and its BLAKE3 digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// `"file" | "dir" | "pipeline" | "baseline" | "lockfile" | "report" | ...`.
    pub kind: String,
    /// Path (repo-relative where applicable).
    pub path: String,
    /// Lowercase-hex BLAKE3 of the artifact's content.
    pub blake3: String,
}

impl Artifact {
    /// Content-address a file on disk (BLAKE3).
    ///
    /// # Errors
    /// [`ConformanceError::Hash`] if the file cannot be read.
    pub fn of_file(kind: &str, path: &str, on_disk: &Path) -> Result<Self> {
        Ok(Self {
            kind: kind.to_string(),
            path: path.to_string(),
            blake3: axiom_hash::blake3_file(on_disk)?,
        })
    }

    /// Content-address in-memory bytes (BLAKE3).
    #[must_use]
    pub fn of_bytes(kind: &str, path: &str, bytes: &[u8]) -> Self {
        Self {
            kind: kind.to_string(),
            path: path.to_string(),
            blake3: axiom_hash::blake3_hex(bytes),
        }
    }
}

/// `audit_chain` linkage embedded in a receipt (pattern 07).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLink {
    /// Repo-relative path to the trail file (`audit-trail.jsonl`).
    pub trail_path: String,
    /// `seq` of the row this operation appended.
    pub seq: u64,
    /// `row_hash` of that row (the trail tip after this operation).
    pub row_hash: String,
}

/// The canonical, signed body of an `axiom.receipt.v1` receipt for taudit.
///
/// The signature is computed over the RFC-8785 (JCS) canonical bytes of exactly
/// this struct, so any verifier recomputes identical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptBody {
    /// Schema tag, always [`RECEIPT_SCHEMA`].
    pub schema: String,
    /// Canonical tool name, always [`TOOL_NAME`].
    pub tool: String,
    /// Tool semver.
    pub tool_version: String,
    /// Operation that produced the receipt (e.g. `"scan"`, `"verify"`,
    /// `"remediate"`).
    pub operation: String,
    /// Pattern-07 outcome vocabulary: `"ok" | "failed" | "degraded"`.
    pub outcome: String,
    /// Process exit code for the operation (pattern 11).
    pub exit_code: i32,
    /// Inputs operated on, each content-addressed with BLAKE3.
    pub inputs: Vec<Artifact>,
    /// Outputs produced, each content-addressed with BLAKE3.
    pub outputs: Vec<Artifact>,
    /// Audit-chain linkage to the appended trail row.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub audit_chain: Option<AuditLink>,
    /// Doctrine citations grounding taudit's claims (free-form anchors).
    pub doctrine_citations: Vec<String>,
    /// RFC-3339 creation timestamp.
    pub created_at: String,
    /// Identifier of the pinned key the signature is under.
    pub key_id: String,
}

impl ReceiptBody {
    /// Build a body with the fixed identity fields filled in.
    #[must_use]
    pub fn new(operation: &str, outcome: &str, exit_code: i32, created_at: &str) -> Self {
        Self {
            schema: RECEIPT_SCHEMA.to_string(),
            tool: TOOL_NAME.to_string(),
            tool_version: TOOL_VERSION.to_string(),
            operation: operation.to_string(),
            outcome: outcome.to_string(),
            exit_code,
            inputs: Vec::new(),
            outputs: Vec::new(),
            audit_chain: None,
            doctrine_citations: default_citations(),
            created_at: created_at.to_string(),
            key_id: PINNED_KEY_ID.to_string(),
        }
    }
}

/// Default doctrine citations for a taudit receipt.
#[must_use]
fn default_citations() -> Vec<String> {
    vec![
        "ecosystem-catalog/standardisation/CONFORMANCE.md#taudit".to_string(),
        "ecosystem-catalog pattern-07 (receipt-emission)".to_string(),
        "ecosystem-catalog pattern-09 (audit-chain)".to_string(),
        "ecosystem-catalog pattern-11 (exit-code state machine)".to_string(),
        "ecosystem-catalog ADR-0003 / engineering-doctrine ADR-0022 (BLAKE3)".to_string(),
    ]
}

/// A complete, signed receipt: the canonical body plus its detached hex
/// signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// The signed body.
    pub body: ReceiptBody,
    /// Lowercase-hex Ed25519 signature over `JCS(body)`.
    pub signature: String,
}

impl Receipt {
    /// Sign `body` under the pinned key, producing a complete receipt.
    ///
    /// # Errors
    /// [`ConformanceError::Receipt`] if the body cannot be canonicalized/signed.
    pub fn sign(body: ReceiptBody) -> Result<Self> {
        let (sig, _key_id) = axiom_receipt::sign_bytes(&Jcs(&body), &signer())?;
        Ok(Self {
            body,
            signature: hex::encode(sig),
        })
    }

    /// Serialise to pretty JSON suitable for writing to disk.
    ///
    /// # Errors
    /// [`ConformanceError::Json`] on a serialization failure.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse a receipt from JSON.
    ///
    /// # Errors
    /// [`ConformanceError::Json`] on a parse failure.
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

/// Typed verdict from [`verify_receipt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptVerdict {
    /// Schema, key_id, and Ed25519 signature all hold.
    Valid,
    /// Verification failed; the string explains why.
    Invalid(String),
}

/// Offline-verify a receipt against the pinned public key:
/// 1. schema must be `axiom.receipt.v1`;
/// 2. `key_id` must match the pinned key;
/// 3. the Ed25519 signature must verify over the JCS canonical body.
///
/// Returns a typed [`ReceiptVerdict`]; never panics.
///
/// # Errors
/// [`ConformanceError::Receipt`] only if the verifier key material is malformed
/// (it is pinned, so this should not occur); verification failures are returned
/// as [`ReceiptVerdict::Invalid`], not errors.
pub fn verify_receipt(receipt: &Receipt) -> Result<ReceiptVerdict> {
    if receipt.body.schema != RECEIPT_SCHEMA {
        return Ok(ReceiptVerdict::Invalid(format!(
            "unsupported schema: {}",
            receipt.body.schema
        )));
    }
    if receipt.body.key_id != PINNED_KEY_ID {
        return Ok(ReceiptVerdict::Invalid(format!(
            "unknown key_id: {}",
            receipt.body.key_id
        )));
    }
    let sig = match decode_sig(&receipt.signature) {
        Ok(sig) => sig,
        Err(why) => return Ok(ReceiptVerdict::Invalid(why)),
    };
    let verifier = axiom_receipt::Ed25519Verifier::from_pubkey(signer().verifying_key_bytes())?;
    match axiom_receipt::verify_bytes(&Jcs(&receipt.body), &sig, &verifier) {
        Ok(()) => Ok(ReceiptVerdict::Valid),
        Err(e) => Ok(ReceiptVerdict::Invalid(e.to_string())),
    }
}

/// Decode a 128-char lowercase-hex string into a 64-byte signature.
fn decode_sig(s: &str) -> std::result::Result<[u8; 64], String> {
    let raw = hex::decode(s).map_err(|e| format!("signature not hex: {e}"))?;
    raw.try_into()
        .map_err(|v: Vec<u8>| format!("signature must be 64 bytes, got {}", v.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn append_chains_and_verifies() {
        let dir = tempdir().unwrap();
        let r0 = append_audit(
            dir.path(),
            "scan",
            "ok",
            0,
            "2026-06-16T00:00:00Z",
            ReceiptLink::None,
        )
        .unwrap();
        let r1 = append_audit(
            dir.path(),
            "verify",
            "ok",
            0,
            "2026-06-16T00:00:01Z",
            ReceiptLink::Present {
                path: "receipts/v.json".to_string(),
                blake3: axiom_hash::blake3_hex(b"v"),
            },
        )
        .unwrap();
        assert_eq!(r0.seq, 0);
        assert_eq!(r0.prev_hash, GENESIS_HASH);
        assert_eq!(r1.seq, 1);
        assert_eq!(r1.prev_hash, r0.row_hash);

        match verify_trail(dir.path()).unwrap() {
            ChainVerdict::Valid { rows, head_hash } => {
                assert_eq!(rows, 2);
                assert_eq!(head_hash, r1.row_hash);
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn empty_trail_is_valid() {
        let dir = tempdir().unwrap();
        assert_eq!(
            verify_trail(dir.path()).unwrap(),
            ChainVerdict::Valid {
                rows: 0,
                head_hash: String::new()
            }
        );
    }

    #[test]
    fn tampered_row_breaks_chain() {
        let dir = tempdir().unwrap();
        append_audit(
            dir.path(),
            "scan",
            "ok",
            0,
            "2026-06-16T00:00:00Z",
            ReceiptLink::None,
        )
        .unwrap();
        let trail = dir.path().join(TRAIL_FILENAME);
        let mut rows = axiom_audit::read_rows(&trail).unwrap();
        rows[0].exit_code = 99; // body changes but row_hash is now stale.
        let line = serde_json::to_string(&rows[0]).unwrap();
        std::fs::write(&trail, format!("{line}\n")).unwrap();
        assert!(matches!(
            verify_trail(dir.path()).unwrap(),
            ChainVerdict::Broken(_)
        ));
    }

    #[test]
    fn receipt_signs_and_verifies() {
        let mut body = ReceiptBody::new("scan", "ok", 0, "2026-06-16T00:00:00Z");
        body.inputs
            .push(Artifact::of_bytes("pipeline", ".github/workflows/ci.yml", b"on: push"));
        body.audit_chain = Some(AuditLink {
            trail_path: TRAIL_FILENAME.to_string(),
            seq: 0,
            row_hash: axiom_hash::blake3_hex(b"row"),
        });
        let receipt = Receipt::sign(body.clone()).unwrap();
        assert_eq!(receipt.signature.len(), 128);
        assert_eq!(verify_receipt(&receipt).unwrap(), ReceiptVerdict::Valid);

        // A round-trip through JSON still verifies.
        let json = receipt.to_json().unwrap();
        let parsed = Receipt::from_json(&json).unwrap();
        assert_eq!(verify_receipt(&parsed).unwrap(), ReceiptVerdict::Valid);
    }

    #[test]
    fn tampered_receipt_body_fails() {
        let body = ReceiptBody::new("scan", "ok", 0, "2026-06-16T00:00:00Z");
        let mut receipt = Receipt::sign(body).unwrap();
        receipt.body.outcome = "failed".to_string(); // mutate after signing
        assert!(matches!(
            verify_receipt(&receipt).unwrap(),
            ReceiptVerdict::Invalid(_)
        ));
    }

    #[test]
    fn wrong_schema_is_rejected() {
        let mut body = ReceiptBody::new("scan", "ok", 0, "2026-06-16T00:00:00Z");
        body.schema = "axiom.receipt.v0".to_string();
        let receipt = Receipt::sign(body).unwrap();
        assert!(matches!(
            verify_receipt(&receipt).unwrap(),
            ReceiptVerdict::Invalid(_)
        ));
    }

    #[test]
    fn concurrent_locked_appends_never_corrupt_the_trail() {
        let dir = tempdir().unwrap();
        let repo = dir.path().to_path_buf();
        const THREADS: usize = 8;
        let mut handles = Vec::new();
        for t in 0..THREADS {
            let repo = repo.clone();
            handles.push(std::thread::spawn(move || {
                let _lock = TrailLock::acquire(&repo).unwrap();
                append_audit(
                    &repo,
                    "scan",
                    "ok",
                    0,
                    "2026-06-16T00:00:00Z",
                    ReceiptLink::Present {
                        path: format!("receipts/{t}.json"),
                        blake3: axiom_hash::blake3_hex(format!("row-{t}").as_bytes()),
                    },
                )
                .unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let trail = repo.join(TRAIL_FILENAME);
        let rows = axiom_audit::read_rows(&trail).unwrap();
        assert_eq!(rows.len(), THREADS, "every locked append must be its own row");
        match verify_trail(&repo).unwrap() {
            ChainVerdict::Valid { rows: n, .. } => assert_eq!(n, THREADS),
            other => panic!("expected Valid chain, got {other:?}"),
        }
        let text = std::fs::read_to_string(&trail).unwrap();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            assert_eq!(
                line.matches("\"schema\"").count(),
                1,
                "a line concatenated two rows: {line}"
            );
        }
    }

    #[test]
    fn pinned_public_key_is_rfc8032_vector() {
        assert_eq!(
            pinned_public_key_hex(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
    }

    #[test]
    fn exit_codes_are_pinned() {
        assert_eq!(Exit::Ok.as_i32(), 0);
        assert_eq!(Exit::AssertionFailed.as_i32(), 1);
        assert_eq!(Exit::Usage.as_i32(), 2);
        assert_eq!(Exit::Preflight.as_i32(), 3);
        assert_eq!(Exit::Degraded.as_i32(), 4);
    }
}
