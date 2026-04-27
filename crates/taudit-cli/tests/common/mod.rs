#![allow(dead_code)]
// Shared by multiple `tests/*.rs` binaries; not every binary uses every helper.

use std::path::PathBuf;

use taudit_core::finding::Finding;

/// Repository workspace root (parent of `crates/`, `tests/`).
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root from CARGO_MANIFEST_DIR")
}

pub fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

pub fn sorted_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        let ka = (
            format!("{:?}", a.category),
            a.message.clone(),
            a.nodes_involved.clone(),
        );
        let kb = (
            format!("{:?}", b.category),
            b.message.clone(),
            b.nodes_involved.clone(),
        );
        ka.cmp(&kb)
    });
    findings
}
