//! Criterion benches for the GitHub Actions parser.
//!
//! Inputs:
//!   - The three real fixtures under `<workspace>/tests/fixtures/*.yml`.
//!   - One synthetic 1000-job workflow generated at startup.
#![allow(clippy::all)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::path::PathBuf;
use taudit_core::graph::PipelineSource;
use taudit_core::ports::PipelineParser;
use taudit_parse_gha::GhaParser;

/// Workspace-relative fixture paths. Cargo runs benches with CWD set to the
/// crate dir, so we walk up to the workspace root once.
fn workspace_fixtures_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/taudit-parse-gha -> crates
    p.pop(); // crates -> workspace root
    p.push("tests");
    p.push("fixtures");
    p
}

/// Build a synthetic GHA workflow string with `n_jobs` jobs, each with
/// 4 steps (checkout + 3 build/test/deploy). Used to measure parser scaling
/// well past anything you'd see in a real repo.
fn synthetic_workflow(n_jobs: usize) -> String {
    let mut out = String::new();
    out.push_str("name: SyntheticBench\non: push\n\npermissions:\n  contents: read\n\njobs:\n");
    for i in 0..n_jobs {
        out.push_str(&format!(
            "  job_{i}:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29\n      - name: Build {i}\n        run: cargo build\n        env:\n          TOKEN_{i}: \"${{{{ secrets.TOKEN_{i} }}}}\"\n      - name: Test {i}\n        run: cargo test\n      - name: Deploy {i}\n        run: ./deploy.sh\n        env:\n          DEPLOY_KEY_{i}: \"${{{{ secrets.DEPLOY_KEY_{i} }}}}\"\n"
        ));
    }
    out
}

fn bench_parse(c: &mut Criterion) {
    let parser = GhaParser;
    let fixtures_dir = workspace_fixtures_dir();

    let mut group = c.benchmark_group("gha_parse");

    // Real fixtures
    for name in &["clean.yml", "over-privileged.yml", "propagation-leaky.yml"] {
        let path = fixtures_dir.join(name);
        let content = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => panic!("failed to read fixture {}: {e}", path.display()),
        };
        let source = PipelineSource {
            file: name.to_string(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        };
        group.throughput(Throughput::Bytes(content.len() as u64));
        group.bench_with_input(BenchmarkId::new("fixture", name), &content, |b, c| {
            b.iter(|| parser.parse(c, &source).expect("fixture must parse"));
        });
    }

    // Synthetic large input
    let synthetic = synthetic_workflow(1000);
    let synthetic_source = PipelineSource {
        file: "synthetic-1000-jobs.yml".to_string(),
        repo: None,
        git_ref: None,
        commit_sha: None,
    };
    group.throughput(Throughput::Bytes(synthetic.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("synthetic_jobs", 1000),
        &synthetic,
        |b, c| {
            b.iter(|| {
                parser
                    .parse(c, &synthetic_source)
                    .expect("synthetic must parse")
            });
        },
    );

    group.finish();
}

criterion_group!(benches, bench_parse);
criterion_main!(benches);
