//! Criterion benches for the Azure DevOps pipeline parser.
//!
//! No `tests/fixtures/*.yml` exists for this crate (see workspace `tests/`
//! for shared GHA fixtures), so this bench uses three inline ADO YAML
//! samples plus one synthetic 1000-job pipeline.
#![allow(clippy::all)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use taudit_core::graph::PipelineSource;
use taudit_core::ports::PipelineParser;
use taudit_parse_ado::AdoParser;

const ADO_SMALL: &str = r#"
trigger:
  - main

pool:
  vmImage: ubuntu-latest

jobs:
  - job: Build
    steps:
      - script: echo build
        env:
          TOKEN: $(SECRET_TOKEN)
      - task: Bash@3
        inputs:
          targetType: inline
          script: echo done
"#;

const ADO_PR: &str = r#"
pr:
  - main

pool:
  vmImage: ubuntu-latest

variables:
  - group: prod-secrets

jobs:
  - job: Test
    steps:
      - script: echo $(BUILD_TOKEN)
      - task: AzureCLI@2
        inputs:
          azureSubscription: prod-conn
          scriptType: bash
          scriptLocation: inlineScript
          inlineScript: az account show
"#;

const ADO_TEMPLATE: &str = r#"
resources:
  repositories:
    - repository: shared
      type: github
      name: org/shared-templates
      ref: main

extends:
  template: pipelines/build.yml@shared

pool:
  vmImage: ubuntu-latest
"#;

fn synthetic_pipeline(n_jobs: usize) -> String {
    let mut out = String::new();
    out.push_str("trigger:\n  - main\n\npool:\n  vmImage: ubuntu-latest\n\njobs:\n");
    for i in 0..n_jobs {
        out.push_str(&format!(
            "  - job: Job_{i}\n    steps:\n      - script: echo build {i}\n        env:\n          TOKEN_{i}: $(SECRET_{i})\n      - task: Bash@3\n        inputs:\n          targetType: inline\n          script: ./run_{i}.sh\n      - script: ./deploy_{i}.sh\n        env:\n          KEY_{i}: $(DEPLOY_KEY_{i})\n"
        ));
    }
    out
}

fn source(name: &str) -> PipelineSource {
    PipelineSource {
        file: name.to_string(),
        repo: None,
        git_ref: None,
        commit_sha: None,
    }
}

fn bench_parse(c: &mut Criterion) {
    let parser = AdoParser;
    let mut group = c.benchmark_group("ado_parse");

    for (name, content) in &[
        ("small.yml", ADO_SMALL),
        ("pr_with_var_group.yml", ADO_PR),
        ("template_extends.yml", ADO_TEMPLATE),
    ] {
        let src = source(name);
        group.throughput(Throughput::Bytes(content.len() as u64));
        group.bench_with_input(BenchmarkId::new("inline", name), content, |b, c| {
            b.iter(|| parser.parse(c, &src).expect("inline ADO must parse"));
        });
    }

    let synthetic = synthetic_pipeline(1000);
    let synthetic_source = source("synthetic-1000-jobs.yml");
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
