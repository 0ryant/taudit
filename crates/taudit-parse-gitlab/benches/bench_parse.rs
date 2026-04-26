//! Criterion benches for the GitLab CI parser.
//!
//! No `tests/fixtures/*.yml` exists for this crate, so this bench uses three
//! inline GitLab samples plus one synthetic 1000-job pipeline.
#![allow(clippy::all)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use taudit_core::graph::PipelineSource;
use taudit_core::ports::PipelineParser;
use taudit_parse_gitlab::GitlabParser;

const GITLAB_SMALL: &str = r#"
stages:
  - build
  - test

variables:
  BUILD_ENV: "ci"

build:
  stage: build
  image: rust:1.75
  script:
    - cargo build
  variables:
    DEPLOY_TOKEN: "$DEPLOY_TOKEN"

test:
  stage: test
  script:
    - cargo test
"#;

const GITLAB_MR: &str = r#"
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

build:
  image: alpine:3.18
  script:
    - echo $CI_JOB_TOKEN
    - ./build.sh
  variables:
    API_KEY: "$API_KEY"
    AWS_ACCESS_KEY: "$AWS_ACCESS_KEY"

deploy:
  image: registry.example.com/deploy:latest
  script:
    - ./deploy.sh
  id_tokens:
    AWS_TOKEN:
      aud: sts.amazonaws.com
"#;

const GITLAB_INCLUDE: &str = r#"
include:
  - project: "ops/templates"
    file: "/ci/build.yml"
    ref: main

stages:
  - build
  - publish

publish:
  extends: .publish_template
  script:
    - ./publish.sh
  variables:
    REGISTRY_PASSWORD: "$REGISTRY_PASSWORD"
"#;

fn synthetic_pipeline(n_jobs: usize) -> String {
    let mut out = String::new();
    out.push_str("stages:\n  - build\n\nvariables:\n  GLOBAL: \"x\"\n\n");
    for i in 0..n_jobs {
        out.push_str(&format!(
            "job_{i}:\n  stage: build\n  image: rust:1.75\n  script:\n    - cargo build\n    - ./run_{i}.sh\n  variables:\n    TOKEN_{i}: \"$TOKEN_{i}\"\n    DEPLOY_KEY_{i}: \"$DEPLOY_KEY_{i}\"\n\n"
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
    let parser = GitlabParser;
    let mut group = c.benchmark_group("gitlab_parse");

    for (name, content) in &[
        ("small.yml", GITLAB_SMALL),
        ("mr_with_oidc.yml", GITLAB_MR),
        ("include_extends.yml", GITLAB_INCLUDE),
    ] {
        let src = source(name);
        group.throughput(Throughput::Bytes(content.len() as u64));
        group.bench_with_input(BenchmarkId::new("inline", name), content, |b, c| {
            b.iter(|| parser.parse(c, &src).expect("inline GitLab must parse"));
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
