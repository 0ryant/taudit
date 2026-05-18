#![no_main]
use libfuzzer_sys::fuzz_target;
use taudit_core::graph::PipelineSource;
use taudit_core::ports::PipelineParser;
use taudit_parse_bitbucket::BitbucketParser;

fuzz_target!(|data: &[u8]| {
    if let Ok(yaml) = std::str::from_utf8(data) {
        let source = PipelineSource {
            file: "fuzz.yml".into(),
            repo: None,
            git_ref: None,
            commit_sha: None,
        };
        let _ = BitbucketParser.parse(yaml, &source);
    }
});
