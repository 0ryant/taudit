use crate::error::TauditError;
use crate::finding::Finding;
use crate::graph::{AuthorityGraph, PipelineSource};

/// Parser port: converts raw YAML into an authority graph.
/// One implementation per CI platform (GHA, ADO, GitLab).
pub trait PipelineParser: Send + Sync {
    fn platform(&self) -> &str;
    fn parse(&self, content: &str, source: &PipelineSource) -> Result<AuthorityGraph, TauditError>;
}

/// Report sink port: outputs findings in a specific format.
/// Generic over the writer so composition root injects the destination.
pub trait ReportSink<W: std::io::Write>: Send + Sync {
    fn emit(
        &self,
        writer: &mut W,
        graph: &AuthorityGraph,
        findings: &[Finding],
    ) -> Result<(), TauditError>;
}

/// Analysis rule port: a single finding pattern.
/// Built-in rules implement this; extensible for custom rules.
pub trait AnalysisRule: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, graph: &AuthorityGraph) -> Vec<Finding>;
}
