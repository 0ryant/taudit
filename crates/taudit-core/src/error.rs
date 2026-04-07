/// Core error type — no I/O variants. Adapters wrap this in their own errors.
#[derive(Debug, thiserror::Error)]
pub enum TauditError {
    #[error("parse error: {0}")]
    Parse(String),

    #[error("invalid graph: {0}")]
    InvalidGraph(String),

    #[error("analysis error: {0}")]
    Analysis(String),

    #[error("report error: {0}")]
    Report(String),
}
