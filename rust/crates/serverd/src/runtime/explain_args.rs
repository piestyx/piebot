use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum ExplainTarget {
    CapsuleRef(String),
    RunId(String),
}

#[derive(Debug, Clone)]
pub struct ExplainArgs {
    pub runtime_root: PathBuf,
    pub target: ExplainTarget,
}
