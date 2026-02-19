use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PortPlanNodeKind {
    Inventory,
    ModuleMap,
    DataModel,
    IoBoundary,
    Serialization,
    Tests,
    BuildSystem,
    MigrationSlice,
}

impl PortPlanNodeKind {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Inventory => "inventory",
            Self::ModuleMap => "module_map",
            Self::DataModel => "data_model",
            Self::IoBoundary => "io_boundary",
            Self::Serialization => "serialization",
            Self::Tests => "tests",
            Self::BuildSystem => "build_system",
            Self::MigrationSlice => "migration_slice",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct PortPlanNode {
    pub id: String,
    pub kind: PortPlanNodeKind,
    pub targets: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub invariant_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct PortInvariant {
    pub id: String,
    pub statement: String,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct WorkUnit {
    pub id: String,
    pub node_id: String,
    pub target_path: String,
    pub acceptance_criteria: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct PortPlanArtifact {
    pub schema: String,
    pub repo_identity_root_hash: String,
    pub repo_index_snapshot_root_hash: String,
    pub plan_root_hash: String,
    pub nodes: Vec<PortPlanNode>,
    pub invariants: Vec<PortInvariant>,
    pub work_units: Vec<WorkUnit>,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct PortPlanSummaryArtifact {
    pub schema: String,
    pub repo_identity_root_hash: String,
    pub repo_index_snapshot_root_hash: String,
    pub plan_root_hash: String,
    pub node_count: u64,
    pub invariant_count: u64,
    pub work_unit_count: u64,
    pub node_kinds: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct PortPlanRequestArtifact {
    pub schema: String,
    pub intent: String,
    pub repo_identity_ref: String,
    pub repo_identity_root_hash: String,
    pub repo_index_snapshot_ref: String,
    pub repo_index_snapshot_root_hash: String,
    pub files: Vec<PortPlanRequestFileSummary>,
    pub chunks: Vec<PortPlanRequestChunkSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct PortPlanRequestFileSummary {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct PortPlanRequestChunkSummary {
    pub path: String,
    pub chunk_count: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct RepoIdentityArtifactLite {
    pub schema: String,
    pub files: Vec<RepoFileEntryLite>,
    pub root_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct RepoFileEntryLite {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct RepoIndexSnapshotArtifactLite {
    pub schema: String,
    pub repo_identity_root_hash: String,
    pub chunk_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_chunk_bytes: Option<u64>,
    pub chunks: Vec<RepoChunkLite>,
    pub root_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct RepoChunkLite {
    pub path: String,
    pub file_sha256: String,
    pub start: u64,
    pub len: u64,
    pub chunk_sha256: String,
    pub chunk_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct PortPlanProviderOutput {
    pub schema: String,
    pub candidate_nodes: Vec<PortPlanCandidateNode>,
    pub candidate_invariants: Vec<PortPlanCandidateInvariant>,
    pub candidate_work_units: Vec<PortPlanCandidateWorkUnit>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct PortPlanCandidateNode {
    pub kind: PortPlanNodeKind,
    pub target_paths: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<PortPlanCandidateNodeRef>,
    #[serde(default)]
    pub invariant_statements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct PortPlanCandidateNodeRef {
    pub kind: PortPlanNodeKind,
    pub target_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct PortPlanCandidateInvariant {
    pub statement: String,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct PortPlanCandidateWorkUnit {
    pub node: PortPlanCandidateNodeRef,
    pub target_path: String,
    #[serde(default)]
    pub acceptance_criteria: Vec<String>,
}
