use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceApplyPatchMode {
    JsonPatch,
    FullReplace,
    LinePatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "op", deny_unknown_fields)]
pub enum JsonPatchOp {
    Insert { at: u64, text: String },
    Delete { start: u64, end: u64 },
    Replace { start: u64, end: u64, text: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "op", deny_unknown_fields)]
pub enum LinePatchOp {
    InsertLines {
        at_line: u64,
        lines: Vec<String>,
    },
    DeleteLines {
        start_line: u64,
        end_line_exclusive: u64,
    },
    ReplaceLines {
        start_line: u64,
        end_line_exclusive: u64,
        lines: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspacePatchAction {
    Applied,
    Noop,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct WorkspaceApplyPatchRequest {
    pub schema: String,
    pub target_path: String,
    pub mode: WorkspaceApplyPatchMode,
    #[serde(default)]
    pub allow_create: bool,
    #[serde(default)]
    pub allow_create_parents: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precondition_sha256_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<Vec<JsonPatchOp>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_patch: Option<Vec<LinePatchOp>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct WorkspaceApplyPatchResult {
    pub schema: String,
    pub target_path: String,
    pub action: WorkspacePatchAction,
    pub created: bool,
    pub before_sha256_hex: String,
    pub after_sha256_hex: String,
    pub bytes_written: u64,
    pub applied_patch_sha256_hex: String,
    pub precondition_checked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct WorkspacePatchReceipt {
    pub schema: String,
    pub request_ref: String,
    pub result_ref: String,
    pub request_hash_hex: String,
    pub target_path: String,
    pub before_sha256_hex: String,
    pub after_sha256_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ApprovalArtifact {
    pub schema: String,
    pub approved: bool,
    pub scope: ApprovalScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ApprovalScope {
    pub kind: String,
    pub tool_id: String,
    pub request_hash_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ApprovalHashRequest {
    pub schema: String,
    pub target_path: String,
    pub mode: WorkspaceApplyPatchMode,
    pub allow_create: bool,
    pub allow_create_parents: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precondition_sha256_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<Vec<JsonPatchOp>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_patch: Option<Vec<LinePatchOp>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}
