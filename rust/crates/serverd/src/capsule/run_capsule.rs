use crate::runtime::artifacts::artifact_filename;
use pie_common::{canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::Path;

pub const RUN_CAPSULE_SCHEMA: &str = "serverd.run_capsule.v1";

#[derive(Debug)]
pub struct RunCapsuleError {
    reason: &'static str,
    detail: Option<String>,
}

impl RunCapsuleError {
    pub fn new(reason: &'static str) -> Self {
        Self {
            reason,
            detail: None,
        }
    }

    pub fn with_detail(reason: &'static str, detail: String) -> Self {
        Self {
            reason,
            detail: Some(detail),
        }
    }

    pub fn reason(&self) -> &'static str {
        self.reason
    }

    #[allow(dead_code)]
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl std::fmt::Display for RunCapsuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for RunCapsuleError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RunCapsule {
    pub schema: String,
    pub run: RunCapsuleRun,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skill: Option<RunCapsuleSkill>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub router: Option<RunCapsuleRouter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<RunCapsuleTools>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<RunCapsuleContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub providers: Option<Vec<RunCapsuleProvider>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_io: Option<Vec<RunCapsuleToolIo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<RunCapsuleState>,
    pub audit: RunCapsuleAudit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RunCapsuleRun {
    pub run_id: String,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RunCapsuleSkill {
    pub skill_id: String,
    pub skill_manifest_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_contract_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_contract_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RunCapsuleRouter {
    pub router_config_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RunCapsuleTools {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_registry_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_policy_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RunCapsuleContext {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompt_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompt_template_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RunCapsuleProvider {
    pub provider_id: String,
    pub request_ref: String,
    pub response_ref: String,
    pub output_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_request_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_response_artifact_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RunCapsuleToolIo {
    pub tool_id: String,
    pub input_ref: String,
    pub output_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RunCapsuleState {
    pub initial_state_hash: String,
    pub final_state_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub state_delta_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RunCapsuleAudit {
    pub audit_head_hash: String,
}

pub fn write_run_capsule(
    runtime_root: &Path,
    capsule: &RunCapsule,
) -> Result<(String, String), RunCapsuleError> {
    let value = serde_json::to_value(capsule)
        .map_err(|_| RunCapsuleError::new("run_capsule_build_failed"))?;
    let bytes = canonical_json_bytes(&value)
        .map_err(|_| RunCapsuleError::new("run_capsule_build_failed"))?;
    let capsule_ref = sha256_bytes(&bytes);
    let capsule_hash = capsule_ref.clone();
    if capsule_ref != capsule_hash {
        return Err(RunCapsuleError::new("run_capsule_build_failed"));
    }
    let dir = runtime_root.join("artifacts").join("run_capsules");
    fs::create_dir_all(&dir)
        .map_err(|e| RunCapsuleError::with_detail("run_capsule_write_failed", e.to_string()))?;
    let filename = artifact_filename(&capsule_ref);
    let path = dir.join(&filename);
    if path.exists() {
        let existing = fs::read(&path)
            .map_err(|e| RunCapsuleError::with_detail("run_capsule_write_failed", e.to_string()))?;
        if existing != bytes {
            return Err(RunCapsuleError::new("run_capsule_write_failed"));
        }
        return Ok((capsule_ref, capsule_hash));
    }
    let tmp_path = dir.join(format!("{}.tmp", filename));
    let mut file = fs::File::create(&tmp_path)
        .map_err(|e| RunCapsuleError::with_detail("run_capsule_write_failed", e.to_string()))?;
    file.write_all(&bytes)
        .map_err(|e| RunCapsuleError::with_detail("run_capsule_write_failed", e.to_string()))?;
    file.sync_all()
        .map_err(|e| RunCapsuleError::with_detail("run_capsule_write_failed", e.to_string()))?;
    if let Err(e) = fs::rename(&tmp_path, &path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(RunCapsuleError::with_detail(
            "run_capsule_write_failed",
            e.to_string(),
        ));
    }
    Ok((capsule_ref, capsule_hash))
}
