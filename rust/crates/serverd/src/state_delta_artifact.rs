use crate::runtime::artifacts::artifact_filename;
use crate::tools::ToolError;
use pie_common::{canonical_json_bytes, sha256_bytes};
use pie_kernel_state::{apply_delta, KernelState, StateDelta};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const STATE_DELTA_ARTIFACT_SCHEMA: &str = "serverd.state_delta_artifact.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct StateDeltaArtifact {
    schema: String,
    kind: String,
    params: serde_json::Value,
}

pub fn write_delta_artifact(runtime_root: &Path, delta: &StateDelta) -> Result<String, ToolError> {
    let (kind, params) = match delta {
        StateDelta::TickAdvance { by } => {
            ("tick_advance".to_string(), serde_json::json!({ "by": by }))
        }
        StateDelta::SetTag { key, value } => (
            "set_tag".to_string(),
            serde_json::json!({ "key": key, "value": value }),
        ),
    };
    let artifact = StateDeltaArtifact {
        schema: STATE_DELTA_ARTIFACT_SCHEMA.to_string(),
        kind,
        params,
    };
    let value = serde_json::to_value(&artifact)
        .map_err(|_| ToolError::new("state_delta_artifact_invalid"))?;
    let bytes = canonical_json_bytes(&value)
        .map_err(|_| ToolError::new("state_delta_artifact_hash_failed"))?;
    let artifact_ref = sha256_bytes(&bytes);
    let dir = runtime_root.join("artifacts").join("state_deltas");
    fs::create_dir_all(&dir)
        .map_err(|e| ToolError::with_source("state_delta_artifact_write_failed", e))?;
    let filename = artifact_filename(&artifact_ref);
    let path = dir.join(&filename);
    if path.exists() {
        let existing = fs::read(&path)
            .map_err(|e| ToolError::with_source("state_delta_artifact_read_failed", e))?;
        if existing != bytes {
            return Err(ToolError::new("state_delta_artifact_conflict"));
        }
        return Ok(artifact_ref);
    }
    let tmp_path = dir.join(format!("{}.tmp", filename));
    let mut file = fs::File::create(&tmp_path)
        .map_err(|e| ToolError::with_source("state_delta_artifact_write_failed", e))?;
    file.write_all(&bytes)
        .map_err(|e| ToolError::with_source("state_delta_artifact_write_failed", e))?;
    file.sync_all()
        .map_err(|e| ToolError::with_source("state_delta_artifact_write_failed", e))?;
    if let Err(e) = fs::rename(&tmp_path, &path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(ToolError::with_source(
            "state_delta_artifact_write_failed",
            e,
        ));
    }
    Ok(artifact_ref)
}

pub fn apply_delta_from_artifact(
    runtime_root: &Path,
    delta_ref: &str,
    state: KernelState,
) -> Result<KernelState, ToolError> {
    let path = state_delta_artifact_path(runtime_root, delta_ref);
    let bytes = fs::read(&path)
        .map_err(|e| ToolError::with_source("state_delta_artifact_read_failed", e))?;
    let artifact: StateDeltaArtifact = serde_json::from_slice(&bytes)
        .map_err(|_| ToolError::new("state_delta_artifact_invalid"))?;
    if artifact.schema != STATE_DELTA_ARTIFACT_SCHEMA {
        return Err(ToolError::new("state_delta_artifact_invalid"));
    }
    let delta = match artifact.kind.as_str() {
        "tick_advance" => {
            let by = artifact
                .params
                .get("by")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| ToolError::new("state_delta_artifact_invalid"))?;
            StateDelta::TickAdvance { by }
        }
        "set_tag" => {
            let key = artifact
                .params
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ToolError::new("state_delta_artifact_invalid"))?;
            let value = artifact
                .params
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ToolError::new("state_delta_artifact_invalid"))?;
            StateDelta::SetTag {
                key: key.to_string(),
                value: value.to_string(),
            }
        }
        _ => return Err(ToolError::new("state_delta_artifact_invalid")),
    };
    Ok(apply_delta(state, &delta))
}

fn state_delta_artifact_path(runtime_root: &Path, artifact_ref: &str) -> PathBuf {
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    runtime_root
        .join("artifacts")
        .join("state_deltas")
        .join(format!("{}.json", trimmed))
}
