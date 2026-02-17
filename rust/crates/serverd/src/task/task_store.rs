#![allow(dead_code)]

use pie_common::canonical_json_bytes;
use pie_kernel_state::StateDelta;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct TaskRequest {
    pub(crate) task_id: String,
    pub(crate) tick_index: u64,
    pub(crate) intent: Intent,
    // Stage 1 output correlation fields only.
    // NOT part of persisted task ingestion/ledger schema.
    // Must not be used for queue/ledger decisions; Stage 4 defines persisted schema contracts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) state_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) observation_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) requested_tick: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) request_hash: Option<String>,
    #[serde(default)]
    pub(crate) meta: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(crate) enum Intent {
    NoOp,
    ApplyDelta { delta: StateDelta },
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TaskSource {
    Stdin,
    File,
}

pub(crate) fn is_safe_task_id(task_id: &str) -> bool {
    if task_id == "." || task_id == ".." {
        return false;
    }
    task_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

pub(crate) fn canonical_task_bytes(task: &TaskRequest) -> Result<Vec<u8>, PersistError> {
    let value = serde_json::to_value(task).map_err(|_| PersistError::new("persist_failed"))?;
    canonical_json_bytes(&value).map_err(|_| PersistError::new("persist_failed"))
}

#[derive(Debug)]
pub(crate) struct PersistError {
    reason: &'static str,
    source: Option<std::io::Error>,
}

impl PersistError {
    pub(crate) fn new(reason: &'static str) -> Self {
        Self {
            reason,
            source: None,
        }
    }

    pub(crate) fn with_source(reason: &'static str, source: std::io::Error) -> Self {
        Self {
            reason,
            source: Some(source),
        }
    }

    pub(crate) fn reason(&self) -> &'static str {
        self.reason
    }
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for PersistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e as _)
    }
}

pub(crate) fn persist_task(
    runtime_root: &Path,
    task: &TaskRequest,
) -> Result<(PathBuf, Vec<u8>), PersistError> {
    if !is_safe_task_id(&task.task_id) {
        return Err(PersistError::new("task_id_unsafe"));
    }

    let tasks_dir = runtime_root.join("tasks");
    std::fs::create_dir_all(&tasks_dir)
        .map_err(|e| PersistError::with_source("persist_failed", e))?;

    let final_path = tasks_dir.join(format!("{}.json", task.task_id));
    let tmp_path = tasks_dir.join(format!(".{}.{}.tmp", task.task_id, Uuid::new_v4()));
    let bytes = canonical_task_bytes(task)?;

    let mut file = std::fs::File::create(&tmp_path)
        .map_err(|e| PersistError::with_source("persist_failed", e))?;
    file.write_all(&bytes)
        .map_err(|e| PersistError::with_source("persist_failed", e))?;
    file.sync_all()
        .map_err(|e| PersistError::with_source("persist_failed", e))?;

    if let Err(e) = std::fs::rename(&tmp_path, &final_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(PersistError::with_source("persist_failed", e));
    }
    Ok((final_path, bytes))
}
