use crate::task::task_store::is_safe_task_id;
use pie_common::canonical_json_bytes;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub(crate) const TASK_STATUS_SCHEMA: &str = "serverd.task_status.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TaskStatusKind {
    Pending,
    Applied,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct TaskStatus {
    pub(crate) schema: String,
    pub(crate) task_id: String,
    pub(crate) status: TaskStatusKind,
    pub(crate) enqueued_at: u64,
    pub(crate) applied_at: Option<u64>,
    pub(crate) last_hash: Option<String>,
}

#[derive(Debug)]
pub(crate) struct StatusError {
    reason: &'static str,
    source: Option<std::io::Error>,
}

impl StatusError {
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

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for StatusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e as _)
    }
}

fn task_status_path(runtime_root: &Path, task_id: &str) -> PathBuf {
    runtime_root
        .join("tasks")
        .join(format!("{}.status.json", task_id))
}

pub(crate) fn read_task_status(
    runtime_root: &Path,
    task_id: &str,
) -> Result<Option<TaskStatus>, StatusError> {
    let path = task_status_path(runtime_root, task_id);
    if !path.exists() {
        return Ok(None);
    }
    let bytes =
        std::fs::read(&path).map_err(|e| StatusError::with_source("task_status_read_failed", e))?;
    let status: TaskStatus =
        serde_json::from_slice(&bytes).map_err(|_| StatusError::new("task_status_read_failed"))?;
    if status.schema != TASK_STATUS_SCHEMA || status.task_id != task_id {
        return Err(StatusError::new("invalid_task_status"));
    }
    Ok(Some(status))
}

pub(crate) fn write_task_status_atomic(
    runtime_root: &Path,
    task_id: &str,
    status: &TaskStatus,
) -> Result<PathBuf, StatusError> {
    if !is_safe_task_id(task_id) {
        return Err(StatusError::new("task_id_unsafe"));
    }
    let tasks_dir = runtime_root.join("tasks");
    std::fs::create_dir_all(&tasks_dir)
        .map_err(|e| StatusError::with_source("task_status_write_failed", e))?;

    let final_path = task_status_path(runtime_root, task_id);
    let tmp_path = tasks_dir.join(format!(".{}.status.{}.tmp", task_id, Uuid::new_v4()));

    let value =
        serde_json::to_value(status).map_err(|_| StatusError::new("task_status_write_failed"))?;
    let bytes =
        canonical_json_bytes(&value).map_err(|_| StatusError::new("task_status_write_failed"))?;

    let mut file = std::fs::File::create(&tmp_path)
        .map_err(|e| StatusError::with_source("task_status_write_failed", e))?;
    file.write_all(&bytes)
        .map_err(|e| StatusError::with_source("task_status_write_failed", e))?;
    file.sync_all()
        .map_err(|e| StatusError::with_source("task_status_write_failed", e))?;

    if let Err(e) = std::fs::rename(&tmp_path, &final_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(StatusError::with_source("task_status_write_failed", e));
    }

    Ok(final_path)
}
