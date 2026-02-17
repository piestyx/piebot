use crate::task::task_status::{read_task_status, StatusError, TaskStatus, TaskStatusKind};
use crate::task::task_store::is_safe_task_id;
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone)]
pub(crate) struct TaskStatusRow {
    pub(crate) task_id: String,
    pub(crate) status: TaskStatus,
}

pub(crate) fn list_pending_tasks(runtime_root: &Path) -> Result<Vec<TaskStatusRow>, StatusError> {
    let tasks_dir = runtime_root.join("tasks");
    if !tasks_dir.exists() {
        return Ok(Vec::new());
    }
    let mut task_ids = HashSet::new();
    let mut status_ids = HashSet::new();
    let task_entries = std::fs::read_dir(&tasks_dir)
        .map_err(|e| StatusError::with_source("task_status_read_failed", e))?;
    for entry in task_entries {
        let entry = entry.map_err(|e| StatusError::with_source("task_status_read_failed", e))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| StatusError::new("invalid_task_status"))?;
        if let Some(task_id) = file_name.strip_suffix(".status.json") {
            if !is_safe_task_id(task_id) {
                return Err(StatusError::new("task_id_unsafe"));
            }
            status_ids.insert(task_id.to_string());
            continue;
        }
        if let Some(task_id) = file_name.strip_suffix(".json") {
            if !is_safe_task_id(task_id) {
                return Err(StatusError::new("task_id_unsafe"));
            }
            task_ids.insert(task_id.to_string());
        }
    }
    for task_id in task_ids.iter() {
        if !status_ids.contains(task_id) {
            return Err(StatusError::new("task_status_missing"));
        }
    }
    for task_id in status_ids.iter() {
        if !task_ids.contains(task_id) {
            return Err(StatusError::new("task_not_found"));
        }
    }

    let mut rows = Vec::new();
    let entries = std::fs::read_dir(&tasks_dir)
        .map_err(|e| StatusError::with_source("task_status_read_failed", e))?;
    for entry in entries {
        let entry = entry.map_err(|e| StatusError::with_source("task_status_read_failed", e))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| StatusError::new("invalid_task_status"))?;
        let task_id = match file_name.strip_suffix(".status.json") {
            Some(id) => id,
            None => continue,
        };
        if !is_safe_task_id(task_id) {
            return Err(StatusError::new("task_id_unsafe"));
        }
        let status = read_task_status(runtime_root, task_id)?
            .ok_or_else(|| StatusError::new("task_status_missing"))?;
        if status.status == TaskStatusKind::Pending {
            rows.push(TaskStatusRow {
                task_id: task_id.to_string(),
                status,
            });
        }
    }

    rows.sort_by(|a, b| {
        a.status
            .enqueued_at
            .cmp(&b.status.enqueued_at)
            .then_with(|| a.task_id.cmp(&b.task_id))
    });

    Ok(rows)
}
