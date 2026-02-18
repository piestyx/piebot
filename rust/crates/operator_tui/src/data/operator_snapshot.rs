use crate::model::{PendingApproval, RunSummary};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub(crate) struct OperatorSnapshot {
    pub(crate) runs: Vec<RunSummary>,
    pub(crate) pending_approvals: Vec<PendingApproval>,
}

#[derive(Clone, Debug)]
struct IndexedEvent {
    line_index: usize,
    event: Value,
}

#[derive(Clone, Debug)]
struct RunBuilder {
    run_id: String,
    start_line_index: usize,
    last_line_index: usize,
    last_tick_index: Option<u64>,
    final_state_hash: Option<String>,
    capsule_ref: Option<String>,
    verification_ref: Option<String>,
    has_run_started: bool,
    has_run_completed: bool,
    refused: bool,
}

pub(crate) fn load_operator_snapshot(runtime_root: &Path) -> Result<OperatorSnapshot, String> {
    let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
    let events = read_audit_events_strict(&audit_path)?;
    derive_operator_snapshot(runtime_root, &events)
}

fn derive_operator_snapshot(
    runtime_root: &Path,
    events: &[IndexedEvent],
) -> Result<OperatorSnapshot, String> {
    let mut runs: HashMap<String, RunBuilder> = HashMap::new();
    let mut current_run: Option<String> = None;

    fn run_id_from_event_or_current(event: &Value, current_run: &Option<String>) -> Option<String> {
        if let Some(run_id) = event.get("run_id").and_then(|v| v.as_str()) {
            if !run_id.is_empty() {
                return Some(run_id.to_string());
            }
        }
        current_run.clone()
    }
    let mut pending: HashMap<(String, String, String), PendingApproval> = HashMap::new();

    for indexed in events {
        let event = &indexed.event;
        let event_type = event
            .get("event_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("audit_log_invalid: line {}", indexed.line_index + 1))?;
        match event_type {
            "run_started" => {
                let run_id = event
                    .get("run_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("audit_log_invalid: line {}", indexed.line_index + 1))?
                    .to_string();
                current_run = Some(run_id.clone());
                let run = upsert_run(&mut runs, &run_id, indexed.line_index);
                run.has_run_started = true;
            }
            "run_completed" => {
                let run_id = event
                    .get("run_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("audit_log_invalid: line {}", indexed.line_index + 1))?
                    .to_string();
                let run = upsert_run(&mut runs, &run_id, indexed.line_index);
                run.last_line_index = indexed.line_index;
                run.has_run_completed = true;
                run.final_state_hash = event
                    .get("final_state_hash")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string());
                if current_run.as_deref() == Some(run_id.as_str()) {
                    current_run = None;
                }
            }
            "tool_approval_required" => {
                let run_id = match run_id_from_event_or_current(event, &current_run) {
                    Some(value) => value,
                    None => continue,
                };
                let tool_id = match event.get("tool_id").and_then(|v| v.as_str()) {
                    Some(value) => value.to_string(),
                    None => continue,
                };
                let approval_ref = match event.get("approval_ref").and_then(|v| v.as_str()) {
                    Some(value) => value.to_string(),
                    None => continue,
                };
                let request_hash = event
                    .get("request_hash")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string());
                let input_ref = read_approval_request_input_ref(runtime_root, &approval_ref);
                let requested_tick_index = event.get("tick_index").and_then(|v| v.as_u64());
                let key = (run_id.clone(), tool_id.clone(), approval_ref.clone());
                pending.entry(key).or_insert(PendingApproval {
                    run_id,
                    tool_id,
                    approval_ref,
                    input_ref,
                    request_hash,
                    requested_tick_index,
                    requested_line_index: indexed.line_index,
                });
            }
            "approval_created" => {
                let tool_id = match event.get("tool_id").and_then(|v| v.as_str()) {
                    Some(value) => value,
                    None => continue,
                };
                let approval_ref = match event.get("approval_ref").and_then(|v| v.as_str()) {
                    Some(value) => value,
                    None => continue,
                };
                let run_id = match event.get("run_id").and_then(|v| v.as_str()) {
                    Some(value) => value,
                    None => {
                        return Err(format!(
                            "audit_log_invalid: line {} (approval_created missing run_id)",
                            indexed.line_index + 1
                        ));
                    }
                };
                pending.remove(&(
                    run_id.to_string(),
                    tool_id.to_string(),
                    approval_ref.to_string(),
                ));
            }
            "operator_action_refused" => {
                if event.get("action").and_then(|v| v.as_str()) != Some("operator_refuse") {
                    continue;
                }
                if event.get("reason").and_then(|v| v.as_str()) != Some("operator_refused") {
                    continue;
                }
                if let Some(run_id) = event.get("run_id").and_then(|v| v.as_str()) {
                    let run = upsert_run(&mut runs, run_id, indexed.line_index);
                    run.last_line_index = indexed.line_index;
                    run.refused = true;
                }
            }
            "operator_action_completed" => {
                let action = event.get("action").and_then(|v| v.as_str());
                if action == Some("operator_refuse") {
                    let run_id = match event.get("run_id").and_then(|v| v.as_str()) {
                        Some(value) => value,
                        None => continue,
                    };
                    let tool_id = match event.get("target_id").and_then(|v| v.as_str()) {
                        Some(value) => value,
                        None => continue,
                    };
                    let approval_ref = match event.get("artifact_ref").and_then(|v| v.as_str()) {
                        Some(value) => value,
                        None => continue,
                    };
                    pending.remove(&(
                        run_id.to_string(),
                        tool_id.to_string(),
                        approval_ref.to_string(),
                    ));
                    let run = upsert_run(&mut runs, run_id, indexed.line_index);
                    run.last_line_index = indexed.line_index;
                    run.refused = true;
                } else if action == Some("operator_replay_verify") {
                    let run_id = match event.get("run_id").and_then(|v| v.as_str()) {
                        Some(value) => value.to_string(),
                        None => continue,
                    };
                    let verification_ref = match event.get("artifact_ref").and_then(|v| v.as_str())
                    {
                        Some(value) => value.to_string(),
                        None => continue,
                    };
                    let run = upsert_run(&mut runs, &run_id, indexed.line_index);
                    run.last_line_index = indexed.line_index;
                    run.verification_ref = Some(verification_ref);
                }
            }
            "run_capsule_written" => {
                let run_id = match run_id_from_event_or_current(event, &current_run) {
                    Some(value) => value,
                    None => continue,
                };
                let capsule_ref = match event.get("capsule_ref").and_then(|v| v.as_str()) {
                    Some(value) => value.to_string(),
                    None => continue,
                };
                let run = upsert_run(&mut runs, &run_id, indexed.line_index);
                run.last_line_index = indexed.line_index;
                run.capsule_ref = Some(capsule_ref);
            }
            "tick_completed" => {
                let run_id = match run_id_from_event_or_current(event, &current_run) {
                    Some(value) => value,
                    None => continue,
                };
                let tick_index = event.get("tick_index").and_then(|v| v.as_u64());
                let run = upsert_run(&mut runs, &run_id, indexed.line_index);
                run.last_line_index = indexed.line_index;
                if tick_index.is_some() {
                    run.last_tick_index = tick_index;
                }
            }
            _ => {
                if let Some(run_id) = event.get("run_id").and_then(|v| v.as_str()) {
                    let run = upsert_run(&mut runs, run_id, indexed.line_index);
                    run.last_line_index = indexed.line_index;
                } else if let Some(run_id) = current_run.as_ref() {
                    let run = upsert_run(&mut runs, run_id, indexed.line_index);
                    run.last_line_index = indexed.line_index;
                }
            }
        }
    }

    let mut run_summaries: Vec<RunSummary> = runs
        .values()
        .map(|run| RunSummary {
            run_id: run.run_id.clone(),
            status: if run.refused {
                "refused".to_string()
            } else if run.has_run_started && run.has_run_completed {
                "completed".to_string()
            } else if !run.has_run_started && run.has_run_completed {
                "invalid".to_string()
            } else if run.has_run_started {
                "running".to_string()
            } else {
                "unknown".to_string()
            },
            final_state_hash: run.final_state_hash.clone(),
            capsule_ref: run.capsule_ref.clone(),
            verification_ref: run.verification_ref.clone(),
            last_tick_index: run.last_tick_index,
            start_line_index: run.start_line_index,
        })
        .collect();
    run_summaries.sort_by(|a, b| {
        b.start_line_index
            .cmp(&a.start_line_index)
            .then_with(|| a.run_id.cmp(&b.run_id))
    });

    let mut pending_approvals: Vec<PendingApproval> = pending.values().cloned().collect();
    pending_approvals.sort_by(|a, b| {
        a.requested_line_index
            .cmp(&b.requested_line_index)
            .then_with(|| a.run_id.cmp(&b.run_id))
            .then_with(|| a.tool_id.cmp(&b.tool_id))
            .then_with(|| a.approval_ref.cmp(&b.approval_ref))
    });

    Ok(OperatorSnapshot {
        runs: run_summaries,
        pending_approvals,
    })
}

pub(crate) fn approval_file_path(runtime_root: &Path, approval_ref: &str) -> PathBuf {
    let trimmed = approval_ref.strip_prefix("sha256:").unwrap_or(approval_ref);
    runtime_root
        .join("approvals")
        .join(format!("{}.approved.json", trimmed))
}

pub(crate) fn artifact_path_for_ref(
    runtime_root: &Path,
    namespace: &str,
    artifact_ref: &str,
) -> PathBuf {
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    runtime_root
        .join("artifacts")
        .join(namespace)
        .join(format!("{}.json", trimmed))
}

pub(crate) fn read_json_file(path: &Path) -> Result<Value, String> {
    let bytes = fs::read(path).map_err(|e| format!("read failed {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("json invalid {}: {}", path.display(), e))
}

fn read_audit_events_strict(path: &Path) -> Result<Vec<IndexedEvent>, String> {
    if !path.is_file() {
        return Err("audit_log_missing".to_string());
    }
    let content = fs::read_to_string(path).map_err(|e| format!("audit_log_read_failed: {}", e))?;
    let mut events = Vec::new();
    for (line_index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let record: Value = serde_json::from_str(trimmed)
            .map_err(|_| format!("audit_log_malformed_line: {}", line_index + 1))?;
        let envelope = record
            .get("event")
            .ok_or_else(|| format!("audit_log_malformed_line: {}", line_index + 1))?;
        let event = envelope.get("event").unwrap_or(envelope).clone();
        let event_type = event
            .get("event_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("audit_log_malformed_line: {}", line_index + 1))?;
        if event_type.is_empty() {
            return Err(format!("audit_log_malformed_line: {}", line_index + 1));
        }
        events.push(IndexedEvent { line_index, event });
    }
    Ok(events)
}

fn read_approval_request_input_ref(runtime_root: &Path, approval_ref: &str) -> Option<String> {
    let path = artifact_path_for_ref(runtime_root, "approvals", approval_ref);
    let bytes = fs::read(path).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value
        .get("input_ref")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
}

fn upsert_run<'a>(
    runs: &'a mut HashMap<String, RunBuilder>,
    run_id: &str,
    line_index: usize,
) -> &'a mut RunBuilder {
    runs.entry(run_id.to_string()).or_insert(RunBuilder {
        run_id: run_id.to_string(),
        start_line_index: line_index,
        last_line_index: line_index,
        last_tick_index: None,
        final_state_hash: None,
        capsule_ref: None,
        verification_ref: None,
        has_run_started: false,
        has_run_completed: false,
        refused: false,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        approval_file_path, artifact_path_for_ref, derive_operator_snapshot,
        load_operator_snapshot, IndexedEvent, OperatorSnapshot,
    };
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn evt(line_index: usize, event: serde_json::Value) -> IndexedEvent {
        IndexedEvent { line_index, event }
    }

    #[test]
    fn derives_pending_approvals_deterministically() {
        let runtime_root = PathBuf::from("/tmp/nonexistent-runtime");
        let events = vec![
            evt(1, json!({"event_type":"run_started","run_id":"sha256:aaa"})),
            evt(
                2,
                json!({"event_type":"tool_approval_required","tool_id":"tools.noop","approval_ref":"sha256:111","request_hash":"sha256:req1"}),
            ),
            evt(
                3,
                json!({"event_type":"tool_approval_required","tool_id":"tools.exec","approval_ref":"sha256:222","request_hash":"sha256:req2"}),
            ),
            evt(
                4,
                json!({"event_type":"approval_created","run_id":"sha256:aaa","tool_id":"tools.noop","approval_ref":"sha256:111"}),
            ),
            evt(
                5,
                json!({"event_type":"run_completed","run_id":"sha256:aaa","final_state_hash":"sha256:end"}),
            ),
        ];
        let snapshot: OperatorSnapshot =
            derive_operator_snapshot(&runtime_root, &events).expect("derive snapshot");
        assert_eq!(snapshot.pending_approvals.len(), 1);
        assert_eq!(snapshot.pending_approvals[0].tool_id, "tools.exec");
        assert_eq!(snapshot.pending_approvals[0].approval_ref, "sha256:222");
    }

    #[test]
    fn resolves_paths_from_refs() {
        let runtime_root = PathBuf::from("/runtime");
        assert_eq!(
            artifact_path_for_ref(&runtime_root, "run_capsules", "sha256:abcd"),
            PathBuf::from("/runtime/artifacts/run_capsules/abcd.json")
        );
        assert_eq!(
            approval_file_path(&runtime_root, "sha256:abcd"),
            PathBuf::from("/runtime/approvals/abcd.approved.json")
        );
    }

    #[test]
    fn strict_reader_fails_closed_on_malformed_audit_jsonl() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let runtime_root =
            std::env::temp_dir().join(format!("operator_tui_malformed_audit_{}", unique));
        let logs_dir = runtime_root.join("logs");
        std::fs::create_dir_all(&logs_dir).expect("create logs dir");
        std::fs::write(logs_dir.join("audit_rust.jsonl"), "{not-json}\n")
            .expect("write malformed audit");
        let result = load_operator_snapshot(&runtime_root);
        assert!(result.is_err(), "expected malformed audit error");
        let err = result.err().unwrap_or_default();
        assert!(
            err.contains("audit_log_malformed_line"),
            "unexpected error: {}",
            err
        );
        let _ = std::fs::remove_dir_all(runtime_root);
    }

    #[test]
    fn status_mapping_test() {
        let runtime_root = PathBuf::from("/tmp/nonexistent-runtime");

        // refused
        let events_refused = vec![
            evt(1, json!({"event_type":"run_started","run_id":"sha256:111"})),
            evt(
                2,
                json!({"event_type":"operator_action_refused","action":"operator_refuse","reason":"operator_refused","run_id":"sha256:111","target_id":"tools.noop"}),
            ),
        ];
        let snap_refused =
            derive_operator_snapshot(&runtime_root, &events_refused).expect("refused");
        assert_eq!(snap_refused.runs[0].status, "refused");

        // completed
        let events_completed = vec![
            evt(1, json!({"event_type":"run_started","run_id":"sha256:222"})),
            evt(
                2,
                json!({"event_type":"run_completed","run_id":"sha256:222","final_state_hash":"sha256:end"}),
            ),
        ];
        let snap_completed =
            derive_operator_snapshot(&runtime_root, &events_completed).expect("completed");
        assert_eq!(snap_completed.runs[0].status, "completed");

        // running (started, not completed)
        let events_running = vec![
            evt(1, json!({"event_type":"run_started","run_id":"sha256:333"})),
            evt(
                2,
                json!({"event_type":"tick_completed","run_id":"sha256:333","tick_index":1}),
            ),
        ];
        let snap_running =
            derive_operator_snapshot(&runtime_root, &events_running).expect("running");
        assert_eq!(snap_running.runs[0].status, "running");

        // unknown (run-scoped events but no lifecycle markers)
        let events_unknown = vec![evt(
            1,
            json!({"event_type":"tick_completed","run_id":"sha256:444","tick_index":1}),
        )];
        let snap_unknown =
            derive_operator_snapshot(&runtime_root, &events_unknown).expect("unknown");
        assert_eq!(snap_unknown.runs[0].status, "unknown");

        // invalid (run_completed without run_started)
        let events_invalid = vec![evt(
            1,
            json!({"event_type":"run_completed","run_id":"sha256:555","final_state_hash":"sha256:end"}),
        )];
        let snap_invalid =
            derive_operator_snapshot(&runtime_root, &events_invalid).expect("invalid");
        assert_eq!(snap_invalid.runs[0].status, "invalid");
    }

    #[test]
    fn approval_created_missing_run_id_fails() {
        let runtime_root = PathBuf::from("/tmp/nonexistent-runtime");
        let events = vec![
            evt(1, json!({"event_type":"run_started","run_id":"sha256:aaa"})),
            evt(
                2,
                json!({"event_type":"tool_approval_required","run_id":"sha256:aaa","tool_id":"tools.noop","approval_ref":"sha256:111","request_hash":"sha256:req1"}),
            ),
            evt(
                3,
                json!({"event_type":"approval_created","tool_id":"tools.noop","approval_ref":"sha256:111"}),
            ),
        ];
        let result = derive_operator_snapshot(&runtime_root, &events);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("approval_created missing run_id"));
    }
}
