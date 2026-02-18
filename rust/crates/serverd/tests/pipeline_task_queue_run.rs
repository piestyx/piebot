#![cfg(feature = "bin")]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

fn run_ingest_stdin(runtime_root: &Path, input: &[u8]) -> Output {
    let mut cmd = Command::new(common::serverd_exe());
    cmd.arg("ingest")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn serverd ingest");
    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        stdin.write_all(input).expect("failed to write stdin");
    }
    child.wait_with_output().expect("failed to wait on ingest")
}

fn run_serverd(runtime_root: &Path, ticks: u64, delta: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("--mode")
        .arg("null")
        .arg("--ticks")
        .arg(ticks.to_string())
        .arg("--delta")
        .arg(delta)
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run serverd")
}

fn read_event_types(runtime_root: &Path) -> Vec<String> {
    let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
    let contents = fs::read_to_string(audit_path).expect("failed to read audit log");
    let mut types = Vec::new();

    for (i, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line {}: {}", i + 1, e));
        let envelope = record
            .get("event")
            .unwrap_or_else(|| panic!("line {} missing event", i + 1));
        let inner = envelope
            .get("event")
            .unwrap_or_else(|| panic!("line {} missing inner event", i + 1));
        let event_type = inner
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        types.push(event_type);
    }

    types
}

fn find_next_event(events: &[String], event_type: &str, start: usize) -> usize {
    events
        .iter()
        .skip(start)
        .position(|event| event == event_type)
        .map(|idx| idx + start)
        .unwrap_or_else(|| panic!("missing {} after index {}", event_type, start))
}

fn assert_stage2_events_within_window(events: &[String], start: usize, end: usize) {
    for (idx, event) in events.iter().enumerate() {
        if matches!(
            event.as_str(),
            "episode_appended" | "working_memory_updated" | "open_memory_mirror_written"
        ) {
            assert!(
                idx > start && idx < end,
                "stage2 event {} at {} is outside allowed window",
                event,
                idx
            );
        }
    }
}

fn read_task_ids(runtime_root: &Path, event_type: &str) -> Vec<String> {
    let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
    let contents = fs::read_to_string(audit_path).expect("failed to read audit log");
    let mut ids = Vec::new();

    for (i, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line {}: {}", i + 1, e));
        let envelope = record
            .get("event")
            .unwrap_or_else(|| panic!("line {} missing event", i + 1));
        let inner = envelope
            .get("event")
            .unwrap_or_else(|| panic!("line {} missing inner event", i + 1));
        let kind = inner
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if kind == event_type {
            if let Some(id) = inner.get("task_id").and_then(|v| v.as_str()) {
                ids.push(id.to_string());
            }
        }
    }

    ids
}

fn force_enqueued_at(runtime_root: &Path, task_id: &str, value: u64) {
    let status_path = runtime_root
        .join("tasks")
        .join(format!("{}.status.json", task_id));
    let status_bytes = fs::read(&status_path).expect("missing task status file");
    let mut status: serde_json::Value =
        serde_json::from_slice(&status_bytes).expect("status file not json");
    status["enqueued_at"] = serde_json::json!(value);
    fs::write(&status_path, serde_json::to_vec_pretty(&status).unwrap())
        .expect("failed to write status");
}

#[test]
fn run_applies_pending_task() {
    let runtime_root = std::env::temp_dir().join(format!("pie_queue_apply_{}", Uuid::new_v4()));
    let input = br#"{"task_id":"task-1","tick_index":7,"intent":{"kind":"apply_delta","delta":{"kind":"tick_advance","by":1}}}"#;
    let out_ingest = run_ingest_stdin(&runtime_root, input);
    assert!(
        out_ingest.status.success(),
        "ingest failed: {}",
        String::from_utf8_lossy(&out_ingest.stderr)
    );

    let _ = fs::remove_dir_all(runtime_root.join("logs"));
    let out = run_serverd(&runtime_root, 1, "tick:0");
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let status_path = runtime_root.join("tasks").join("task-1.status.json");
    let status_bytes = fs::read(&status_path).expect("missing task status file");
    let status: serde_json::Value =
        serde_json::from_slice(&status_bytes).expect("status file not json");
    assert_eq!(
        status.get("status").and_then(|v| v.as_str()),
        Some("applied")
    );
    assert!(status.get("last_hash").and_then(|v| v.as_str()).is_some());

    let state_path = runtime_root.join("state").join("gsama_state.json");
    let state_bytes = fs::read(&state_path).expect("missing state file");
    let state: serde_json::Value =
        serde_json::from_slice(&state_bytes).expect("state file not json");
    assert_eq!(state.get("tick").and_then(|v| v.as_u64()), Some(1));

    let events = read_event_types(&runtime_root);
    let run_started_idx = find_next_event(&events, "run_started", 0);
    let task_queue_scanned_idx =
        find_next_event(&events, "task_queue_scanned", run_started_idx + 1);
    let task_claimed_idx = find_next_event(&events, "task_claimed", task_queue_scanned_idx + 1);
    let observation_idx = find_next_event(&events, "observation_captured", task_claimed_idx + 1);
    let state_snapshot_idx = find_next_event(&events, "state_snapshot_loaded", observation_idx + 1);
    let intent_selected_idx = find_next_event(&events, "intent_selected", state_snapshot_idx + 1);
    let state_delta_proposed_idx =
        find_next_event(&events, "state_delta_proposed", intent_selected_idx + 1);
    let state_delta_applied_idx =
        find_next_event(&events, "state_delta_applied", state_delta_proposed_idx + 1);
    let tick_completed_idx =
        find_next_event(&events, "tick_completed", state_delta_applied_idx + 1);
    let _task_applied_idx = find_next_event(&events, "task_applied", tick_completed_idx + 1);
    let capsule_idx = find_next_event(&events, "run_capsule_written", _task_applied_idx + 1);
    let _run_completed_idx = find_next_event(&events, "run_completed", capsule_idx + 1);

    let scan_count = events
        .iter()
        .filter(|event| event.as_str() == "task_queue_scanned")
        .count();
    assert_eq!(scan_count, 1, "task_queue_scanned must occur exactly once");
    assert_stage2_events_within_window(&events, state_delta_applied_idx, tick_completed_idx);
}

#[test]
fn run_falls_back_to_delta_when_no_pending() {
    let runtime_root = std::env::temp_dir().join(format!("pie_queue_empty_{}", Uuid::new_v4()));
    let out = run_serverd(&runtime_root, 1, "tick:1");
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let events = read_event_types(&runtime_root);
    let run_started_idx = find_next_event(&events, "run_started", 0);
    let task_queue_scanned_idx =
        find_next_event(&events, "task_queue_scanned", run_started_idx + 1);
    let observation_idx =
        find_next_event(&events, "observation_captured", task_queue_scanned_idx + 1);
    let state_snapshot_idx = find_next_event(&events, "state_snapshot_loaded", observation_idx + 1);
    let intent_selected_idx = find_next_event(&events, "intent_selected", state_snapshot_idx + 1);
    let state_delta_proposed_idx =
        find_next_event(&events, "state_delta_proposed", intent_selected_idx + 1);
    let state_delta_applied_idx =
        find_next_event(&events, "state_delta_applied", state_delta_proposed_idx + 1);
    let tick_completed_idx =
        find_next_event(&events, "tick_completed", state_delta_applied_idx + 1);
    let capsule_idx = find_next_event(&events, "run_capsule_written", tick_completed_idx + 1);
    let _run_completed_idx = find_next_event(&events, "run_completed", capsule_idx + 1);

    let scan_count = events
        .iter()
        .filter(|event| event.as_str() == "task_queue_scanned")
        .count();
    assert_eq!(scan_count, 1, "task_queue_scanned must occur exactly once");
    assert_stage2_events_within_window(&events, state_delta_applied_idx, tick_completed_idx);

    let state_path = runtime_root.join("state").join("gsama_state.json");
    let state_bytes = fs::read(&state_path).expect("missing state file");
    let state: serde_json::Value =
        serde_json::from_slice(&state_bytes).expect("state file not json");
    assert_eq!(state.get("tick").and_then(|v| v.as_u64()), Some(1));
}

#[test]
fn run_is_deterministic_with_two_pending() {
    let runtime_root = std::env::temp_dir().join(format!("pie_queue_two_{}", Uuid::new_v4()));
    let input_a = br#"{"task_id":"task-a","tick_index":1,"intent":{"kind":"apply_delta","delta":{"kind":"tick_advance","by":1}}}"#;
    let input_b = br#"{"task_id":"task-b","tick_index":1,"intent":{"kind":"apply_delta","delta":{"kind":"tick_advance","by":2}}}"#;
    let out_a = run_ingest_stdin(&runtime_root, input_a);
    let out_b = run_ingest_stdin(&runtime_root, input_b);
    assert!(out_a.status.success());
    assert!(out_b.status.success());

    force_enqueued_at(&runtime_root, "task-a", 1);
    force_enqueued_at(&runtime_root, "task-b", 1);

    let _ = fs::remove_dir_all(runtime_root.join("logs"));
    let out = run_serverd(&runtime_root, 1, "tick:0");
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let status_a = fs::read(runtime_root.join("tasks").join("task-a.status.json"))
        .expect("missing task-a status");
    let status_a: serde_json::Value =
        serde_json::from_slice(&status_a).expect("task-a status not json");
    let status_b = fs::read(runtime_root.join("tasks").join("task-b.status.json"))
        .expect("missing task-b status");
    let status_b: serde_json::Value =
        serde_json::from_slice(&status_b).expect("task-b status not json");
    assert_eq!(
        status_a.get("status").and_then(|v| v.as_str()),
        Some("applied")
    );
    assert_eq!(
        status_b.get("status").and_then(|v| v.as_str()),
        Some("pending")
    );

    let state_path = runtime_root.join("state").join("gsama_state.json");
    let state_bytes = fs::read(&state_path).expect("missing state file");
    let state: serde_json::Value =
        serde_json::from_slice(&state_bytes).expect("state file not json");
    assert_eq!(state.get("tick").and_then(|v| v.as_u64()), Some(1));

    let claimed = read_task_ids(&runtime_root, "task_claimed");
    assert_eq!(claimed, vec!["task-a".to_string()]);
}

#[test]
fn pending_status_but_task_missing_fails_closed() {
    let runtime_root = std::env::temp_dir().join(format!("pie_queue_missing_{}", Uuid::new_v4()));
    let input = br#"{"task_id":"task-1","tick_index":1,"intent":{"kind":"no_op"}}"#;
    let out_ingest = run_ingest_stdin(&runtime_root, input);
    assert!(out_ingest.status.success());

    let task_path = runtime_root.join("tasks").join("task-1.json");
    fs::remove_file(&task_path).expect("failed to remove task json");

    let _ = fs::remove_dir_all(runtime_root.join("logs"));
    let out = run_serverd(&runtime_root, 1, "tick:0");
    assert!(!out.status.success());

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("task_not_found")
    );

    let events = read_event_types(&runtime_root);
    let expected = vec!["run_started", "run_completed"];
    assert_eq!(events, expected);

    let status_path = runtime_root.join("tasks").join("task-1.status.json");
    let status_bytes = fs::read(&status_path).expect("missing status file");
    let status: serde_json::Value =
        serde_json::from_slice(&status_bytes).expect("status file not json");
    assert_eq!(
        status.get("status").and_then(|v| v.as_str()),
        Some("pending")
    );
    assert!(status.get("last_hash").map_or(true, |v| v.is_null()));

    let state_path = runtime_root.join("state").join("gsama_state.json");
    assert!(!state_path.exists());
}

#[test]
fn orphan_status_without_task_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_queue_orphan_status_{}", Uuid::new_v4()));
    let tasks_dir = runtime_root.join("tasks");
    fs::create_dir_all(&tasks_dir).expect("failed to create tasks dir");

    let status_path = tasks_dir.join("task-1.status.json");
    let status = serde_json::json!({
        "schema": "serverd.task_status.v1",
        "task_id": "task-1",
        "status": "pending",
        "enqueued_at": 1,
        "applied_at": null,
        "last_hash": null
    });
    fs::write(&status_path, serde_json::to_vec_pretty(&status).unwrap())
        .expect("failed to write status");

    let out = run_serverd(&runtime_root, 1, "tick:0");
    assert!(!out.status.success());

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("task_not_found")
    );

    let events = read_event_types(&runtime_root);
    let expected = vec!["run_started", "run_completed"];
    assert_eq!(events, expected);

    let state_path = runtime_root.join("state").join("gsama_state.json");
    assert!(!state_path.exists());
}

#[test]
fn orphan_task_file_without_status_fails_closed() {
    let runtime_root = std::env::temp_dir().join(format!("pie_queue_orphan_{}", Uuid::new_v4()));
    let tasks_dir = runtime_root.join("tasks");
    fs::create_dir_all(&tasks_dir).expect("failed to create tasks dir");

    let task_path = tasks_dir.join("task-1.json");
    let task = br#"{"task_id":"task-1","tick_index":1,"intent":{"kind":"no_op"}}"#;
    fs::write(&task_path, task).expect("failed to write task");

    let out = run_serverd(&runtime_root, 1, "tick:0");
    assert!(!out.status.success());

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("task_status_missing")
    );

    let events = read_event_types(&runtime_root);
    let expected = vec!["run_started", "run_completed"];
    assert_eq!(events, expected);

    let state_path = runtime_root.join("state").join("gsama_state.json");
    assert!(!state_path.exists());
}

#[test]
fn invalid_status_schema_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_queue_bad_schema_{}", Uuid::new_v4()));
    let input = br#"{"task_id":"task-1","tick_index":1,"intent":{"kind":"no_op"}}"#;
    let out_ingest = run_ingest_stdin(&runtime_root, input);
    assert!(out_ingest.status.success());

    let status_path = runtime_root.join("tasks").join("task-1.status.json");
    let status_bytes = fs::read(&status_path).expect("missing status file");
    let mut status: serde_json::Value =
        serde_json::from_slice(&status_bytes).expect("status file not json");
    status["schema"] = serde_json::json!("wrong.schema");
    fs::write(&status_path, serde_json::to_vec_pretty(&status).unwrap())
        .expect("failed to write status");

    let _ = fs::remove_dir_all(runtime_root.join("logs"));
    let out = run_serverd(&runtime_root, 1, "tick:0");
    assert!(!out.status.success());

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("invalid_task_status")
    );

    let events = read_event_types(&runtime_root);
    let expected = vec!["run_started", "run_completed"];
    assert_eq!(events, expected);

    let state_path = runtime_root.join("state").join("gsama_state.json");
    assert!(!state_path.exists());
}

#[test]
fn malformed_status_json_fails_closed() {
    let runtime_root = std::env::temp_dir().join(format!("pie_queue_bad_json_{}", Uuid::new_v4()));
    let input = br#"{"task_id":"task-1","tick_index":1,"intent":{"kind":"no_op"}}"#;
    let out_ingest = run_ingest_stdin(&runtime_root, input);
    assert!(out_ingest.status.success());

    let status_path = runtime_root.join("tasks").join("task-1.status.json");
    fs::write(&status_path, b"{").expect("failed to corrupt status");

    let _ = fs::remove_dir_all(runtime_root.join("logs"));
    let out = run_serverd(&runtime_root, 1, "tick:0");
    assert!(!out.status.success());

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("task_status_read_failed")
    );

    let events = read_event_types(&runtime_root);
    let expected = vec!["run_started", "run_completed"];
    assert_eq!(events, expected);

    let state_path = runtime_root.join("state").join("gsama_state.json");
    assert!(!state_path.exists());
}
