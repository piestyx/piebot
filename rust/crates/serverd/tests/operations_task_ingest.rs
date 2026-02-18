#![cfg(feature = "bin")]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

const MAX_TASK_BYTES: usize = 1024 * 1024;

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

fn run_ingest_file(runtime_root: &Path, input_path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("ingest")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--in")
        .arg(input_path.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run serverd ingest")
}

fn run_serverd(runtime_root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("--mode")
        .arg("null")
        .arg("--ticks")
        .arg("1")
        .arg("--delta")
        .arg("tick:0")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
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

fn assert_stage1_core_order(events: &[String]) -> (usize, usize, usize, usize) {
    let mut cursor = 0;
    let run_started_idx = find_next_event(events, "run_started", cursor);
    cursor = run_started_idx + 1;
    let observation_idx = find_next_event(events, "observation_captured", cursor);
    let state_snapshot_idx = find_next_event(events, "state_snapshot_loaded", observation_idx + 1);
    let intent_selected_idx = find_next_event(events, "intent_selected", state_snapshot_idx + 1);
    let state_delta_proposed_idx =
        find_next_event(events, "state_delta_proposed", intent_selected_idx + 1);
    let state_delta_applied_idx =
        find_next_event(events, "state_delta_applied", state_delta_proposed_idx + 1);
    let tick_completed_idx = find_next_event(events, "tick_completed", state_delta_applied_idx + 1);
    let capsule_idx = find_next_event(events, "run_capsule_written", tick_completed_idx + 1);
    let _run_completed_idx = find_next_event(events, "run_completed", capsule_idx + 1);
    (
        run_started_idx,
        observation_idx,
        state_delta_applied_idx,
        tick_completed_idx,
    )
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

fn assert_task_queue_scanned_before_observation(events: &[String], observation_idx: usize) {
    for (idx, event) in events.iter().enumerate() {
        if event == "task_queue_scanned" {
            assert!(
                idx < observation_idx,
                "task_queue_scanned at {} must be before observation_captured at {}",
                idx,
                observation_idx
            );
        }
    }
}

#[test]
fn accepts_valid_task_from_stdin() {
    let runtime_root = std::env::temp_dir().join(format!("pie_ingest_ok_{}", Uuid::new_v4()));
    let input =
        br#"{"task_id":"task-1","tick_index":7,"intent":{"kind":"no_op"},"meta":{"k":"v"}}"#;
    let out = run_ingest_stdin(&runtime_root, input);
    assert!(
        out.status.success(),
        "ingest failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let events = read_event_types(&runtime_root);
    let expected = vec![
        "run_started",
        "task_received",
        "task_accepted",
        "task_persisted",
        "task_enqueued",
        "run_capsule_written",
        "run_completed",
    ];
    assert_eq!(events, expected);

    let status_path = runtime_root.join("tasks").join("task-1.status.json");
    let status_bytes = fs::read(status_path).expect("missing task status file");
    let status: serde_json::Value =
        serde_json::from_slice(&status_bytes).expect("status file not json");
    assert_eq!(
        status.get("schema").and_then(|v| v.as_str()),
        Some("serverd.task_status.v1")
    );
    assert_eq!(
        status.get("task_id").and_then(|v| v.as_str()),
        Some("task-1")
    );
    assert_eq!(
        status.get("status").and_then(|v| v.as_str()),
        Some("pending")
    );

    let status_path = runtime_root.join("tasks").join("task-1.status.json");
    let status_bytes = fs::read(status_path).expect("missing task status file");
    let status: serde_json::Value =
        serde_json::from_slice(&status_bytes).expect("status file not json");
    assert_eq!(
        status.get("schema").and_then(|v| v.as_str()),
        Some("serverd.task_status.v1")
    );
    assert_eq!(
        status.get("task_id").and_then(|v| v.as_str()),
        Some("task-1")
    );
    assert_eq!(
        status.get("status").and_then(|v| v.as_str()),
        Some("pending")
    );
}

#[test]
fn rejects_unsafe_task_id() {
    let runtime_root = std::env::temp_dir().join(format!("pie_ingest_unsafe_{}", Uuid::new_v4()));
    let input = br#"{"task_id":"../pwn","tick_index":1,"intent":{"kind":"no_op"}}"#;
    let out = run_ingest_stdin(&runtime_root, input);
    assert!(!out.status.success());

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("ingest output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("task_id_unsafe")
    );

    let events = read_event_types(&runtime_root);
    let expected = vec![
        "run_started",
        "task_received",
        "task_rejected",
        "run_completed",
    ];
    assert_eq!(events, expected);
    assert!(!runtime_root.join("tasks").exists());
}

#[test]
fn rejects_multiple_sources() {
    let runtime_root = std::env::temp_dir().join(format!("pie_ingest_multi_{}", Uuid::new_v4()));
    let input_path =
        std::env::temp_dir().join(format!("pie_ingest_multi_input_{}.json", Uuid::new_v4()));
    fs::write(&input_path, b"{}").expect("failed to write input file");
    let out = Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("ingest")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--stdin")
        .arg("--in")
        .arg(input_path.to_string_lossy().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run serverd ingest");
    assert!(!out.status.success());
}

#[test]
fn rejects_unknown_flag() {
    let runtime_root = std::env::temp_dir().join(format!("pie_ingest_unknown_{}", Uuid::new_v4()));
    let out = Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("ingest")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--bogus")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run serverd ingest");
    assert!(!out.status.success());
}

#[test]
fn accepts_valid_task_from_file() {
    let runtime_root = std::env::temp_dir().join(format!("pie_ingest_file_{}", Uuid::new_v4()));
    let input_path = std::env::temp_dir().join(format!("pie_ingest_input_{}.json", Uuid::new_v4()));
    let input =
        br#"{"task_id":"task-1","tick_index":7,"intent":{"kind":"no_op"},"meta":{"k":"v"}}"#;
    fs::write(&input_path, input).expect("failed to write input file");
    let out = run_ingest_file(&runtime_root, &input_path);
    assert!(
        out.status.success(),
        "ingest failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let events = read_event_types(&runtime_root);
    let expected = vec![
        "run_started",
        "task_received",
        "task_accepted",
        "task_persisted",
        "task_enqueued",
        "run_capsule_written",
        "run_completed",
    ];
    assert_eq!(events, expected);
}

#[test]
fn rejects_invalid_json() {
    let runtime_root = std::env::temp_dir().join(format!("pie_ingest_bad_json_{}", Uuid::new_v4()));
    let out = run_ingest_stdin(&runtime_root, b"{");
    assert!(!out.status.success());

    let events = read_event_types(&runtime_root);
    let expected = vec![
        "run_started",
        "task_received",
        "task_rejected",
        "run_completed",
    ];
    assert_eq!(events, expected);
}

#[test]
fn rejects_missing_task_id() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_ingest_missing_id_{}", Uuid::new_v4()));
    let input = br#"{"tick_index":1,"intent":{"kind":"no_op"}}"#;
    let out = run_ingest_stdin(&runtime_root, input);
    assert!(!out.status.success());

    let events = read_event_types(&runtime_root);
    let expected = vec![
        "run_started",
        "task_received",
        "task_rejected",
        "run_completed",
    ];
    assert_eq!(events, expected);
}

#[test]
fn rejects_oversize_input() {
    let runtime_root = std::env::temp_dir().join(format!("pie_ingest_oversize_{}", Uuid::new_v4()));
    let input = vec![b'a'; MAX_TASK_BYTES + 1];
    let out = run_ingest_stdin(&runtime_root, &input);
    assert!(!out.status.success());

    let events = read_event_types(&runtime_root);
    let expected = vec![
        "run_started",
        "task_received",
        "task_rejected",
        "run_completed",
    ];
    assert_eq!(events, expected);
}

#[test]
fn ingest_does_not_change_run_command_behavior() {
    let runtime_root = std::env::temp_dir().join(format!("pie_ingest_run_{}", Uuid::new_v4()));
    let out = run_serverd(&runtime_root);
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let events = read_event_types(&runtime_root);
    let (_run_started_idx, observation_idx, state_delta_applied_idx, tick_completed_idx) =
        assert_stage1_core_order(&events);
    assert_task_queue_scanned_before_observation(&events, observation_idx);
    assert_stage2_events_within_window(&events, state_delta_applied_idx, tick_completed_idx);
}
