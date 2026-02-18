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

fn run_replay(runtime_root: &Path, task_id: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("replay")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--task")
        .arg(task_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run serverd replay")
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

fn read_state_delta_applied_hashes(runtime_root: &Path) -> Vec<String> {
    let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
    let contents = fs::read_to_string(audit_path).expect("failed to read audit log");
    let mut hashes = Vec::new();

    for (i, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line {}: {}", i + 1, e));
        let event = record
            .get("event")
            .unwrap_or_else(|| panic!("line {} missing event", i + 1));
        let inner = event
            .get("event")
            .unwrap_or_else(|| panic!("line {} missing inner event", i + 1));
        let event_type = inner
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if event_type == "state_delta_applied" {
            if let Some(h) = inner.get("next_state_hash").and_then(|v| v.as_str()) {
                hashes.push(h.to_string());
            }
        }
    }

    hashes
}

#[test]
fn replay_success_matches_ingest_state_hash() {
    let runtime_root = std::env::temp_dir().join(format!("pie_replay_ok_{}", Uuid::new_v4()));
    let input = br#"{"task_id":"task-1","tick_index":1,"intent":{"kind":"apply_delta","delta":{"kind":"tick_advance","by":1}}}"#;
    let out_ingest = run_ingest_stdin(&runtime_root, input);
    assert!(
        out_ingest.status.success(),
        "ingest failed: {}",
        String::from_utf8_lossy(&out_ingest.stderr)
    );

    let status_path = runtime_root.join("tasks").join("task-1.status.json");
    let status_bytes = fs::read(&status_path).expect("missing task status file");
    let status: serde_json::Value =
        serde_json::from_slice(&status_bytes).expect("status file not json");
    assert_eq!(
        status.get("status").and_then(|v| v.as_str()),
        Some("pending")
    );

    let out_replay = run_replay(&runtime_root, "task-1");
    assert!(
        out_replay.status.success(),
        "replay failed: {}",
        String::from_utf8_lossy(&out_replay.stderr)
    );

    let hashes_after_replay = read_state_delta_applied_hashes(&runtime_root);
    let replay_hash = hashes_after_replay
        .last()
        .expect("missing state_delta_applied hash after replay")
        .to_string();

    let status_bytes = fs::read(&status_path).expect("missing task status file");
    let status: serde_json::Value =
        serde_json::from_slice(&status_bytes).expect("status file not json");
    assert_eq!(
        status.get("status").and_then(|v| v.as_str()),
        Some("applied")
    );
    assert_eq!(
        status.get("last_hash").and_then(|v| v.as_str()),
        Some(replay_hash.as_str())
    );
}

#[test]
fn replay_missing_task_fails() {
    let runtime_root = std::env::temp_dir().join(format!("pie_replay_missing_{}", Uuid::new_v4()));
    let out = run_replay(&runtime_root, "missing-task");
    assert!(!out.status.success());

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("replay output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("task_not_found")
    );

    let events = read_event_types(&runtime_root);
    let expected = vec!["run_started", "task_replay_requested", "run_completed"];
    assert_eq!(events, expected);
}

#[test]
fn ingest_persists_task_file() {
    let runtime_root = std::env::temp_dir().join(format!("pie_replay_persist_{}", Uuid::new_v4()));
    let input = br#"{"task_id":"task-2","tick_index":1,"intent":{"kind":"no_op"}}"#;
    let out_ingest = run_ingest_stdin(&runtime_root, input);
    assert!(
        out_ingest.status.success(),
        "ingest failed: {}",
        String::from_utf8_lossy(&out_ingest.stderr)
    );

    let task_path = runtime_root.join("tasks").join("task-2.json");
    let bytes = fs::read(&task_path).expect("missing persisted task file");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("persisted task not json");
    assert_eq!(v.get("task_id").and_then(|v| v.as_str()), Some("task-2"));

    let status_path = runtime_root.join("tasks").join("task-2.status.json");
    let status_bytes = fs::read(&status_path).expect("missing task status file");
    let status: serde_json::Value =
        serde_json::from_slice(&status_bytes).expect("status file not json");
    assert_eq!(
        status.get("status").and_then(|v| v.as_str()),
        Some("pending")
    );
}

#[test]
fn replay_is_idempotent_when_already_applied() {
    let runtime_root = std::env::temp_dir().join(format!("pie_replay_idem_{}", Uuid::new_v4()));
    let input = br#"{"task_id":"task-3","tick_index":1,"intent":{"kind":"apply_delta","delta":{"kind":"tick_advance","by":1}}}"#;
    let out_ingest = run_ingest_stdin(&runtime_root, input);
    assert!(out_ingest.status.success());

    let out_replay = run_replay(&runtime_root, "task-3");
    assert!(out_replay.status.success());

    let status_path = runtime_root.join("tasks").join("task-3.status.json");
    let status_bytes = fs::read(&status_path).expect("missing task status file");
    let status: serde_json::Value =
        serde_json::from_slice(&status_bytes).expect("status file not json");
    let applied_hash = status
        .get("last_hash")
        .and_then(|v| v.as_str())
        .expect("missing last_hash")
        .to_string();

    let out_replay_again = run_replay(&runtime_root, "task-3");
    assert!(out_replay_again.status.success());

    let hashes_after = read_state_delta_applied_hashes(&runtime_root);
    let last_hash = hashes_after
        .last()
        .expect("missing state_delta_applied hash")
        .to_string();
    assert_eq!(last_hash, applied_hash);

    let events = read_event_types(&runtime_root);
    assert!(events.iter().any(|e| e == "task_already_applied"));
}
