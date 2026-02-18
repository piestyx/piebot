#![cfg(feature = "bin")]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

fn read_event_payloads(runtime_root: &Path) -> Vec<serde_json::Value> {
    let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
    let contents = fs::read_to_string(&audit_path).expect("failed to read audit log");
    let mut events = Vec::new();
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
        events.push(inner.clone());
    }
    events
}

fn find_event(events: &[serde_json::Value], event_type: &str) -> serde_json::Value {
    for event in events {
        if event
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            == event_type
        {
            return event.clone();
        }
    }
    panic!("missing {}", event_type);
}

fn run_serverd_null(runtime_root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("--mode")
        .arg("null")
        .arg("--ticks")
        .arg("1")
        .arg("--delta")
        .arg("tick:0")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run serverd")
}

fn run_serverd_delta_tick_one(runtime_root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("--delta")
        .arg("tick:1")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run serverd")
}

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

#[test]
fn verify_with_run_id_returns_final_state_hash() {
    let runtime_root = std::env::temp_dir().join(format!("pie_stage15_verify_{}", Uuid::new_v4()));
    let out_run = run_serverd_null(&runtime_root);
    assert!(
        out_run.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out_run.stderr)
    );
    let run_value: serde_json::Value =
        serde_json::from_slice(&out_run.stdout).expect("run output not json");
    let run_id = run_value
        .get("run_id")
        .and_then(|v| v.as_str())
        .expect("missing run_id");
    let events = read_event_payloads(&runtime_root);
    let run_started = find_event(&events, "run_started");
    let run_completed = find_event(&events, "run_completed");
    assert_eq!(
        run_started.get("run_id").and_then(|v| v.as_str()),
        Some(run_id)
    );
    assert_eq!(
        run_completed.get("run_id").and_then(|v| v.as_str()),
        Some(run_id)
    );
    let completed_final_state = run_completed
        .get("final_state_hash")
        .and_then(|v| v.as_str())
        .expect("missing run_completed.final_state_hash")
        .to_string();

    let out_verify = Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("verify")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--run-id")
        .arg(run_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run serverd verify");
    assert!(
        out_verify.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&out_verify.stderr)
    );
    let verify_value: serde_json::Value =
        serde_json::from_slice(&out_verify.stdout).expect("verify output not json");
    assert_eq!(verify_value.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        verify_value.get("run_id").and_then(|v| v.as_str()),
        Some(run_id)
    );
    let final_state = verify_value
        .get("final_state_hash")
        .and_then(|v| v.as_str())
        .expect("missing final_state_hash");
    assert_eq!(final_state, completed_final_state.as_str());
    assert!(final_state.starts_with("sha256:"));
}

#[test]
fn replay_trigger_returns_ok() {
    let runtime_root = std::env::temp_dir().join(format!("pie_stage15_replay_{}", Uuid::new_v4()));
    let input = br#"{"task_id":"task-15","tick_index":1,"intent":{"kind":"no_op"}}"#;
    let out_ingest = run_ingest_stdin(&runtime_root, input);
    assert!(
        out_ingest.status.success(),
        "ingest failed: {}",
        String::from_utf8_lossy(&out_ingest.stderr)
    );

    let out_replay = run_replay(&runtime_root, "task-15");
    assert!(
        out_replay.status.success(),
        "replay failed: {}",
        String::from_utf8_lossy(&out_replay.stderr)
    );
    let replay_value: serde_json::Value =
        serde_json::from_slice(&out_replay.stdout).expect("replay output not json");
    assert_eq!(replay_value.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        replay_value.get("task_id").and_then(|v| v.as_str()),
        Some("task-15")
    );
}

#[test]
fn delta_run_persists_task_request_for_replay() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage15_delta_replay_{}", Uuid::new_v4()));
    let out_run = run_serverd_delta_tick_one(&runtime_root);
    assert!(
        out_run.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out_run.stderr)
    );
    let run_value: serde_json::Value =
        serde_json::from_slice(&out_run.stdout).expect("run output not json");
    let task_request = run_value
        .get("task_request")
        .cloned()
        .expect("missing task_request");
    let task_id = task_request
        .get("task_id")
        .and_then(|v| v.as_str())
        .expect("missing task_request.task_id");

    let task_path = runtime_root.join("tasks").join(format!("{}.json", task_id));
    assert!(task_path.is_file(), "missing persisted task file");
    let persisted_task: serde_json::Value =
        serde_json::from_slice(&fs::read(&task_path).expect("read task file"))
            .expect("task file is not json");
    assert_eq!(persisted_task, task_request);

    let out_replay = run_replay(&runtime_root, task_id);
    assert!(
        out_replay.status.success(),
        "replay failed: {}",
        String::from_utf8_lossy(&out_replay.stderr)
    );
    let replay_value: serde_json::Value =
        serde_json::from_slice(&out_replay.stdout).expect("replay output not json");
    assert_eq!(replay_value.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        replay_value.get("task_id").and_then(|v| v.as_str()),
        Some(task_id)
    );
}
