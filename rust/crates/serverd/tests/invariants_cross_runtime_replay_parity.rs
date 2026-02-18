use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

fn run_serverd_null(runtime_root: &Path, delta: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("--mode")
        .arg("null")
        .arg("--ticks")
        .arg("1")
        .arg("--delta")
        .arg(delta)
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run serverd")
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
        .expect("failed to run replay")
}

fn write_initial_state(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
}

fn read_event_payloads(runtime_root: &Path) -> Vec<serde_json::Value> {
    common::read_event_payloads(runtime_root)
}

fn find_event(events: &[serde_json::Value], event_type: &str) -> serde_json::Value {
    common::find_event(events, event_type)
}

fn artifact_path(runtime_root: &Path, subdir: &str, artifact_ref: &str) -> PathBuf {
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    runtime_root
        .join("artifacts")
        .join(subdir)
        .join(format!("{}.json", trimmed))
}

fn copy_file(src: &Path, dst: &Path) {
    let parent = dst.parent().expect("destination parent");
    fs::create_dir_all(parent).expect("create destination parent");
    let bytes = fs::read(src).expect("read source");
    fs::write(dst, bytes).expect("write destination");
}

#[test]
fn replay_parity_holds_across_distinct_runtime_roots() {
    let runtime_a =
        std::env::temp_dir().join(format!("pie_inv_replay_parity_a_{}", Uuid::new_v4()));
    let runtime_b =
        std::env::temp_dir().join(format!("pie_inv_replay_parity_b_{}", Uuid::new_v4()));
    write_initial_state(&runtime_a);
    write_initial_state(&runtime_b);

    let out_a = run_serverd_null(&runtime_a, "tick:1");
    assert!(
        out_a.status.success(),
        "source run failed: {}",
        String::from_utf8_lossy(&out_a.stderr)
    );
    let run_a: serde_json::Value = serde_json::from_slice(&out_a.stdout).expect("run_a json");
    let state_hash_a = run_a
        .get("state_hash")
        .and_then(|v| v.as_str())
        .expect("missing run_a.state_hash")
        .to_string();
    let task_request = run_a
        .get("task_request")
        .cloned()
        .expect("missing run_a.task_request");
    let task_id = task_request
        .get("task_id")
        .and_then(|v| v.as_str())
        .expect("missing task_request.task_id");

    let task_a = runtime_a.join("tasks").join(format!("{}.json", task_id));
    let status_a = runtime_a
        .join("tasks")
        .join(format!("{}.status.json", task_id));
    assert!(task_a.is_file(), "source task file missing");
    assert!(status_a.is_file(), "source task status file missing");

    let task_b = runtime_b.join("tasks").join(format!("{}.json", task_id));
    let status_b = runtime_b
        .join("tasks")
        .join(format!("{}.status.json", task_id));
    copy_file(&task_a, &task_b);
    copy_file(&status_a, &status_b);

    let events_a = read_event_payloads(&runtime_a);
    let state_delta_written = find_event(&events_a, "state_delta_artifact_written");
    let delta_ref = state_delta_written
        .get("delta_ref")
        .and_then(|v| v.as_str())
        .expect("missing delta_ref");
    let delta_src = artifact_path(&runtime_a, "state_deltas", delta_ref);
    let delta_dst = artifact_path(&runtime_b, "state_deltas", delta_ref);
    copy_file(&delta_src, &delta_dst);

    let out_replay = run_replay(&runtime_b, task_id);
    assert!(
        out_replay.status.success(),
        "replay failed: {}",
        String::from_utf8_lossy(&out_replay.stderr)
    );
    let replay_value: serde_json::Value =
        serde_json::from_slice(&out_replay.stdout).expect("replay output json");
    assert_eq!(replay_value.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        replay_value.get("task_id").and_then(|v| v.as_str()),
        Some(task_id)
    );

    let status_b_value: serde_json::Value =
        serde_json::from_slice(&fs::read(&status_b).expect("read status_b"))
            .expect("status_b json");
    assert_eq!(
        status_b_value.get("status").and_then(|v| v.as_str()),
        Some("applied")
    );
    let state_hash_b = status_b_value
        .get("last_hash")
        .and_then(|v| v.as_str())
        .expect("missing status_b.last_hash");
    assert_eq!(state_hash_b, state_hash_a);

    let events_b = read_event_payloads(&runtime_b);
    let completed_b = find_event(&events_b, "run_completed");
    assert_eq!(
        completed_b.get("final_state_hash").and_then(|v| v.as_str()),
        Some(state_hash_a.as_str())
    );
}
