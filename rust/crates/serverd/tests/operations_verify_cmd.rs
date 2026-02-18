use std::fs;
use std::path::Path;
use std::process::Command;
use uuid::Uuid;

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

#[test]
fn verify_command_success() {
    let runtime_root = std::env::temp_dir().join(format!("pie_serverd_verify_{}", Uuid::new_v4()));
    let runtime_str = runtime_root.to_string_lossy().to_string();

    let out_run = Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("--mode")
        .arg("null")
        .arg("--ticks")
        .arg("1")
        .arg("--delta")
        .arg("tick:0")
        .arg("--runtime")
        .arg(&runtime_str)
        .output()
        .expect("failed to run serverd");
    assert!(
        out_run.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out_run.stderr)
    );

    let out_verify = Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("verify")
        .arg("--memory")
        .arg("--runtime")
        .arg(&runtime_str)
        .output()
        .expect("failed to run serverd verify");
    assert!(
        out_verify.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&out_verify.stderr)
    );

    let v: serde_json::Value =
        serde_json::from_slice(&out_verify.stdout).expect("verify output not json");
    assert_eq!(v.get("ok").and_then(|v| v.as_bool()), Some(true));
    let last_hash = v
        .get("last_hash")
        .and_then(|v| v.as_str())
        .expect("missing last_hash");
    assert!(last_hash.starts_with("sha256:"));
}

#[test]
fn verify_command_accepts_prefixed_sha256_run_id() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_serverd_verify_prefixed_{}", Uuid::new_v4()));
    let runtime_str = runtime_root.to_string_lossy().to_string();

    let out_run = Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("--mode")
        .arg("null")
        .arg("--ticks")
        .arg("1")
        .arg("--delta")
        .arg("tick:0")
        .arg("--runtime")
        .arg(&runtime_str)
        .output()
        .expect("failed to run serverd");
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
    assert!(run_id.starts_with("sha256:"));
    let suffix = run_id
        .strip_prefix("sha256:")
        .expect("missing sha256 prefix");
    assert_eq!(suffix.len(), 64);
    assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
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
        .arg(&runtime_str)
        .arg("--run-id")
        .arg(run_id)
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
    assert_eq!(
        verify_value
            .get("final_state_hash")
            .and_then(|v| v.as_str()),
        Some(completed_final_state.as_str())
    );
}

#[test]
fn verify_command_missing_log_fails() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_serverd_verify_missing_{}", Uuid::new_v4()));
    let runtime_str = runtime_root.to_string_lossy().to_string();

    let out_verify = Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("verify")
        .arg("--runtime")
        .arg(&runtime_str)
        .output()
        .expect("failed to run serverd verify");
    assert!(!out_verify.status.success());

    let v: serde_json::Value =
        serde_json::from_slice(&out_verify.stdout).expect("verify output not json");
    assert_eq!(v.get("ok").and_then(|v| v.as_bool()), Some(false));
    let err = v.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(err.contains("not found"));
}
