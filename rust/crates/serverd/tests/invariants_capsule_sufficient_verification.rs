use serverd::RUN_CAPSULE_SCHEMA;
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

fn run_verify_for_run(runtime_root: &Path, run_id: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("verify")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--run-id")
        .arg(run_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run verify")
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

fn assert_sha256_prefixed(value: &str, label: &str) {
    assert!(
        value.starts_with("sha256:"),
        "{} must be sha256: prefixed",
        label
    );
}

#[test]
fn run_capsule_final_state_is_consistent_with_verify_for_same_run() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_inv_capsule_verify_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);

    let out_run = run_serverd_null(&runtime_root, "tick:1");
    assert!(
        out_run.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out_run.stderr)
    );
    let run_value: serde_json::Value =
        serde_json::from_slice(&out_run.stdout).expect("run output json");
    let run_id = run_value
        .get("run_id")
        .and_then(|v| v.as_str())
        .expect("missing run_id");
    let run_state_hash = run_value
        .get("state_hash")
        .and_then(|v| v.as_str())
        .expect("missing state_hash");

    let events = read_event_payloads(&runtime_root);
    let capsule_written = find_event(&events, "run_capsule_written");
    let run_completed = find_event(&events, "run_completed");
    let capsule_ref = capsule_written
        .get("capsule_ref")
        .and_then(|v| v.as_str())
        .expect("missing capsule_ref");
    let capsule_bytes =
        fs::read(artifact_path(&runtime_root, "run_capsules", capsule_ref)).expect("read capsule");
    let capsule: serde_json::Value = serde_json::from_slice(&capsule_bytes).expect("capsule json");

    assert_eq!(
        capsule.get("schema").and_then(|v| v.as_str()),
        Some(RUN_CAPSULE_SCHEMA)
    );
    assert_eq!(
        capsule
            .get("run")
            .and_then(|v| v.get("run_id"))
            .and_then(|v| v.as_str()),
        Some(run_id)
    );
    assert_eq!(
        capsule
            .get("run")
            .and_then(|v| v.get("mode"))
            .and_then(|v| v.as_str()),
        Some("null")
    );
    let audit_head_hash = capsule
        .get("audit")
        .and_then(|v| v.get("audit_head_hash"))
        .and_then(|v| v.as_str())
        .expect("missing audit.audit_head_hash");
    assert_sha256_prefixed(audit_head_hash, "audit.audit_head_hash");

    let initial_state_hash = capsule
        .get("state")
        .and_then(|v| v.get("initial_state_hash"))
        .and_then(|v| v.as_str())
        .expect("missing state.initial_state_hash");
    let capsule_final_state_hash = capsule
        .get("state")
        .and_then(|v| v.get("final_state_hash"))
        .and_then(|v| v.as_str())
        .expect("missing state.final_state_hash");
    assert_sha256_prefixed(initial_state_hash, "state.initial_state_hash");
    assert_sha256_prefixed(capsule_final_state_hash, "state.final_state_hash");

    let state_delta_refs = capsule
        .get("state")
        .and_then(|v| v.get("state_delta_refs"))
        .and_then(|v| v.as_array())
        .expect("missing state.state_delta_refs");
    assert!(
        !state_delta_refs.is_empty(),
        "state_delta_refs must be present for tick:1 run"
    );

    assert_eq!(
        run_completed
            .get("final_state_hash")
            .and_then(|v| v.as_str()),
        Some(capsule_final_state_hash)
    );
    assert_eq!(run_state_hash, capsule_final_state_hash);

    let out_verify = run_verify_for_run(&runtime_root, run_id);
    assert!(
        out_verify.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&out_verify.stderr)
    );
    let verify_value: serde_json::Value =
        serde_json::from_slice(&out_verify.stdout).expect("verify output json");
    let verify_final_state_hash = verify_value
        .get("final_state_hash")
        .and_then(|v| v.as_str())
        .expect("missing verify.final_state_hash");
    assert_eq!(verify_value.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        verify_value.get("run_id").and_then(|v| v.as_str()),
        Some(run_id)
    );
    assert_eq!(verify_final_state_hash, capsule_final_state_hash);
}
