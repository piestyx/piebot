use pie_common::sha256_bytes;
use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

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

fn read_event_payloads(runtime_root: &Path) -> Vec<serde_json::Value> {
    common::read_event_payloads_stage15(runtime_root)
}

fn find_event(events: &[serde_json::Value], event_type: &str) -> serde_json::Value {
    common::find_event(events, event_type)
}

#[test]
fn capsule_export_writes_deterministic_output() {
    let runtime_root = std::env::temp_dir().join(format!("pie_stage15_export_{}", Uuid::new_v4()));
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
    let capsule_event = find_event(&events, "run_capsule_written");
    let capsule_ref = capsule_event
        .get("capsule_ref")
        .and_then(|v| v.as_str())
        .expect("missing capsule_ref");

    let out_export = Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("capsule")
        .arg("export")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--run-id")
        .arg(run_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run capsule export");
    assert!(
        out_export.status.success(),
        "export failed: {}",
        String::from_utf8_lossy(&out_export.stderr)
    );
    let export_value: serde_json::Value =
        serde_json::from_slice(&out_export.stdout).expect("export output not json");
    assert_eq!(export_value.get("ok").and_then(|v| v.as_bool()), Some(true));
    let export_path = export_value
        .get("export_path")
        .and_then(|v| v.as_str())
        .expect("missing export_path");
    let export_hash = export_value
        .get("export_hash")
        .and_then(|v| v.as_str())
        .expect("missing export_hash");

    let trimmed = capsule_ref.strip_prefix("sha256:").unwrap_or(capsule_ref);
    let expected_rel = format!("exports/capsule_{}.json", trimmed);
    assert_eq!(export_path, expected_rel);

    let export_abs = runtime_root.join(export_path);
    let exported_bytes = fs::read(&export_abs).expect("exported file missing");
    let capsule_path = runtime_root
        .join("artifacts")
        .join("run_capsules")
        .join(format!("{}.json", trimmed));
    let capsule_bytes = fs::read(&capsule_path).expect("capsule artifact missing");
    assert_eq!(exported_bytes, capsule_bytes);
    let expected_hash = sha256_bytes(&capsule_bytes);
    assert_eq!(export_hash, expected_hash.as_str());

    let out_export_again = Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("capsule")
        .arg("export")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--run-id")
        .arg(run_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run capsule export");
    assert!(out_export_again.status.success());
    let exported_again = fs::read(&export_abs).expect("exported file missing");
    assert_eq!(exported_again, capsule_bytes);
}
