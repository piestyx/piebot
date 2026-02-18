use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

fn run_serverd(runtime_root: &Path, ticks: u64, delta: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("--mode")
        .arg("route")
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

fn write_initial_state(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
}

fn write_router_config(runtime_root: &Path, value: serde_json::Value) {
    let dir = runtime_root.join("router");
    fs::create_dir_all(&dir).expect("create router dir");
    let bytes = serde_json::to_vec(&value).expect("serialize config");
    fs::write(dir.join("config.json"), bytes).expect("write config");
}

fn read_event_payloads(runtime_root: &Path) -> Vec<serde_json::Value> {
    common::read_event_payloads(runtime_root)
}

fn read_event_types(runtime_root: &Path) -> Vec<String> {
    read_event_payloads(runtime_root)
        .iter()
        .map(|event| {
            event
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string()
        })
        .collect()
}

fn positions(events: &[String], kind: &str) -> Vec<usize> {
    events
        .iter()
        .enumerate()
        .filter_map(|(idx, event)| if event == kind { Some(idx) } else { None })
        .collect()
}

fn find_artifact_ref(events: &[serde_json::Value], event_type: &str) -> String {
    for event in events {
        if event.get("event_type").and_then(|v| v.as_str()) == Some(event_type) {
            return event
                .get("artifact_ref")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
        }
    }
    panic!("missing {}", event_type);
}

fn artifact_path(runtime_root: &Path, subdir: &str, artifact_ref: &str) -> PathBuf {
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    runtime_root
        .join("artifacts")
        .join(subdir)
        .join(format!("{}.json", trimmed))
}

#[test]
fn route_mode_emits_route_selected_and_provider_events() {
    let runtime_root = std::env::temp_dir().join(format!("pie_stage3_events_{}", Uuid::new_v4()));
    let out = run_serverd(&runtime_root, 1, "tick:0");
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let events = read_event_types(&runtime_root);
    let intent_idx = positions(&events, "intent_selected");
    let route_idx = positions(&events, "route_selected");
    let req_idx = positions(&events, "provider_request_written");
    let resp_idx = positions(&events, "provider_response_written");
    let delta_idx = positions(&events, "state_delta_proposed");

    assert_eq!(intent_idx.len(), 1);
    assert_eq!(route_idx.len(), 1);
    assert_eq!(req_idx.len(), 1);
    assert_eq!(resp_idx.len(), 1);
    assert_eq!(delta_idx.len(), 1);

    assert!(intent_idx[0] < route_idx[0]);
    assert!(route_idx[0] < req_idx[0]);
    assert!(req_idx[0] < resp_idx[0]);
    assert!(resp_idx[0] < delta_idx[0]);
}

#[test]
fn router_deterministic_across_runtimes() {
    let runtime_one = std::env::temp_dir().join(format!("pie_stage3_det_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_stage3_det_two_{}", Uuid::new_v4()));
    write_initial_state(&runtime_one);
    write_initial_state(&runtime_two);

    let out_one = run_serverd(&runtime_one, 1, "tick:0");
    let out_two = run_serverd(&runtime_two, 1, "tick:0");
    assert!(
        out_one.status.success(),
        "run one failed: {}",
        String::from_utf8_lossy(&out_one.stderr)
    );
    assert!(
        out_two.status.success(),
        "run two failed: {}",
        String::from_utf8_lossy(&out_two.stderr)
    );

    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let types_one = read_event_types(&runtime_one);
    let types_two = read_event_types(&runtime_two);
    assert_eq!(types_one, types_two);

    let req_ref_one = find_artifact_ref(&events_one, "provider_request_written");
    let req_ref_two = find_artifact_ref(&events_two, "provider_request_written");
    let resp_ref_one = find_artifact_ref(&events_one, "provider_response_written");
    let resp_ref_two = find_artifact_ref(&events_two, "provider_response_written");

    let req_bytes_one =
        fs::read(artifact_path(&runtime_one, "requests", &req_ref_one)).expect("read request one");
    let req_bytes_two =
        fs::read(artifact_path(&runtime_two, "requests", &req_ref_two)).expect("read request two");
    assert_eq!(req_bytes_one, req_bytes_two);

    let resp_bytes_one = fs::read(artifact_path(&runtime_one, "responses", &resp_ref_one))
        .expect("read response one");
    let resp_bytes_two = fs::read(artifact_path(&runtime_two, "responses", &resp_ref_two))
        .expect("read response two");
    assert_eq!(resp_bytes_one, resp_bytes_two);
}

#[test]
fn provider_failure_fails_closed() {
    let runtime_root = std::env::temp_dir().join(format!("pie_stage3_fail_{}", Uuid::new_v4()));
    write_router_config(
        &runtime_root,
        serde_json::json!({
            "schema": "serverd.router.v1",
            "default_provider": "missing",
            "routes": [],
            "policy": { "fail_if_unavailable": true }
        }),
    );
    let out = run_serverd(&runtime_root, 1, "tick:0");
    assert!(!out.status.success(), "run should fail");

    let events = read_event_types(&runtime_root);
    assert_eq!(
        events,
        vec![
            "run_started",
            "workspace_policy_loaded",
            "provider_failed",
            "run_completed"
        ]
    );
}
