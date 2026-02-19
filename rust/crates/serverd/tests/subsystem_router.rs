use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

fn run_serverd_with(
    runtime_root: &Path,
    ticks: u64,
    delta: &str,
    provider_mode: Option<&str>,
    envs: &[(&str, &str)],
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_serverd"));
    command
        .arg("--mode")
        .arg("route")
        .arg("--ticks")
        .arg(ticks.to_string())
        .arg("--delta")
        .arg(delta)
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(provider_mode) = provider_mode {
        command.arg("--provider").arg(provider_mode);
    }
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().expect("failed to run serverd")
}

fn run_serverd(runtime_root: &Path, ticks: u64, delta: &str) -> Output {
    run_serverd_with(runtime_root, ticks, delta, None, &[])
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

fn parse_state_hash(output: &Output) -> String {
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("run output json");
    value
        .get("state_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
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
            "provider_mode_selected",
            "workspace_policy_loaded",
            "provider_failed",
            "run_completed"
        ]
    );
}

#[test]
fn provider_replay_refuses_without_artifact() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage3_replay_missing_{}", Uuid::new_v4()));
    let out = run_serverd_with(&runtime_root, 1, "tick:0", Some("replay"), &[]);
    assert!(!out.status.success(), "run should fail");

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("provider_replay_missing_artifact")
    );
    let events = read_event_types(&runtime_root);
    assert!(events
        .iter()
        .any(|e| e == "provider_replay_missing_artifact"));
    assert!(!events.iter().any(|e| e == "provider_response_written"));
}

#[test]
fn provider_live_writes_artifact_then_replay_loads_without_provider_call() {
    let runtime_live =
        std::env::temp_dir().join(format!("pie_stage3_live_only_{}", Uuid::new_v4()));
    let out_live = run_serverd_with(&runtime_live, 1, "tick:0", Some("live"), &[]);
    assert!(
        out_live.status.success(),
        "live run failed: {}",
        String::from_utf8_lossy(&out_live.stderr)
    );
    let live_state_hash = parse_state_hash(&out_live);
    assert!(!live_state_hash.is_empty());
    let events_live = read_event_payloads(&runtime_live);
    let events_live_types = read_event_types(&runtime_live);
    let request_hash = events_live
        .iter()
        .find_map(|event| {
            if event.get("event_type").and_then(|v| v.as_str()) == Some("provider_request_written")
            {
                event
                    .get("request_hash")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string())
            } else {
                None
            }
        })
        .expect("request_hash from live run");
    let artifact = artifact_path(&runtime_live, "provider_responses", &request_hash);
    assert!(artifact.is_file(), "provider response artifact missing");
    let runtime_probe =
        std::env::temp_dir().join(format!("pie_stage3_replay_probe_{}", Uuid::new_v4()));
    let out_missing = run_serverd_with(&runtime_probe, 1, "tick:0", Some("replay"), &[]);
    assert!(
        !out_missing.status.success(),
        "replay should fail without artifact"
    );
    let replay_events = read_event_payloads(&runtime_probe);
    let replay_request_hash = replay_events
        .iter()
        .find_map(|event| {
            if event.get("event_type").and_then(|v| v.as_str())
                == Some("provider_replay_missing_artifact")
            {
                event
                    .get("request_hash")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string())
            } else {
                None
            }
        })
        .expect("request_hash from replay missing event");

    let response_value = serde_json::json!({
        "schema": "serverd.provider_response.v1",
        "request_hash": replay_request_hash,
        "model": "mock",
        "output": {
            "schema": "serverd.provider_output.v1",
            "output": "null"
        }
    });
    let response_hash = {
        let bytes = pie_common::canonical_json_bytes(&response_value).expect("canonical response");
        pie_common::sha256_bytes(&bytes)
    };
    let artifact_value = serde_json::json!({
        "schema": "serverd.provider_response_artifact.v1",
        "request_hash": replay_request_hash,
        "provider_id": "mock",
        "response": response_value,
        "response_hash": response_hash,
        "created_from_run_id": "sha256:test",
        "created_from_tick_index": 0
    });
    let runtime_replay =
        std::env::temp_dir().join(format!("pie_stage3_replay_only_{}", Uuid::new_v4()));
    let replay_artifact =
        artifact_path(&runtime_replay, "provider_responses", &replay_request_hash);
    std::fs::create_dir_all(
        replay_artifact
            .parent()
            .expect("replay provider_responses parent"),
    )
    .expect("create replay provider_responses dir");
    std::fs::write(
        replay_artifact,
        serde_json::to_vec(&artifact_value).expect("serialize replay artifact"),
    )
    .expect("write replay provider response artifact");

    let out_replay = run_serverd_with(
        &runtime_replay,
        1,
        "tick:0",
        Some("replay"),
        &[("MOCK_PROVIDER_PANIC_IF_CALLED", "1")],
    );
    assert!(
        out_replay.status.success(),
        "replay run failed: {}",
        String::from_utf8_lossy(&out_replay.stderr)
    );
    let replay_state_hash = parse_state_hash(&out_replay);
    assert_eq!(live_state_hash, replay_state_hash);
    assert!(events_live_types
        .iter()
        .any(|e| e == "provider_response_artifact_written"));
    let replay_events_types = read_event_types(&runtime_replay);
    assert!(replay_events_types
        .iter()
        .any(|e| e == "provider_response_artifact_loaded"));
}
