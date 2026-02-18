#![cfg(feature = "bin")]

use pie_kernel_state::{save, KernelState};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;
mod common;

fn run_serverd(
    runtime: Option<&Path>,
    ticks: u64,
    delta: &str,
    current_dir: Option<&Path>,
    env_runtime_root: Option<&Path>,
) -> std::process::Output {
    let mut cmd = Command::new(common::serverd_exe());
    cmd.arg("--mode").arg("null");
    cmd.arg("--ticks").arg(ticks.to_string());
    cmd.arg("--delta").arg(delta);
    if let Some(runtime) = runtime {
        cmd.arg("--runtime")
            .arg(runtime.to_string_lossy().to_string());
    }
    if let Some(env_root) = env_runtime_root {
        cmd.env("PIE_RUNTIME_ROOT", env_root.to_string_lossy().to_string());
    }
    if let Some(dir) = current_dir {
        cmd.current_dir(dir);
    }
    cmd.output().expect("failed to run serverd")
}
fn write_initial_state(runtime_root: &Path) {
    let state_path = runtime_root.join("state").join("gsama_state.json");
    let mut state = KernelState::default();
    state.state_id = Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap();
    save(&state_path, &state).expect("failed to write initial state");
}

fn read_event_envelopes(audit_path: &Path) -> Vec<serde_json::Value> {
    let contents = fs::read_to_string(audit_path).expect("failed to read audit log");
    let mut events = Vec::new();

    for (i, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line {}: {}", i + 1, e));
        let event = record
            .get("event")
            .unwrap_or_else(|| panic!("line {} missing event", i + 1))
            .clone();
        events.push(event);
    }

    events
}

fn read_event_types(audit_path: &Path) -> Vec<String> {
    read_event_envelopes(audit_path)
        .iter()
        .map(|event| {
            let inner = event
                .get("event")
                .unwrap_or_else(|| panic!("missing inner event"));
            inner
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string()
        })
        .collect()
}

fn read_output_json(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("failed to parse output JSON")
}

fn find_next_event(events: &[String], event_type: &str, start: usize) -> usize {
    events
        .iter()
        .skip(start)
        .position(|event| event == event_type)
        .map(|idx| idx + start)
        .unwrap_or_else(|| panic!("missing {} after index {}", event_type, start))
}

fn assert_stage2_events_within_windows(events: &[String], windows: &[(usize, usize)]) {
    for (idx, event) in events.iter().enumerate() {
        if matches!(
            event.as_str(),
            "episode_appended" | "working_memory_updated" | "open_memory_mirror_written"
        ) {
            let in_window = windows
                .iter()
                .any(|(start, end)| idx > *start && idx < *end);
            assert!(
                in_window,
                "stage2 event {} at {} is outside allowed window",
                event, idx
            );
        }
    }
}

fn assert_task_queue_scanned_before_observation(
    events: &[String],
    ticks: &[(usize, usize, usize)],
    run_started_idx: usize,
) {
    for (tick_idx, (observation_idx, _delta_applied_idx, tick_completed_idx)) in
        ticks.iter().enumerate()
    {
        let segment_start = if tick_idx == 0 {
            run_started_idx + 1
        } else {
            ticks[tick_idx - 1].2 + 1
        };
        for idx in segment_start..*tick_completed_idx {
            if events[idx] == "task_queue_scanned" {
                assert!(
                    idx < *observation_idx,
                    "task_queue_scanned at {} must be before observation_captured at {}",
                    idx,
                    observation_idx
                );
            }
        }
    }
}

fn read_state_delta_applied_hashes(runtime_root: &Path) -> Vec<String> {
    let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
    let events = read_event_envelopes(&audit_path);
    events
        .iter()
        .filter_map(|event| {
            let inner = event.get("event")?;
            let event_type = inner.get("event_type")?.as_str()?;
            if event_type != "state_delta_applied" {
                return None;
            }
            inner
                .get("next_state_hash")?
                .as_str()
                .map(|s| s.to_string())
        })
        .collect()
}

#[test]
fn deterministic_state_hashes_match_across_runs() {
    let runtime_one = std::env::temp_dir().join(format!("pie_serverd_run1_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_serverd_run2_{}", Uuid::new_v4()));
    let env_runtime = std::env::temp_dir().join(format!("pie_serverd_env_{}", Uuid::new_v4()));
    write_initial_state(&runtime_one);
    write_initial_state(&runtime_two);
    let out_one = run_serverd(Some(&runtime_one), 2, "tick:1", None, Some(&env_runtime));
    assert!(
        out_one.status.success(),
        "first run failed: {}",
        String::from_utf8_lossy(&out_one.stderr)
    );
    let out_two = run_serverd(Some(&runtime_two), 2, "tick:1", None, Some(&env_runtime));
    assert!(
        out_two.status.success(),
        "second run failed: {}",
        String::from_utf8_lossy(&out_two.stderr)
    );

    let hashes_one = read_state_delta_applied_hashes(&runtime_one);
    let hashes_two = read_state_delta_applied_hashes(&runtime_two);
    assert_eq!(hashes_one, hashes_two);
}

#[test]
fn audit_event_ordering_matches_stage1_spec() {
    let runtime_root = std::env::temp_dir().join(format!("pie_serverd_order_{}", Uuid::new_v4()));
    let env_runtime = std::env::temp_dir().join(format!("pie_serverd_env_{}", Uuid::new_v4()));
    let out = run_serverd(Some(&runtime_root), 2, "tick:1", None, Some(&env_runtime));
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
    let events = read_event_types(&audit_path);
    let mut cursor = 0;
    let run_started_idx = find_next_event(&events, "run_started", cursor);
    cursor = run_started_idx + 1;

    let mut tick_bounds = Vec::new();
    for _ in 0..2 {
        let observation_idx = find_next_event(&events, "observation_captured", cursor);
        let state_snapshot_idx =
            find_next_event(&events, "state_snapshot_loaded", observation_idx + 1);
        let intent_selected_idx =
            find_next_event(&events, "intent_selected", state_snapshot_idx + 1);
        let state_delta_proposed_idx =
            find_next_event(&events, "state_delta_proposed", intent_selected_idx + 1);
        let state_delta_applied_idx =
            find_next_event(&events, "state_delta_applied", state_delta_proposed_idx + 1);
        let tick_completed_idx =
            find_next_event(&events, "tick_completed", state_delta_applied_idx + 1);
        tick_bounds.push((observation_idx, state_delta_applied_idx, tick_completed_idx));
        cursor = tick_completed_idx + 1;
    }
    let capsule_idx = find_next_event(&events, "run_capsule_written", cursor);
    let _run_completed_idx = find_next_event(&events, "run_completed", capsule_idx + 1);

    let windows: Vec<(usize, usize)> = tick_bounds
        .iter()
        .map(|(_, state_delta_applied_idx, tick_completed_idx)| {
            (*state_delta_applied_idx, *tick_completed_idx)
        })
        .collect();
    assert_stage2_events_within_windows(&events, &windows);
    assert_task_queue_scanned_before_observation(&events, &tick_bounds, run_started_idx);
}

#[test]
fn task_request_is_deterministic_and_has_no_wall_time() {
    let runtime_one = std::env::temp_dir().join(format!("pie_serverd_req1_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_serverd_req2_{}", Uuid::new_v4()));
    write_initial_state(&runtime_one);
    write_initial_state(&runtime_two);
    let out_one = run_serverd(Some(&runtime_one), 1, "tick:0", None, None);
    let out_two = run_serverd(Some(&runtime_two), 1, "tick:0", None, None);
    assert!(out_one.status.success(), "run one failed");
    assert!(out_two.status.success(), "run two failed");

    let json_one = read_output_json(&out_one);
    let json_two = read_output_json(&out_two);
    let req_one = json_one.get("task_request").expect("missing task_request");
    let req_two = json_two.get("task_request").expect("missing task_request");

    let hash_one = req_one
        .get("request_hash")
        .and_then(|v| v.as_str())
        .expect("missing request_hash");
    let hash_two = req_two
        .get("request_hash")
        .and_then(|v| v.as_str())
        .expect("missing request_hash");
    assert_eq!(hash_one, hash_two);

    let requested_tick = req_one
        .get("requested_tick")
        .and_then(|v| v.as_u64())
        .expect("missing requested_tick");
    assert_eq!(requested_tick, 0);
}

#[test]
fn intent_selected_includes_request_hash_and_intent() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_serverd_req_audit_{}", Uuid::new_v4()));
    let out = run_serverd(Some(&runtime_root), 1, "tick:0", None, None);
    assert!(out.status.success(), "run failed");

    let output_json = read_output_json(&out);
    let request_hash = output_json
        .get("task_request")
        .and_then(|v| v.get("request_hash"))
        .and_then(|v| v.as_str())
        .expect("missing task_request.request_hash");

    let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
    let events = read_event_envelopes(&audit_path);
    let mut found = false;
    for event in events {
        let inner = event.get("event").expect("missing inner event");
        let event_type = inner
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if event_type == "intent_selected" {
            let intent_kind = inner
                .get("intent")
                .and_then(|v| v.get("kind"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            assert_eq!(intent_kind, "no_op");
            let event_request_hash = inner
                .get("request_hash")
                .and_then(|v| v.as_str())
                .expect("missing request_hash on intent_selected");
            assert_eq!(event_request_hash, request_hash);
            found = true;
        }
    }
    assert!(found, "intent_selected event not found");
}

#[test]
fn audit_event_includes_schema() {
    let runtime_root = std::env::temp_dir().join(format!("pie_serverd_schema_{}", Uuid::new_v4()));
    let env_runtime = std::env::temp_dir().join(format!("pie_serverd_env_{}", Uuid::new_v4()));
    let out = run_serverd(Some(&runtime_root), 1, "tick:0", None, Some(&env_runtime));
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
    let events = read_event_envelopes(&audit_path);
    let first = events.first().expect("missing events");
    let schema = first
        .get("schema")
        .and_then(|v| v.as_str())
        .expect("missing schema");
    assert_eq!(schema, "serverd.audit.v1");
}

#[test]
fn runtime_root_defaults_to_env_override_and_audit_path_is_normalized() {
    let runtime_root = std::env::temp_dir().join(format!("pie_serverd_env_{}", Uuid::new_v4()));
    let out = run_serverd(None, 1, "tick:0", None, Some(&runtime_root));
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let output_json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("failed to parse output JSON");
    let audit_path_str = output_json
        .get("audit_path")
        .and_then(|v| v.as_str())
        .expect("missing audit_path");

    assert!(!audit_path_str.contains("/../"));
    assert!(!audit_path_str.contains("\\..\\"));

    let audit_path = PathBuf::from(audit_path_str);
    let expected_audit_path = runtime_root.join("logs").join("audit_rust.jsonl");

    let actual = audit_path
        .canonicalize()
        .expect("failed to canonicalize audit_path");
    let expected = expected_audit_path
        .canonicalize()
        .expect("failed to canonicalize expected audit_path");

    assert_eq!(actual, expected);
}
