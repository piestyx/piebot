#![cfg(feature = "bin")]

use serverd::lenses::LENS_CONFIG_SCHEMA;
use serverd::retrieval::RETRIEVAL_CONFIG_SCHEMA;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

const WORKING_SNAPSHOT_SCHEMA: &str = "serverd.working_memory.v1";

fn run_serverd_route(runtime_root: &Path, ticks: u64, delta: &str) -> Output {
    let mut cmd = Command::new(common::serverd_exe());
    cmd.arg("--mode")
        .arg("route")
        .arg("--ticks")
        .arg(ticks.to_string())
        .arg("--delta")
        .arg(delta)
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.output().expect("failed to run serverd")
}

fn write_initial_state(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
}

fn write_working_snapshot(runtime_root: &Path, tick_index: u64, entries: serde_json::Value) {
    let dir = runtime_root.join("memory");
    fs::create_dir_all(&dir).expect("create memory dir");
    let value = serde_json::json!({
        "schema": WORKING_SNAPSHOT_SCHEMA,
        "tick_index": tick_index,
        "entries": entries
    });
    let bytes = serde_json::to_vec(&value).expect("serialize working snapshot");
    fs::write(dir.join("working.json"), bytes).expect("write working snapshot");
}

fn write_retrieval_config(runtime_root: &Path, value: serde_json::Value) {
    let dir = runtime_root.join("retrieval");
    fs::create_dir_all(&dir).expect("create retrieval dir");
    let bytes = serde_json::to_vec(&value).expect("serialize retrieval config");
    fs::write(dir.join("config.json"), bytes).expect("write retrieval config");
}

fn write_lens_config(runtime_root: &Path, value: serde_json::Value) {
    let dir = runtime_root.join("lenses");
    fs::create_dir_all(&dir).expect("create lenses dir");
    let bytes = serde_json::to_vec(&value).expect("serialize lens config");
    fs::write(dir.join("config.json"), bytes).expect("write lens config");
}

fn retrieval_config_working(namespace: &str) -> serde_json::Value {
    serde_json::json!({
        "schema": RETRIEVAL_CONFIG_SCHEMA,
        "enabled": true,
        "sources": ["working"],
        "namespaces_allowlist": [namespace],
        "max_items": 32,
        "max_bytes": 65536,
        "default_recency_ticks": 64,
        "default_tags": []
    })
}

fn lens_config_all(max_output_bytes: u64, max_candidates: u64) -> serde_json::Value {
    serde_json::json!({
        "schema": LENS_CONFIG_SCHEMA,
        "enabled": true,
        "allowed_lenses": ["dedup_v1", "recency_v1", "salience_v1"],
        "max_output_bytes": max_output_bytes,
        "max_candidates": max_candidates,
        "recency_ticks": 8,
        "top_per_group": 2
    })
}

fn read_event_payloads(runtime_root: &Path) -> Vec<serde_json::Value> {
    common::read_event_payloads(runtime_root)
}

fn find_event(events: &[serde_json::Value], event_type: &str) -> serde_json::Value {
    common::find_event(events, event_type)
}

fn event_types(events: &[serde_json::Value]) -> Vec<String> {
    events
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

fn assert_before(types: &[String], first: &str, second: &str) {
    let first_idx = types
        .iter()
        .position(|v| v == first)
        .unwrap_or_else(|| panic!("missing {}", first));
    let second_idx = types
        .iter()
        .position(|v| v == second)
        .unwrap_or_else(|| panic!("missing {}", second));
    assert!(
        first_idx < second_idx,
        "{} must occur before {}",
        first,
        second
    );
}

fn artifact_path(runtime_root: &Path, subdir: &str, artifact_ref: &str) -> PathBuf {
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    runtime_root
        .join("artifacts")
        .join(subdir)
        .join(format!("{}.json", trimmed))
}

#[test]
fn lens_outputs_deterministic_across_two_runtimes() {
    let runtime_one = std::env::temp_dir().join(format!("pie_stage14_det_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_stage14_det_two_{}", Uuid::new_v4()));
    for runtime_root in [&runtime_one, &runtime_two] {
        write_initial_state(runtime_root);
        write_working_snapshot(
            runtime_root,
            3,
            serde_json::json!([
                {
                    "key": "k-b",
                    "value_ref": "contexts/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "last_touched_tick": 3
                },
                {
                    "key": "k-a",
                    "value_ref": "contexts/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "last_touched_tick": 2
                },
                {
                    "key": "k-a2",
                    "value_ref": "contexts/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "last_touched_tick": 2
                }
            ]),
        );
        write_retrieval_config(runtime_root, retrieval_config_working("contexts"));
        write_lens_config(runtime_root, lens_config_all(65536, 32));
    }

    let out_one = run_serverd_route(&runtime_one, 1, "tick:0");
    let out_two = run_serverd_route(&runtime_two, 1, "tick:0");
    assert!(out_one.status.success(), "run one failed");
    assert!(out_two.status.success(), "run two failed");

    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let lens_written_one = find_event(&events_one, "lens_outputs_written");
    let lens_written_two = find_event(&events_two, "lens_outputs_written");
    let outputs_ref_one = lens_written_one
        .get("outputs_ref")
        .and_then(|v| v.as_str())
        .expect("missing outputs_ref one");
    let outputs_ref_two = lens_written_two
        .get("outputs_ref")
        .and_then(|v| v.as_str())
        .expect("missing outputs_ref two");
    assert_eq!(outputs_ref_one, outputs_ref_two);

    let bytes_one =
        fs::read(artifact_path(&runtime_one, "lens_outputs", outputs_ref_one)).expect("read one");
    let bytes_two =
        fs::read(artifact_path(&runtime_two, "lens_outputs", outputs_ref_two)).expect("read two");
    assert_eq!(bytes_one, bytes_two);

    let value_one: serde_json::Value = serde_json::from_slice(&bytes_one).expect("json one");
    let value_two: serde_json::Value = serde_json::from_slice(&bytes_two).expect("json two");
    assert_eq!(
        value_one.get("output_hash").and_then(|v| v.as_str()),
        value_two.get("output_hash").and_then(|v| v.as_str())
    );
}

#[test]
fn lens_invalid_config_fails_closed() {
    let runtime_root = std::env::temp_dir().join(format!("pie_stage14_bad_cfg_{}", Uuid::new_v4()));
    write_lens_config(
        &runtime_root,
        serde_json::json!({
            "schema": "wrong.schema",
            "enabled": true,
            "allowed_lenses": ["dedup_v1"],
            "max_output_bytes": 1024,
            "max_candidates": 10
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("lens_config_invalid")
    );
}

#[test]
fn lens_caps_max_candidates_fail_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage14_cap_candidates_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_working_snapshot(
        &runtime_root,
        0,
        serde_json::json!([
            {
                "key": "k1",
                "value_ref": "contexts/sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "last_touched_tick": 0
            },
            {
                "key": "k2",
                "value_ref": "contexts/sha256:2222222222222222222222222222222222222222222222222222222222222222",
                "last_touched_tick": 0
            }
        ]),
    );
    write_retrieval_config(&runtime_root, retrieval_config_working("contexts"));
    write_lens_config(
        &runtime_root,
        serde_json::json!({
            "schema": LENS_CONFIG_SCHEMA,
            "enabled": true,
            "allowed_lenses": ["dedup_v1"],
            "max_output_bytes": 65536,
            "max_candidates": 1
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("lens_output_exceeds_max_candidates")
    );
}

#[test]
fn lens_caps_max_output_bytes_fail_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage14_cap_bytes_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_working_snapshot(
        &runtime_root,
        0,
        serde_json::json!([
            {
                "key": "k1",
                "value_ref": "contexts/sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "last_touched_tick": 0
            }
        ]),
    );
    write_retrieval_config(&runtime_root, retrieval_config_working("contexts"));
    write_lens_config(
        &runtime_root,
        serde_json::json!({
            "schema": LENS_CONFIG_SCHEMA,
            "enabled": true,
            "allowed_lenses": ["salience_v1"],
            "max_output_bytes": 16,
            "max_candidates": 8
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("lens_output_exceeds_max_bytes")
    );
}

#[test]
fn lenses_enabled_requires_retrieval_fail_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage14_requires_retrieval_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_working_snapshot(
        &runtime_root,
        1,
        serde_json::json!([
            {
                "key": "k1",
                "value_ref": "contexts/sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "last_touched_tick": 1
            }
        ]),
    );
    write_lens_config(
        &runtime_root,
        serde_json::json!({
            "schema": LENS_CONFIG_SCHEMA,
            "enabled": true,
            "allowed_lenses": ["dedup_v1"],
            "max_output_bytes": 65536,
            "max_candidates": 16
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("lens_requires_retrieval")
    );
}

#[test]
fn lens_event_ordering_after_retrieval_before_context() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage14_ordering_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_working_snapshot(
        &runtime_root,
        1,
        serde_json::json!([
            {
                "key": "k1",
                "value_ref": "contexts/sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "last_touched_tick": 1
            }
        ]),
    );
    write_retrieval_config(&runtime_root, retrieval_config_working("contexts"));
    write_lens_config(&runtime_root, lens_config_all(65536, 16));
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(out.status.success(), "run should succeed");
    let events = read_event_payloads(&runtime_root);
    let types = event_types(&events);
    assert_before(&types, "retrieval_results_written", "lens_plan_built");
    assert_before(&types, "lens_plan_built", "lens_set_selected");
    assert_before(&types, "lens_set_selected", "lens_executed");
    assert_before(&types, "lens_executed", "lens_outputs_written");
    assert_before(&types, "lens_outputs_written", "context_policy_loaded");
    assert_before(&types, "lens_outputs_written", "context_selected");
}

#[test]
fn lens_set_selection_is_canonicalized_from_allowed_lenses() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage14_canonical_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_working_snapshot(
        &runtime_root,
        2,
        serde_json::json!([
            {
                "key": "k1",
                "value_ref": "contexts/sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "last_touched_tick": 2
            },
            {
                "key": "k2",
                "value_ref": "contexts/sha256:2222222222222222222222222222222222222222222222222222222222222222",
                "last_touched_tick": 2
            }
        ]),
    );
    write_retrieval_config(&runtime_root, retrieval_config_working("contexts"));
    write_lens_config(
        &runtime_root,
        serde_json::json!({
            "schema": LENS_CONFIG_SCHEMA,
            "enabled": true,
            "allowed_lenses": ["salience_v1", "dedup_v1", "recency_v1"],
            "max_output_bytes": 65536,
            "max_candidates": 16
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(out.status.success(), "run should succeed");

    let events = read_event_payloads(&runtime_root);
    let lens_set = find_event(&events, "lens_set_selected");
    let lens_set_ref = lens_set
        .get("lens_set_ref")
        .and_then(|v| v.as_str())
        .expect("missing lens_set_ref");
    let bytes =
        fs::read(artifact_path(&runtime_root, "lens_sets", lens_set_ref)).expect("read lens_set");
    let lens_set_value: serde_json::Value = serde_json::from_slice(&bytes).expect("lens_set json");
    let lens_ids: Vec<String> = lens_set_value
        .get("lens_ids")
        .and_then(|v| v.as_array())
        .expect("lens_ids array")
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert_eq!(
        lens_ids,
        vec![
            "dedup_v1".to_string(),
            "recency_v1".to_string(),
            "salience_v1".to_string()
        ]
    );
}

#[test]
fn lens_effect_refined_candidate_order_matches_expected() {
    let runtime_root = std::env::temp_dir().join(format!("pie_stage14_effect_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_working_snapshot(
        &runtime_root,
        10,
        serde_json::json!([
            {
                "key": "k-b",
                "value_ref": "contexts/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "last_touched_tick": 9
            },
            {
                "key": "k-a",
                "value_ref": "contexts/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "last_touched_tick": 8
            },
            {
                "key": "k-a2",
                "value_ref": "contexts/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "last_touched_tick": 8
            },
            {
                "key": "k-old",
                "value_ref": "contexts/sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "last_touched_tick": 1
            }
        ]),
    );
    write_retrieval_config(&runtime_root, retrieval_config_working("contexts"));
    write_lens_config(
        &runtime_root,
        serde_json::json!({
            "schema": LENS_CONFIG_SCHEMA,
            "enabled": true,
            "allowed_lenses": ["dedup_v1", "recency_v1", "salience_v1"],
            "max_output_bytes": 65536,
            "max_candidates": 32,
            "recency_ticks": 3,
            "top_per_group": 2
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(out.status.success(), "run should succeed");

    let events = read_event_payloads(&runtime_root);
    let lens_written = find_event(&events, "lens_outputs_written");
    let outputs_ref = lens_written
        .get("outputs_ref")
        .and_then(|v| v.as_str())
        .expect("missing outputs_ref");
    let bytes =
        fs::read(artifact_path(&runtime_root, "lens_outputs", outputs_ref)).expect("read outputs");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("outputs json");
    let got: Vec<String> = value
        .get("refined_context_candidates")
        .and_then(|v| v.as_array())
        .expect("refined candidates")
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert_eq!(
        got,
        vec![
            "contexts/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            "contexts/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
        ]
    );
}
