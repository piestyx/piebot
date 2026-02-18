#![cfg(feature = "bin")]

use serverd::lenses::{LENS_CONFIG_SCHEMA, LENS_PLAN_SCHEMA};
use serverd::modes::{MODE_CONFIG_SCHEMA, MODE_PROFILE_SCHEMA};
use serverd::retrieval::RETRIEVAL_CONFIG_SCHEMA;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

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

fn write_mode_config(runtime_root: &Path, value: serde_json::Value) {
    let dir = runtime_root.join("modes");
    fs::create_dir_all(&dir).expect("create modes dir");
    let bytes = serde_json::to_vec(&value).expect("serialize mode config");
    fs::write(dir.join("config.json"), bytes).expect("write mode config");
}

fn write_mode_profile(runtime_root: &Path, mode_id: &str, value: serde_json::Value) {
    let dir = runtime_root.join("modes").join("profiles");
    fs::create_dir_all(&dir).expect("create mode profiles dir");
    let bytes = serde_json::to_vec(&value).expect("serialize mode profile");
    fs::write(dir.join(format!("{}.json", mode_id)), bytes).expect("write mode profile");
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

fn read_lens_plan_artifact(runtime_root: &Path, events: &[serde_json::Value]) -> serde_json::Value {
    let plan_event = find_event(events, "lens_plan_built");
    let plan_ref = plan_event
        .get("plan_ref")
        .and_then(|v| v.as_str())
        .expect("missing plan_ref");
    let bytes =
        fs::read(artifact_path(runtime_root, "lens_plans", plan_ref)).expect("read lens plan");
    serde_json::from_slice(&bytes).expect("lens plan json")
}

fn base_retrieval_enabled() -> serde_json::Value {
    serde_json::json!({
        "schema": RETRIEVAL_CONFIG_SCHEMA,
        "enabled": true,
        "sources": ["working"],
        "namespaces_allowlist": ["contexts"],
        "max_items": 32,
        "max_bytes": 65536,
        "default_recency_ticks": 16,
        "default_tags": []
    })
}

#[test]
fn lens_plan_disabled_still_emits_plan_with_empty_selection() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage18_disabled_plan_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(out.status.success(), "run should succeed");
    let events = read_event_payloads(&runtime_root);
    let plan_event = find_event(&events, "lens_plan_built");
    let selected = plan_event
        .get("selected_lenses")
        .and_then(|v| v.as_array())
        .expect("selected_lenses");
    assert!(
        selected.is_empty(),
        "selected_lenses must be empty when disabled"
    );
    let plan = read_lens_plan_artifact(&runtime_root, &events);
    assert_eq!(
        plan.get("schema").and_then(|v| v.as_str()),
        Some(LENS_PLAN_SCHEMA)
    );
    assert_eq!(
        plan.get("selected_lenses")
            .and_then(|v| v.as_array())
            .map(|v| v.len()),
        Some(0)
    );
    let reasons: Vec<String> = plan
        .get("reason_codes")
        .and_then(|v| v.as_array())
        .expect("reason codes")
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert!(reasons.iter().any(|v| v == "lenses_disabled"));
}

#[test]
fn lens_plan_enabled_matches_allowed_lenses_order() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage18_enabled_order_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_retrieval_config(&runtime_root, base_retrieval_enabled());
    write_lens_config(
        &runtime_root,
        serde_json::json!({
            "schema": LENS_CONFIG_SCHEMA,
            "enabled": true,
            "allowed_lenses": ["salience_v1", "dedup_v1", "recency_v1"],
            "max_output_bytes": 65536,
            "max_candidates": 32
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(out.status.success(), "run should succeed");
    let events = read_event_payloads(&runtime_root);
    let plan = read_lens_plan_artifact(&runtime_root, &events);
    let selected: Vec<String> = plan
        .get("selected_lenses")
        .and_then(|v| v.as_array())
        .expect("selected_lenses")
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert_eq!(
        selected,
        vec![
            "dedup_v1".to_string(),
            "recency_v1".to_string(),
            "salience_v1".to_string()
        ]
    );
}

#[test]
fn lens_plan_fails_closed_when_enabled_but_empty_allowed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage18_empty_allowed_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_lens_config(
        &runtime_root,
        serde_json::json!({
            "schema": LENS_CONFIG_SCHEMA,
            "enabled": true,
            "allowed_lenses": [],
            "max_output_bytes": 65536,
            "max_candidates": 32
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
fn lens_plan_requires_retrieval_when_lenses_enabled() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage18_requires_retrieval_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_lens_config(
        &runtime_root,
        serde_json::json!({
            "schema": LENS_CONFIG_SCHEMA,
            "enabled": true,
            "allowed_lenses": ["dedup_v1"],
            "max_output_bytes": 65536,
            "max_candidates": 32
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
fn lens_plan_deterministic_across_two_runtimes() {
    let runtime_one = std::env::temp_dir().join(format!("pie_stage18_det_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_stage18_det_two_{}", Uuid::new_v4()));
    for runtime_root in [&runtime_one, &runtime_two] {
        write_initial_state(runtime_root);
        write_retrieval_config(runtime_root, base_retrieval_enabled());
        write_lens_config(
            runtime_root,
            serde_json::json!({
                "schema": LENS_CONFIG_SCHEMA,
                "enabled": true,
                "allowed_lenses": ["salience_v1", "dedup_v1", "recency_v1"],
                "max_output_bytes": 65536,
                "max_candidates": 32
            }),
        );
    }
    let out_one = run_serverd_route(&runtime_one, 1, "tick:0");
    let out_two = run_serverd_route(&runtime_two, 1, "tick:0");
    assert!(out_one.status.success(), "run one should succeed");
    assert!(out_two.status.success(), "run two should succeed");
    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let plan_event_one = find_event(&events_one, "lens_plan_built");
    let plan_event_two = find_event(&events_two, "lens_plan_built");
    assert_eq!(
        plan_event_one.get("plan_hash").and_then(|v| v.as_str()),
        plan_event_two.get("plan_hash").and_then(|v| v.as_str())
    );
    let plan_ref_one = plan_event_one
        .get("plan_ref")
        .and_then(|v| v.as_str())
        .expect("plan_ref one");
    let plan_ref_two = plan_event_two
        .get("plan_ref")
        .and_then(|v| v.as_str())
        .expect("plan_ref two");
    let bytes_one =
        fs::read(artifact_path(&runtime_one, "lens_plans", plan_ref_one)).expect("plan bytes one");
    let bytes_two =
        fs::read(artifact_path(&runtime_two, "lens_plans", plan_ref_two)).expect("plan bytes two");
    assert_eq!(bytes_one, bytes_two);
}

#[test]
fn lens_plan_includes_mode_policy_hash_when_present() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage18_mode_policy_hash_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_retrieval_config(&runtime_root, base_retrieval_enabled());
    write_lens_config(
        &runtime_root,
        serde_json::json!({
            "schema": LENS_CONFIG_SCHEMA,
            "enabled": true,
            "allowed_lenses": ["dedup_v1", "recency_v1"],
            "max_output_bytes": 65536,
            "max_candidates": 32
        }),
    );
    write_mode_config(
        &runtime_root,
        serde_json::json!({
            "schema": MODE_CONFIG_SCHEMA,
            "enabled": true,
            "default_mode": "strict",
            "allowed_modes": ["strict"],
            "max_profile_bytes": 65536
        }),
    );
    write_mode_profile(
        &runtime_root,
        "strict",
        serde_json::json!({
            "schema": MODE_PROFILE_SCHEMA,
            "mode_id": "strict",
            "bias": {},
            "lens_policy": {
                "forbid_lenses": ["recency_v1"]
            }
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(out.status.success(), "run should succeed");
    let events = read_event_payloads(&runtime_root);
    let plan = read_lens_plan_artifact(&runtime_root, &events);
    assert!(
        plan.get("mode_policy_hash")
            .and_then(|v| v.as_str())
            .is_some(),
        "mode_policy_hash should be present in lens plan"
    );
    let reasons: Vec<String> = plan
        .get("reason_codes")
        .and_then(|v| v.as_array())
        .expect("reason codes")
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert!(reasons.iter().any(|v| v == "mode_policy_applied"));
}
