#![cfg(feature = "bin")]

use serverd::lenses::LENS_CONFIG_SCHEMA;
use serverd::modes::{MODE_APPLIED_SCHEMA, MODE_CONFIG_SCHEMA, MODE_PROFILE_SCHEMA};
use serverd::retrieval::RETRIEVAL_CONFIG_SCHEMA;
use std::fs;
use std::path::Path;
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

fn base_mode_config(mode_id: &str) -> serde_json::Value {
    serde_json::json!({
        "schema": MODE_CONFIG_SCHEMA,
        "enabled": true,
        "default_mode": mode_id,
        "allowed_modes": [mode_id],
        "max_profile_bytes": 65536
    })
}

fn write_base_retrieval_config(runtime_root: &Path, max_items: u64, max_bytes: u64) {
    write_retrieval_config(
        runtime_root,
        serde_json::json!({
            "schema": RETRIEVAL_CONFIG_SCHEMA,
            "enabled": true,
            "sources": ["episodic", "working"],
            "namespaces_allowlist": ["contexts", "working"],
            "max_items": max_items,
            "max_bytes": max_bytes,
            "default_recency_ticks": 16,
            "default_tags": []
        }),
    );
}

fn write_base_lens_config(
    runtime_root: &Path,
    allowed_lenses: serde_json::Value,
    max_candidates: u64,
) {
    write_lens_config(
        runtime_root,
        serde_json::json!({
            "schema": LENS_CONFIG_SCHEMA,
            "enabled": true,
            "allowed_lenses": allowed_lenses,
            "max_output_bytes": 65536,
            "max_candidates": max_candidates,
            "recency_ticks": 8,
            "top_per_group": 3
        }),
    );
}

fn read_event_payloads(runtime_root: &Path) -> Vec<serde_json::Value> {
    common::read_event_payloads(runtime_root)
}

fn find_event(events: &[serde_json::Value], event_type: &str) -> serde_json::Value {
    common::find_event(events, event_type)
}

fn read_mode_applied_bytes(runtime_root: &Path) -> Vec<u8> {
    let dir = runtime_root.join("artifacts").join("mode_applied");
    let mut files: Vec<_> = fs::read_dir(&dir)
        .expect("read mode_applied dir")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();
    files.sort();
    assert_eq!(files.len(), 1, "expected exactly one mode_applied artifact");
    fs::read(&files[0]).expect("read mode_applied artifact")
}

fn read_mode_applied_json(runtime_root: &Path) -> serde_json::Value {
    let bytes = read_mode_applied_bytes(runtime_root);
    serde_json::from_slice(&bytes).expect("mode_applied json")
}

#[test]
fn mode_policy_retrieval_tightening_applies_and_emits_audit() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage17_retrieval_tighten_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_base_retrieval_config(&runtime_root, 32, 65536);
    write_mode_config(&runtime_root, base_mode_config("strict"));
    write_mode_profile(
        &runtime_root,
        "strict",
        serde_json::json!({
            "schema": MODE_PROFILE_SCHEMA,
            "mode_id": "strict",
            "bias": {},
            "retrieval_policy": {
                "allow_namespaces": ["contexts"],
                "max_items": 8,
                "max_bytes": 4096
            }
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(out.status.success(), "run should succeed");
    let events = read_event_payloads(&runtime_root);
    let policy_event = find_event(&events, "mode_policy_applied");
    let policy_hash = policy_event
        .get("policy_hash")
        .and_then(|v| v.as_str())
        .expect("policy hash");
    assert_eq!(
        policy_event.get("mode_id").and_then(|v| v.as_str()),
        Some("strict")
    );
    let mode_applied = read_mode_applied_json(&runtime_root);
    assert_eq!(
        mode_applied.get("schema").and_then(|v| v.as_str()),
        Some(MODE_APPLIED_SCHEMA)
    );
    assert_eq!(
        mode_applied
            .get("mode_policy_hash")
            .and_then(|v| v.as_str()),
        Some(policy_hash)
    );
    assert_eq!(
        mode_applied
            .get("retrieval_config")
            .and_then(|v| v.get("namespaces_allowlist"))
            .and_then(|v| v.as_array())
            .expect("namespaces allowlist")
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>(),
        vec!["contexts"]
    );
    assert_eq!(
        mode_applied
            .get("retrieval_config")
            .and_then(|v| v.get("max_items"))
            .and_then(|v| v.as_u64()),
        Some(8)
    );
    assert_eq!(
        mode_applied
            .get("retrieval_config")
            .and_then(|v| v.get("max_bytes"))
            .and_then(|v| v.as_u64()),
        Some(4096)
    );
}

#[test]
fn mode_policy_retrieval_loosen_attempt_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage17_retrieval_loosen_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_base_retrieval_config(&runtime_root, 8, 4096);
    write_mode_config(&runtime_root, base_mode_config("strict"));
    write_mode_profile(
        &runtime_root,
        "strict",
        serde_json::json!({
            "schema": MODE_PROFILE_SCHEMA,
            "mode_id": "strict",
            "bias": {},
            "retrieval_policy": {
                "max_items": 32
            }
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("mode_policy_loosen_attempt")
    );
}

#[test]
fn mode_policy_lens_tightening_applies_and_emits_audit() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage17_lens_tighten_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_base_retrieval_config(&runtime_root, 32, 65536);
    write_base_lens_config(
        &runtime_root,
        serde_json::json!(["salience_v1", "dedup_v1", "recency_v1"]),
        64,
    );
    write_mode_config(&runtime_root, base_mode_config("strict"));
    write_mode_profile(
        &runtime_root,
        "strict",
        serde_json::json!({
            "schema": MODE_PROFILE_SCHEMA,
            "mode_id": "strict",
            "bias": {},
            "lens_policy": {
                "require_lenses": ["dedup_v1", "recency_v1"],
                "forbid_lenses": ["salience_v1"],
                "max_candidates": 8,
                "max_output_bytes": 4096
            }
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(out.status.success(), "run should succeed");
    let events = read_event_payloads(&runtime_root);
    let policy_event = find_event(&events, "mode_policy_applied");
    assert_eq!(
        policy_event.get("mode_id").and_then(|v| v.as_str()),
        Some("strict")
    );
    let mode_applied = read_mode_applied_json(&runtime_root);
    assert_eq!(
        mode_applied
            .get("lens_config")
            .and_then(|v| v.get("allowed_lenses"))
            .and_then(|v| v.as_array())
            .expect("allowed_lenses")
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>(),
        vec!["dedup_v1", "recency_v1"]
    );
    assert_eq!(
        mode_applied
            .get("lens_config")
            .and_then(|v| v.get("max_candidates"))
            .and_then(|v| v.as_u64()),
        Some(8)
    );
    assert_eq!(
        mode_applied
            .get("lens_config")
            .and_then(|v| v.get("max_output_bytes"))
            .and_then(|v| v.as_u64()),
        Some(4096)
    );
}

#[test]
fn mode_policy_lens_loosen_attempt_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage17_lens_loosen_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_base_retrieval_config(&runtime_root, 32, 65536);
    write_base_lens_config(&runtime_root, serde_json::json!(["dedup_v1"]), 16);
    write_mode_config(&runtime_root, base_mode_config("strict"));
    write_mode_profile(
        &runtime_root,
        "strict",
        serde_json::json!({
            "schema": MODE_PROFILE_SCHEMA,
            "mode_id": "strict",
            "bias": {},
            "lens_policy": {
                "require_lenses": ["salience_v1"]
            }
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("mode_policy_loosen_attempt")
    );
}

#[test]
fn mode_policy_empty_intersection_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage17_empty_intersection_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_base_retrieval_config(&runtime_root, 32, 65536);
    write_base_lens_config(&runtime_root, serde_json::json!(["dedup_v1"]), 16);
    write_mode_config(&runtime_root, base_mode_config("strict"));
    write_mode_profile(
        &runtime_root,
        "strict",
        serde_json::json!({
            "schema": MODE_PROFILE_SCHEMA,
            "mode_id": "strict",
            "bias": {},
            "lens_policy": {
                "require_lenses": ["dedup_v1"],
                "forbid_lenses": ["dedup_v1"]
            }
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("mode_policy_empty_intersection")
    );
}

#[test]
fn mode_policy_binding_is_deterministic_across_runtimes() {
    let runtime_one = std::env::temp_dir().join(format!("pie_stage17_det_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_stage17_det_two_{}", Uuid::new_v4()));
    for runtime_root in [&runtime_one, &runtime_two] {
        write_initial_state(runtime_root);
        write_base_retrieval_config(runtime_root, 32, 65536);
        write_base_lens_config(
            runtime_root,
            serde_json::json!(["salience_v1", "dedup_v1", "recency_v1"]),
            64,
        );
        write_mode_config(runtime_root, base_mode_config("strict"));
        write_mode_profile(
            runtime_root,
            "strict",
            serde_json::json!({
                "schema": MODE_PROFILE_SCHEMA,
                "mode_id": "strict",
                "bias": {},
                "retrieval_policy": {
                    "allow_namespaces": ["contexts"],
                    "max_items": 8,
                    "max_bytes": 4096
                },
                "lens_policy": {
                    "require_lenses": ["dedup_v1", "recency_v1"],
                    "forbid_lenses": ["salience_v1"],
                    "max_candidates": 8,
                    "max_output_bytes": 4096
                }
            }),
        );
    }
    let out_one = run_serverd_route(&runtime_one, 1, "tick:0");
    let out_two = run_serverd_route(&runtime_two, 1, "tick:0");
    assert!(out_one.status.success(), "run one should succeed");
    assert!(out_two.status.success(), "run two should succeed");
    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let policy_one = find_event(&events_one, "mode_policy_applied");
    let policy_two = find_event(&events_two, "mode_policy_applied");
    assert_eq!(
        policy_one.get("policy_hash").and_then(|v| v.as_str()),
        policy_two.get("policy_hash").and_then(|v| v.as_str())
    );
    assert_eq!(
        read_mode_applied_bytes(&runtime_one),
        read_mode_applied_bytes(&runtime_two)
    );
}
