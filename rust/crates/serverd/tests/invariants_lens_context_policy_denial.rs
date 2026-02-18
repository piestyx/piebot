#![cfg(feature = "bin")]

use serverd::lenses::LENS_CONFIG_SCHEMA;
use serverd::retrieval::RETRIEVAL_CONFIG_SCHEMA;
use serverd::CONTEXT_POLICY_SCHEMA;
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

fn write_context_policy(runtime_root: &Path, value: serde_json::Value) {
    let dir = runtime_root.join("context");
    fs::create_dir_all(&dir).expect("create context dir");
    let bytes = serde_json::to_vec(&value).expect("serialize context policy");
    fs::write(dir.join("policy.json"), bytes).expect("write context policy");
}

fn write_context_artifact(
    runtime_root: &Path,
    namespace: &str,
    artifact_ref: &str,
    value: serde_json::Value,
) {
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    let dir = runtime_root.join("artifacts").join(namespace);
    fs::create_dir_all(&dir).expect("create artifact namespace dir");
    let bytes = serde_json::to_vec(&value).expect("serialize artifact");
    fs::write(dir.join(format!("{}.json", trimmed)), bytes).expect("write context artifact");
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
fn lens_candidates_cannot_bypass_context_namespace_policy() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_inv_lens_ctx_policy_denial_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);

    let allowed_ref = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let denied_ref = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    write_context_artifact(
        &runtime_root,
        "contexts",
        allowed_ref,
        serde_json::json!({
            "schema": "test.context.v1",
            "body": "allowed"
        }),
    );
    write_context_artifact(
        &runtime_root,
        "denied_ctx",
        denied_ref,
        serde_json::json!({
            "schema": "test.context.v1",
            "body": "denied"
        }),
    );

    write_working_snapshot(
        &runtime_root,
        7,
        serde_json::json!([
            {
                "key": "allow",
                "value_ref": format!("contexts/{}", allowed_ref),
                "last_touched_tick": 7
            },
            {
                "key": "deny",
                "value_ref": format!("denied_ctx/{}", denied_ref),
                "last_touched_tick": 7
            }
        ]),
    );

    write_retrieval_config(
        &runtime_root,
        serde_json::json!({
            "schema": RETRIEVAL_CONFIG_SCHEMA,
            "enabled": true,
            "sources": ["working"],
            "namespaces_allowlist": ["contexts", "denied_ctx"],
            "max_items": 32,
            "max_bytes": 65536,
            "default_recency_ticks": 64,
            "default_tags": []
        }),
    );
    write_lens_config(
        &runtime_root,
        serde_json::json!({
            "schema": LENS_CONFIG_SCHEMA,
            "enabled": true,
            "allowed_lenses": ["dedup_v1"],
            "max_output_bytes": 65536,
            "max_candidates": 16,
            "recency_ticks": 8,
            "top_per_group": 2
        }),
    );
    write_context_policy(
        &runtime_root,
        serde_json::json!({
            "schema": CONTEXT_POLICY_SCHEMA,
            "enabled": true,
            "max_items": 10,
            "max_bytes": 65536,
            "allowed_namespaces": ["contexts"],
            "ordering": "stable_manifest_order",
            "allow_skill_overrides": false
        }),
    );

    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(!out.status.success(), "run should fail closed");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("context_namespace_denied")
    );

    let events = read_event_payloads(&runtime_root);
    let types = event_types(&events);
    assert_before(&types, "retrieval_results_written", "lens_outputs_written");
    assert_before(&types, "lens_outputs_written", "context_policy_loaded");
    assert!(
        !types.iter().any(|t| t == "context_selected"),
        "context_selected must not be emitted on namespace denial"
    );

    let lens_written = find_event(&events, "lens_outputs_written");
    let outputs_ref = lens_written
        .get("outputs_ref")
        .and_then(|v| v.as_str())
        .expect("missing outputs_ref");
    let bytes =
        fs::read(artifact_path(&runtime_root, "lens_outputs", outputs_ref)).expect("read outputs");
    let outputs: serde_json::Value = serde_json::from_slice(&bytes).expect("outputs json");
    let got: Vec<String> = outputs
        .get("refined_context_candidates")
        .and_then(|v| v.as_array())
        .expect("refined candidates")
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert!(
        got.iter()
            .any(|v| v == &format!("contexts/{}", allowed_ref)),
        "expected allowlisted candidate in lens outputs"
    );
    assert!(
        got.iter().any(|v| v == &format!("denied_ctx/{}", denied_ref)),
        "expected denied candidate in lens outputs"
    );
}
