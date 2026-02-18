#![cfg(feature = "bin")]

use serverd::retrieval::RETRIEVAL_CONFIG_SCHEMA;
use serverd::skills::SKILL_MANIFEST_SCHEMA;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

const WORKING_SNAPSHOT_SCHEMA: &str = "serverd.working_memory.v1";

fn run_serverd_route(runtime_root: &Path, ticks: u64, delta: &str, skill: Option<&str>) -> Output {
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
    if let Some(skill_id) = skill {
        cmd.arg("--skill").arg(skill_id);
    }
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

fn write_skill_manifest(runtime_root: &Path, skill_id: &str, prompt_refs: &[String]) {
    let dir = runtime_root.join("skills").join(skill_id);
    fs::create_dir_all(&dir).expect("create skill dir");
    let value = serde_json::json!({
        "schema": SKILL_MANIFEST_SCHEMA,
        "skill_id": skill_id,
        "allowed_tools": [],
        "tool_constraints": [],
        "prompt_template_refs": prompt_refs
    });
    let bytes = serde_json::to_vec(&value).expect("serialize skill manifest");
    fs::write(dir.join("skill.json"), bytes).expect("write skill manifest");
}

fn retrieval_config_base() -> serde_json::Value {
    serde_json::json!({
        "schema": RETRIEVAL_CONFIG_SCHEMA,
        "enabled": true,
        "sources": ["working"],
        "namespaces_allowlist": ["working"],
        "max_items": 8,
        "max_bytes": 8192,
        "default_recency_ticks": 32,
        "default_tags": []
    })
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

#[test]
fn retrieval_deterministic_across_runtimes() {
    let runtime_one = std::env::temp_dir().join(format!("pie_stage13_det_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_stage13_det_two_{}", Uuid::new_v4()));
    for runtime_root in [&runtime_one, &runtime_two] {
        write_initial_state(runtime_root);
        write_working_snapshot(
            runtime_root,
            2,
            serde_json::json!([
                {
                    "key": "req-b",
                    "value_ref": "working/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "last_touched_tick": 2
                },
                {
                    "key": "req-a",
                    "value_ref": "working/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "last_touched_tick": 2
                }
            ]),
        );
        write_retrieval_config(runtime_root, retrieval_config_base());
    }

    let out_one = run_serverd_route(&runtime_one, 1, "tick:0", None);
    let out_two = run_serverd_route(&runtime_two, 1, "tick:0", None);
    assert!(out_one.status.success(), "run one failed");
    assert!(out_two.status.success(), "run two failed");

    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let retrieval_results_one = find_event(&events_one, "retrieval_results_written");
    let retrieval_results_two = find_event(&events_two, "retrieval_results_written");
    let results_ref_one = retrieval_results_one
        .get("results_ref")
        .and_then(|v| v.as_str())
        .expect("missing results_ref one");
    let results_ref_two = retrieval_results_two
        .get("results_ref")
        .and_then(|v| v.as_str())
        .expect("missing results_ref two");
    assert_eq!(results_ref_one, results_ref_two);

    let retrieval_exec_one = find_event(&events_one, "retrieval_executed");
    let retrieval_exec_two = find_event(&events_two, "retrieval_executed");
    let set_hash_one = retrieval_exec_one
        .get("result_set_hash")
        .and_then(|v| v.as_str())
        .expect("missing result_set_hash one");
    let set_hash_two = retrieval_exec_two
        .get("result_set_hash")
        .and_then(|v| v.as_str())
        .expect("missing result_set_hash two");
    assert_eq!(set_hash_one, set_hash_two);

    let bytes_one = fs::read(artifact_path(
        &runtime_one,
        "retrieval_results",
        results_ref_one,
    ))
    .expect("read one");
    let bytes_two = fs::read(artifact_path(
        &runtime_two,
        "retrieval_results",
        results_ref_two,
    ))
    .expect("read two");
    assert_eq!(bytes_one, bytes_two);
}

#[test]
fn retrieval_invalid_config_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage13_bad_config_{}", Uuid::new_v4()));
    write_retrieval_config(
        &runtime_root,
        serde_json::json!({
            "schema": "wrong.schema",
            "enabled": true,
            "sources": ["working"],
            "namespaces_allowlist": ["working"],
            "max_items": 8,
            "max_bytes": 8192,
            "default_recency_ticks": 32
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0", None);
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("retrieval_config_invalid")
    );
}

#[test]
fn retrieval_namespace_deny_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage13_namespace_deny_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_skill_manifest(
        &runtime_root,
        "demo",
        &[String::from(
            "contexts/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )],
    );
    let mut config = retrieval_config_base();
    config["namespaces_allowlist"] = serde_json::json!(["working"]);
    write_retrieval_config(&runtime_root, config);

    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"));
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("retrieval_namespace_denied")
    );
}

#[test]
fn retrieval_caps_max_items_enforced_fail_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage13_cap_items_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_working_snapshot(
        &runtime_root,
        0,
        serde_json::json!([
            {
                "key": "k1",
                "value_ref": "working/sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "last_touched_tick": 0
            },
            {
                "key": "k2",
                "value_ref": "working/sha256:2222222222222222222222222222222222222222222222222222222222222222",
                "last_touched_tick": 0
            }
        ]),
    );
    let mut config = retrieval_config_base();
    config["max_items"] = serde_json::json!(1);
    write_retrieval_config(&runtime_root, config);

    let out = run_serverd_route(&runtime_root, 1, "tick:0", None);
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("retrieval_selection_exceeds_max_items")
    );
}

#[test]
fn retrieval_caps_max_bytes_enforced_fail_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage13_cap_bytes_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_working_snapshot(
        &runtime_root,
        0,
        serde_json::json!([
            {
                "key": "k1",
                "value_ref": "working/sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "last_touched_tick": 0
            }
        ]),
    );
    let mut config = retrieval_config_base();
    config["max_bytes"] = serde_json::json!(16);
    write_retrieval_config(&runtime_root, config);

    let out = run_serverd_route(&runtime_root, 1, "tick:0", None);
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("retrieval_selection_exceeds_max_bytes")
    );
}

#[test]
fn retrieval_stable_ordering_on_ties() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage13_ordering_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_working_snapshot(
        &runtime_root,
        0,
        serde_json::json!([
            {
                "key": "k-b",
                "value_ref": "working/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "last_touched_tick": 0
            },
            {
                "key": "k-a",
                "value_ref": "working/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "last_touched_tick": 0
            }
        ]),
    );
    write_retrieval_config(&runtime_root, retrieval_config_base());

    let out = run_serverd_route(&runtime_root, 1, "tick:0", None);
    assert!(out.status.success(), "run should succeed");

    let events = read_event_payloads(&runtime_root);
    let retrieval_results = find_event(&events, "retrieval_results_written");
    let results_ref = retrieval_results
        .get("results_ref")
        .and_then(|v| v.as_str())
        .expect("missing results_ref");
    let bytes = fs::read(artifact_path(
        &runtime_root,
        "retrieval_results",
        results_ref,
    ))
    .expect("read results");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("results json");
    let refs: Vec<String> = value
        .get("results")
        .and_then(|v| v.as_array())
        .expect("results array")
        .iter()
        .filter_map(|row| {
            row.get("ref")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    assert_eq!(
        refs,
        vec![
            "working/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            "working/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string()
        ]
    );
}

#[test]
fn retrieval_enabled_route_emits_artifacts_before_context_selection() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage13_integration_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_working_snapshot(
        &runtime_root,
        0,
        serde_json::json!([
            {
                "key": "k1",
                "value_ref": "working/sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "last_touched_tick": 0
            }
        ]),
    );
    write_retrieval_config(&runtime_root, retrieval_config_base());

    let out = run_serverd_route(&runtime_root, 1, "tick:0", None);
    assert!(out.status.success(), "run should succeed");

    let events = read_event_payloads(&runtime_root);
    let types = event_types(&events);
    assert_before(&types, "retrieval_config_loaded", "context_policy_loaded");
    assert_before(&types, "retrieval_query_written", "context_policy_loaded");
    assert_before(&types, "retrieval_executed", "context_policy_loaded");
    assert_before(&types, "retrieval_results_written", "context_policy_loaded");
    assert_before(&types, "retrieval_results_written", "context_selected");

    let query_event = find_event(&events, "retrieval_query_written");
    let query_ref = query_event
        .get("query_ref")
        .and_then(|v| v.as_str())
        .expect("missing query_ref");
    assert!(artifact_path(&runtime_root, "retrieval_queries", query_ref).is_file());

    let results_event = find_event(&events, "retrieval_results_written");
    let results_ref = results_event
        .get("results_ref")
        .and_then(|v| v.as_str())
        .expect("missing results_ref");
    assert!(artifact_path(&runtime_root, "retrieval_results", results_ref).is_file());
}
