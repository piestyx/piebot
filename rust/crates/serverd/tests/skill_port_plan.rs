#![cfg(feature = "bin")]

use serverd::retrieval::save_gsama_store;
use serverd::skills::SKILL_MANIFEST_SCHEMA;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

const WORKSPACE_POLICY_SCHEMA: &str = "serverd.workspace_policy.v1";
const REPO_INDEX_CONFIG_SCHEMA: &str = "serverd.repo_index_config.v1";
const RETRIEVAL_CONFIG_SCHEMA: &str = "serverd.retrieval_config.v1";
const PORT_PLAN_SCHEMA: &str = "serverd.port_plan.v1";

fn run_serverd_route_with_envs(
    runtime_root: &Path,
    provider_mode: &str,
    envs: &[(&str, &str)],
) -> Output {
    let mut cmd = Command::new(common::serverd_exe());
    cmd.arg("--mode")
        .arg("route")
        .arg("--ticks")
        .arg("1")
        .arg("--delta")
        .arg("tick:0")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--skill")
        .arg("port_repo.v1")
        .arg("--provider")
        .arg(provider_mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output().expect("failed to run serverd")
}

fn write_initial_state(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
}

fn write_workspace_policy(runtime_root: &Path) {
    let dir = runtime_root.join("workspace");
    fs::create_dir_all(&dir).expect("create workspace policy dir");
    let value = serde_json::json!({
        "schema": WORKSPACE_POLICY_SCHEMA,
        "enabled": true,
        "workspace_root": "workspace_data",
        "allow_repo_root": false,
        "per_run_dir": false
    });
    fs::write(
        dir.join("policy.json"),
        serde_json::to_vec(&value).expect("serialize workspace policy"),
    )
    .expect("write workspace policy");
}

fn write_repo_index_config(runtime_root: &Path) {
    write_repo_index_config_with_enabled(runtime_root, true);
}

fn write_repo_index_config_with_enabled(runtime_root: &Path, enabled: bool) {
    let dir = runtime_root.join("repo_index");
    fs::create_dir_all(&dir).expect("create repo_index dir");
    let value = serde_json::json!({
        "schema": REPO_INDEX_CONFIG_SCHEMA,
        "enabled": enabled,
        "max_file_bytes": 1024 * 1024,
        "max_total_bytes": 4 * 1024 * 1024,
        "chunk_mode": "fixed_size",
        "fixed_chunk_bytes": 8,
        "ignore_globs": []
    });
    fs::write(
        dir.join("config.json"),
        serde_json::to_vec(&value).expect("serialize repo index config"),
    )
    .expect("write repo index config");
}

fn write_retrieval_config(runtime_root: &Path) {
    write_retrieval_config_with_enabled(runtime_root, true);
}

fn write_retrieval_config_with_enabled(runtime_root: &Path, enabled: bool) {
    let dir = runtime_root.join("retrieval");
    fs::create_dir_all(&dir).expect("create retrieval dir");
    let value = serde_json::json!({
        "schema": RETRIEVAL_CONFIG_SCHEMA,
        "enabled": enabled,
        "kind": "gsama",
        "sources": ["episodic"],
        "namespaces_allowlist": ["contexts"],
        "max_items": 16,
        "max_bytes": 8192,
        "default_recency_ticks": 16,
        "default_tags": [],
        "gsama_vector_source_mode": "hash_fallback_only",
        "gsama_allow_hash_embedder": true,
        "gsama_hash_embedder_dim": 64,
        "gsama_store_capacity": 1024,
        "gsama_vector_dim": 74
    });
    fs::write(
        dir.join("config.json"),
        serde_json::to_vec(&value).expect("serialize retrieval config"),
    )
    .expect("write retrieval config");
}

fn write_initial_gsama_store(runtime_root: &Path) {
    let store = gsama_core::Store::new(74, 1024);
    save_gsama_store(runtime_root, &store).expect("write initial gsama store");
}

fn write_skill_manifest(runtime_root: &Path) {
    let dir = runtime_root.join("skills").join("port_repo.v1");
    fs::create_dir_all(&dir).expect("create skill dir");
    let value = serde_json::json!({
        "schema": SKILL_MANIFEST_SCHEMA,
        "skill_id": "port_repo.v1",
        "allowed_tools": [],
        "tool_constraints": [],
        "prompt_template_refs": []
    });
    fs::write(
        dir.join("skill.json"),
        serde_json::to_vec(&value).expect("serialize skill manifest"),
    )
    .expect("write skill manifest");
}

fn write_router_config(runtime_root: &Path) {
    let dir = runtime_root.join("router");
    fs::create_dir_all(&dir).expect("create router dir");
    let value = serde_json::json!({
        "schema": "serverd.router.v1",
        "default_provider": "mock_port_plan",
        "routes": [],
        "policy": { "fail_if_unavailable": true }
    });
    fs::write(
        dir.join("config.json"),
        serde_json::to_vec(&value).expect("serialize router config"),
    )
    .expect("write router config");
}

fn write_workspace_contents(runtime_root: &Path) {
    let workspace = runtime_root.join("workspace_data");
    fs::create_dir_all(workspace.join("src")).expect("create src");
    fs::create_dir_all(workspace.join("tests")).expect("create tests");
    fs::write(
        workspace.join("src").join("lib.rs"),
        b"pub fn migrate() {}\n",
    )
    .expect("write lib.rs");
    fs::write(
        workspace.join("tests").join("port_repo_plan.rs"),
        b"#[test]\nfn plan_is_stable() {}\n",
    )
    .expect("write test file");
}

fn setup_runtime(runtime_root: &Path) {
    write_initial_state(runtime_root);
    write_workspace_policy(runtime_root);
    write_repo_index_config(runtime_root);
    write_retrieval_config(runtime_root);
    write_initial_gsama_store(runtime_root);
    write_skill_manifest(runtime_root);
    write_router_config(runtime_root);
    write_workspace_contents(runtime_root);
}

fn read_event_payloads(runtime_root: &Path) -> Vec<serde_json::Value> {
    common::read_event_payloads(runtime_root)
}

fn find_event(events: &[serde_json::Value], event_type: &str) -> serde_json::Value {
    common::find_event(events, event_type)
}
fn find_last_event(events: &[serde_json::Value], event_type: &str) -> serde_json::Value {
    events
        .iter()
        .rev()
        .find(|event| event.get("event_type").and_then(|v| v.as_str()) == Some(event_type))
        .cloned()
        .unwrap_or_else(|| panic!("missing {}", event_type))
}

fn find_events(events: &[serde_json::Value], event_type: &str) -> Vec<serde_json::Value> {
    events
        .iter()
        .filter(|event| event.get("event_type").and_then(|v| v.as_str()) == Some(event_type))
        .cloned()
        .collect()
}

fn artifact_path(runtime_root: &Path, subdir: &str, artifact_ref: &str) -> PathBuf {
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    runtime_root
        .join("artifacts")
        .join(subdir)
        .join(format!("{}.json", trimmed))
}

fn assert_no_nondeterministic_fields(value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                assert!(
                    !matches!(
                        key.as_str(),
                        "timestamp"
                            | "created_at"
                            | "updated_at"
                            | "mtime"
                            | "ctime"
                            | "inode"
                            | "absolute_path"
                    ),
                    "unexpected nondeterministic key: {}",
                    key
                );
                assert_no_nondeterministic_fields(inner);
            }
        }
        serde_json::Value::Array(list) => {
            for item in list {
                assert_no_nondeterministic_fields(item);
            }
        }
        _ => {}
    }
}

#[test]
fn deterministic_port_plan_across_runtime_roots() {
    let runtime_one = std::env::temp_dir().join(format!("pie_port_plan_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_port_plan_two_{}", Uuid::new_v4()));
    setup_runtime(&runtime_one);
    setup_runtime(&runtime_two);

    let out_one = run_serverd_route_with_envs(&runtime_one, "record", &[]);
    let out_two = run_serverd_route_with_envs(&runtime_two, "record", &[]);
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
    let port_plan_one = find_event(&events_one, "port_plan_written");
    let port_plan_two = find_event(&events_two, "port_plan_written");
    let request_one = find_event(&events_one, "port_plan_request_written");
    let request_ref_one = request_one
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("request artifact_ref one missing");
    assert_eq!(
        port_plan_one.get("request_ref").and_then(|v| v.as_str()),
        Some(request_ref_one)
    );
    assert!(
        artifact_path(&runtime_one, "port_plan_requests", request_ref_one).is_file(),
        "port plan request artifact should exist"
    );
    let plan_root_one = port_plan_one
        .get("plan_root_hash")
        .and_then(|v| v.as_str())
        .expect("plan_root_hash one missing");
    let plan_root_two = port_plan_two
        .get("plan_root_hash")
        .and_then(|v| v.as_str())
        .expect("plan_root_hash two missing");
    assert_eq!(plan_root_one, plan_root_two);

    let plan_ref_one = port_plan_one
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("plan artifact ref one missing");
    let plan_ref_two = port_plan_two
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("plan artifact ref two missing");
    let plan_bytes_one =
        fs::read(artifact_path(&runtime_one, "port_plans", plan_ref_one)).expect("read plan one");
    let plan_bytes_two =
        fs::read(artifact_path(&runtime_two, "port_plans", plan_ref_two)).expect("read plan two");
    assert_eq!(plan_bytes_one, plan_bytes_two);

    let plan_value: serde_json::Value =
        serde_json::from_slice(&plan_bytes_one).expect("plan one not json");
    assert_eq!(
        plan_value.get("schema").and_then(|v| v.as_str()),
        Some(PORT_PLAN_SCHEMA)
    );
    assert_no_nondeterministic_fields(&plan_value);
    assert_eq!(
        port_plan_one.get("node_count").and_then(|v| v.as_u64()),
        Some(
            plan_value
                .get("nodes")
                .and_then(|v| v.as_array())
                .expect("nodes array")
                .len() as u64
        )
    );
    assert_eq!(
        port_plan_one
            .get("invariant_count")
            .and_then(|v| v.as_u64()),
        Some(
            plan_value
                .get("invariants")
                .and_then(|v| v.as_array())
                .expect("invariants array")
                .len() as u64
        )
    );
    assert_eq!(
        port_plan_one
            .get("work_unit_count")
            .and_then(|v| v.as_u64()),
        Some(
            plan_value
                .get("work_units")
                .and_then(|v| v.as_array())
                .expect("work_units array")
                .len() as u64
        )
    );

    let capsule_event = find_event(&events_one, "run_capsule_written");
    let capsule_ref = capsule_event
        .get("capsule_ref")
        .and_then(|v| v.as_str())
        .expect("capsule_ref missing");
    let capsule_value: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_path(&runtime_one, "run_capsules", capsule_ref)).expect("read capsule"),
    )
    .expect("capsule json");
    let context_refs = capsule_value
        .get("context")
        .and_then(|v| v.get("context_refs"))
        .and_then(|v| v.as_array())
        .expect("context refs missing");
    let refs: Vec<&str> = context_refs.iter().filter_map(|v| v.as_str()).collect();
    let repo_identity_event = find_event(&events_one, "repo_identity_written");
    let repo_identity_ref = repo_identity_event
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("repo identity ref missing")
        .to_string();
    let repo_snapshot_event = find_event(&events_one, "repo_index_snapshot_written");
    let repo_snapshot_ref = repo_snapshot_event
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("repo snapshot ref missing")
        .to_string();
    assert!(refs.contains(&format!("repo_identity/{}", repo_identity_ref).as_str()));
    assert!(refs.contains(&format!("repo_index_snapshot/{}", repo_snapshot_ref).as_str()));
    assert!(refs.contains(&format!("port_plans/{}", plan_ref_one).as_str()));

    let gsama_path = runtime_one
        .join("memory")
        .join("gsama")
        .join("store_snapshot.json");
    assert!(gsama_path.is_file(), "gsama store snapshot missing");
    let gsama_value: serde_json::Value =
        serde_json::from_slice(&fs::read(&gsama_path).expect("read gsama snapshot"))
            .expect("gsama snapshot json");
    let entries = gsama_value
        .get("entries")
        .and_then(|v| v.as_array())
        .expect("gsama entries");
    assert!(
        !entries.is_empty(),
        "gsama entries must include port plan anchors"
    );
    let mut has_port_plan_tag = false;
    for entry in entries {
        let Some(tags) = entry.get("tags").and_then(|v| v.as_array()) else {
            continue;
        };
        if tags.iter().any(|tag| {
            tag.as_array()
                .and_then(|arr| {
                    if arr.len() != 2 {
                        return None;
                    }
                    Some(
                        arr[0].as_str() == Some("port_plan_ref")
                            && arr[1]
                                .as_str()
                                .map(|v| v.starts_with("port_plans/sha256:"))
                                .unwrap_or(false),
                    )
                })
                .unwrap_or(false)
        }) {
            has_port_plan_tag = true;
            break;
        }
    }
    assert!(
        has_port_plan_tag,
        "missing gsama port_plan_ref anchoring tag"
    );
}

#[test]
fn replay_mode_uses_recorded_provider_artifact_without_provider_call() {
    let runtime_record =
        std::env::temp_dir().join(format!("pie_port_plan_replay_record_{}", Uuid::new_v4()));
    let runtime_replay =
        std::env::temp_dir().join(format!("pie_port_plan_replay_replay_{}", Uuid::new_v4()));
    setup_runtime(&runtime_record);
    setup_runtime(&runtime_replay);

    let out_record = run_serverd_route_with_envs(&runtime_record, "record", &[]);
    assert!(
        out_record.status.success(),
        "record run failed: {}",
        String::from_utf8_lossy(&out_record.stderr)
    );

    let src_dir = runtime_record.join("artifacts").join("provider_responses");
    let dst_dir = runtime_replay.join("artifacts").join("provider_responses");
    fs::create_dir_all(&dst_dir).expect("create replay provider_responses dir");
    let entries = fs::read_dir(&src_dir).expect("read record provider_responses dir");
    for entry in entries {
        let entry = entry.expect("provider_responses dir entry");
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("provider response filename");
        fs::copy(&path, dst_dir.join(file_name)).expect("copy provider response artifact");
    }

    let out_replay = run_serverd_route_with_envs(
        &runtime_replay,
        "replay",
        &[("MOCK_PROVIDER_PANIC_IF_CALLED", "1")],
    );
    assert!(
        out_replay.status.success(),
        "replay run failed: {}",
        String::from_utf8_lossy(&out_replay.stderr)
    );
    let record_events = read_event_payloads(&runtime_record);
    let replay_events = read_event_payloads(&runtime_replay);
    let record_plan_event = find_event(&record_events, "port_plan_written");
    let replay_plan_event = find_event(&replay_events, "port_plan_written");
    let record_plan_ref = record_plan_event
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("record plan ref missing");
    let replay_plan_ref = replay_plan_event
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("replay plan ref missing");
    assert_eq!(record_plan_ref, replay_plan_ref);
    let replay_request_event = find_event(&replay_events, "port_plan_request_written");
    let replay_request_ref = replay_request_event
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("replay request ref missing");
    assert_eq!(
        replay_plan_event
            .get("request_ref")
            .and_then(|v| v.as_str()),
        Some(replay_request_ref)
    );
    assert!(
        artifact_path(&runtime_replay, "port_plan_requests", replay_request_ref).is_file(),
        "replay request artifact missing"
    );
    let record_bytes = fs::read(artifact_path(
        &runtime_record,
        "port_plans",
        record_plan_ref,
    ))
    .expect("read record plan bytes");
    let replay_bytes = fs::read(artifact_path(
        &runtime_replay,
        "port_plans",
        replay_plan_ref,
    ))
    .expect("read replay plan bytes");
    assert_eq!(record_bytes, replay_bytes);
    assert!(
        !find_events(&replay_events, "provider_response_artifact_loaded").is_empty(),
        "replay must load provider response artifact"
    );
}

#[test]
fn invalid_provider_payload_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_port_plan_invalid_{}", Uuid::new_v4()));
    setup_runtime(&runtime_root);

    let out = run_serverd_route_with_envs(
        &runtime_root,
        "record",
        &[("MOCK_PORT_PLAN_INVALID_MODE", "unknown_field")],
    );
    assert!(
        !out.status.success(),
        "run unexpectedly succeeded with invalid provider payload"
    );
    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("error output must be json");
    assert_eq!(
        value.get("error").and_then(|v| v.as_str()),
        Some("port_plan_provider_invalid")
    );

    let events = read_event_payloads(&runtime_root);
    assert!(
        find_events(&events, "port_plan_written").is_empty(),
        "port plan artifact must not be written on invalid provider payload"
    );
}

#[test]
fn multi_run_runtime_uses_latest_audit_repo_refs_when_repo_index_disabled() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_port_plan_multi_run_{}", Uuid::new_v4()));
    setup_runtime(&runtime_root);

    let out_first = run_serverd_route_with_envs(&runtime_root, "record", &[]);
    assert!(
        out_first.status.success(),
        "first run failed: {}",
        String::from_utf8_lossy(&out_first.stderr)
    );

    fs::write(
        runtime_root
            .join("workspace_data")
            .join("src")
            .join("lib.rs"),
        b"pub fn migrate_v2() {}\n",
    )
    .expect("write updated workspace for second run");
    let out_second = run_serverd_route_with_envs(&runtime_root, "record", &[]);
    assert!(
        out_second.status.success(),
        "second run failed: {}",
        String::from_utf8_lossy(&out_second.stderr)
    );

    let events_after_second = read_event_payloads(&runtime_root);
    let latest_repo_identity = find_last_event(&events_after_second, "repo_identity_written");
    let latest_repo_snapshot = find_last_event(&events_after_second, "repo_index_snapshot_written");
    let expected_repo_identity_root_hash = latest_repo_identity
        .get("root_hash")
        .and_then(|v| v.as_str())
        .expect("latest repo identity root hash missing")
        .to_string();
    let expected_repo_snapshot_root_hash = latest_repo_snapshot
        .get("root_hash")
        .and_then(|v| v.as_str())
        .expect("latest repo snapshot root hash missing")
        .to_string();
    let repo_identity_events_before =
        find_events(&events_after_second, "repo_identity_written").len();
    let repo_snapshot_events_before =
        find_events(&events_after_second, "repo_index_snapshot_written").len();

    write_repo_index_config_with_enabled(&runtime_root, false);
    write_retrieval_config_with_enabled(&runtime_root, false);
    fs::write(
        runtime_root
            .join("workspace_data")
            .join("src")
            .join("lib.rs"),
        b"pub fn migrate_v3() {}\n",
    )
    .expect("write updated workspace for third run");
    let out_third = run_serverd_route_with_envs(&runtime_root, "record", &[]);
    assert!(
        out_third.status.success(),
        "third run failed: {}",
        String::from_utf8_lossy(&out_third.stderr)
    );

    let events_after_third = read_event_payloads(&runtime_root);
    assert_eq!(
        find_events(&events_after_third, "repo_identity_written").len(),
        repo_identity_events_before,
        "repo identity should not be rebuilt when repo_index is disabled"
    );
    assert_eq!(
        find_events(&events_after_third, "repo_index_snapshot_written").len(),
        repo_snapshot_events_before,
        "repo snapshot should not be rebuilt when repo_index is disabled"
    );
    let latest_plan_event = find_last_event(&events_after_third, "port_plan_written");
    assert_eq!(
        latest_plan_event
            .get("repo_identity_root_hash")
            .and_then(|v| v.as_str()),
        Some(expected_repo_identity_root_hash.as_str())
    );
    assert_eq!(
        latest_plan_event
            .get("repo_index_snapshot_root_hash")
            .and_then(|v| v.as_str()),
        Some(expected_repo_snapshot_root_hash.as_str())
    );
}
