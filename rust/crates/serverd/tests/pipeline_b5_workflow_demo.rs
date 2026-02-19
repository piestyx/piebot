#![cfg(feature = "bin")]
// B5 closeout invariants:
// - replay is deterministic and provider-pure
// - replay does not mutate GSAMA snapshot bytes
// - continuity comes from GSAMA-sourced retrieval rows
// - replay runtime is pre-validated for isolation

use pie_audit_log::AuditAppender;
use serverd::output_contract::OUTPUT_CONTRACT_SCHEMA;
use serverd::retrieval::{load_retrieval_config, save_gsama_store, RETRIEVAL_CONFIG_SCHEMA};
use serverd::skills::SKILL_MANIFEST_SCHEMA;
use serverd::tools::execute::{execute_tool, TOOL_INPUT_NOOP_SCHEMA, TOOL_OUTPUT_NOOP_SCHEMA};
use serverd::tools::policy::{
    load_policy_config, ToolPolicyInput, TOOL_APPROVAL_REQUEST_SCHEMA, TOOL_POLICY_SCHEMA,
};
use serverd::tools::{ToolId, ToolRegistry, TOOL_SPEC_SCHEMA};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use uuid::Uuid;
mod common;

// Helper to hash GSAMA snapshot bytes for immutability assertions.
fn hash_bytes(bytes: &[u8]) -> String {
    pie_common::sha256_bytes(bytes)
}

static ENV_LOCK: Mutex<()> = Mutex::new(());
const WORKSPACE_POLICY_SCHEMA: &str = "serverd.workspace_policy.v1";
const CONTEXT_POINTER_SCHEMA: &str = "serverd.context_pointer.v1";

const FIXTURE_ALLOWED: &str = include_str!("fixtures/workflow/allowed.txt");
const FIXTURE_TARGET: &str = include_str!("fixtures/workflow/target.txt");

fn run_serverd_route(
    runtime_root: &Path,
    ticks: u64,
    delta: &str,
    provider_mode: &str,
    skill: Option<&str>,
    envs: &[(&str, &str)],
) -> Output {
    let mut cmd = Command::new(common::serverd_exe());
    cmd.arg("--mode")
        .arg("route")
        .arg("--ticks")
        .arg(ticks.to_string())
        .arg("--delta")
        .arg(delta)
        .arg("--provider")
        .arg(provider_mode)
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(skill_id) = skill {
        cmd.arg("--skill").arg(skill_id);
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run serverd route")
}

fn run_serverd_verify(runtime_root: &Path, run_id: &str) -> Output {
    Command::new(common::serverd_exe())
        .arg("verify")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--run-id")
        .arg(run_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run serverd verify")
}

fn run_serverd_approve(runtime_root: &Path, tool_id: &str, input_ref: &str) -> Output {
    Command::new(common::serverd_exe())
        .arg("approve")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--tool")
        .arg(tool_id)
        .arg("--input-ref")
        .arg(input_ref)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run serverd approve")
}

fn write_initial_state(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
}

fn write_router_config(runtime_root: &Path, default_provider: &str) {
    let dir = runtime_root.join("router");
    fs::create_dir_all(&dir).expect("create router dir");
    let value = serde_json::json!({
        "schema": "serverd.router.v1",
        "default_provider": default_provider,
        "routes": [],
        "policy": { "fail_if_unavailable": true }
    });
    let bytes = serde_json::to_vec(&value).expect("serialize router config");
    fs::write(dir.join("config.json"), bytes).expect("write router config");
}

fn write_skill_manifest(runtime_root: &Path, skill_id: &str, output_contract: &str) {
    let dir = runtime_root.join("skills").join(skill_id);
    fs::create_dir_all(&dir).expect("create skills dir");
    let value = serde_json::json!({
        "schema": SKILL_MANIFEST_SCHEMA,
        "skill_id": skill_id,
        "allowed_tools": ["tools.noop"],
        "tool_constraints": [],
        "prompt_template_refs": [],
        "output_contract": output_contract
    });
    let bytes = serde_json::to_vec(&value).expect("serialize skill manifest");
    fs::write(dir.join("skill.json"), bytes).expect("write skill manifest");
}

fn write_output_contract(runtime_root: &Path, contract_id: &str) {
    let dir = runtime_root.join("contracts");
    fs::create_dir_all(&dir).expect("create contracts dir");
    let value = serde_json::json!({
        "schema": OUTPUT_CONTRACT_SCHEMA,
        "contract_id": contract_id,
        "allowed_tool_calls": ["tools.noop"],
        "allowed_fields": ["schema", "output", "tool_call"],
        "required_fields": ["schema", "output", "tool_call"],
        "field_constraints": {
            "schema": { "type": "string" },
            "output": { "type": "string" },
            "tool_call.tool_id": { "type": "string" },
            "tool_call.input_ref": { "type": "string" }
        }
    });
    let bytes = serde_json::to_vec(&value).expect("serialize output contract");
    fs::write(dir.join(format!("{}.json", contract_id)), bytes).expect("write output contract");
}

fn write_noop_tool_spec(runtime_root: &Path, requires_approval: bool, filesystem: bool) {
    let dir = runtime_root.join("tools");
    fs::create_dir_all(&dir).expect("create tools dir");
    let value = serde_json::json!({
        "schema": TOOL_SPEC_SCHEMA,
        "id": "tools.noop",
        "input_schema": TOOL_INPUT_NOOP_SCHEMA,
        "output_schema": TOOL_OUTPUT_NOOP_SCHEMA,
        "deterministic": true,
        "risk_level": "low",
        "requires_approval": requires_approval,
        "requires_arming": false,
        "filesystem": filesystem,
        "version": "v1"
    });
    let bytes = serde_json::to_vec(&value).expect("serialize tool spec");
    fs::write(dir.join("noop.json"), bytes).expect("write tool spec");
}

fn write_tool_policy(runtime_root: &Path, allowed_tools: &[&str]) {
    let dir = runtime_root.join("tools");
    fs::create_dir_all(&dir).expect("create tools dir");
    let value = serde_json::json!({
        "schema": TOOL_POLICY_SCHEMA,
        "allowed_tools": allowed_tools,
        "default_allow": false
    });
    let bytes = serde_json::to_vec(&value).expect("serialize tool policy");
    fs::write(dir.join("policy.json"), bytes).expect("write tool policy");
}

fn write_workspace_policy(runtime_root: &Path) {
    let dir = runtime_root.join("workspace");
    fs::create_dir_all(&dir).expect("create workspace dir");
    let value = serde_json::json!({
        "schema": WORKSPACE_POLICY_SCHEMA,
        "enabled": true,
        "workspace_root": "workspace",
        "allow_repo_root": false,
        "per_run_dir": false
    });
    let bytes = serde_json::to_vec(&value).expect("serialize workspace policy");
    fs::write(dir.join("policy.json"), bytes).expect("write workspace policy");
}

fn write_fixture_workspace(runtime_root: &Path) {
    let dir = runtime_root.join("workspace");
    fs::create_dir_all(&dir).expect("create workspace root");
    fs::write(dir.join("allowed.txt"), FIXTURE_ALLOWED.as_bytes()).expect("write allowed fixture");
    fs::write(dir.join("target.txt"), FIXTURE_TARGET.as_bytes()).expect("write target fixture");
}

fn write_retrieval_config(runtime_root: &Path) {
    let dir = runtime_root.join("retrieval");
    fs::create_dir_all(&dir).expect("create retrieval dir");
    let default_config = serverd::retrieval::RetrievalConfig::default();
    let value = serde_json::json!({
        "schema": RETRIEVAL_CONFIG_SCHEMA,
        "enabled": true,
        "kind": "gsama",
        "sources": ["episodic", "working"],
        "namespaces_allowlist": ["contexts"],
        "max_items": 16,
        "max_bytes": 8192,
        "default_recency_ticks": 32,
        "default_tags": [],
        "gsama_vector_source_mode": "hash_fallback_only",
        "gsama_allow_hash_embedder": true,
        "gsama_hash_embedder_dim": default_config.gsama_hash_embedder_dim,
        "gsama_store_capacity": default_config.gsama_store_capacity,
        "gsama_vector_dim": default_config.gsama_vector_dim
    });
    let bytes = serde_json::to_vec(&value).expect("serialize retrieval config");
    fs::write(dir.join("config.json"), bytes).expect("write retrieval config");
}

fn initialize_empty_gsama_store(runtime_root: &Path) {
    let config =
        load_retrieval_config(runtime_root).expect("load retrieval config for test runtime");
    let vector_dim = config.gsama_vector_dim;
    let capacity = config.gsama_store_capacity;
    let store = gsama_core::Store::new(vector_dim, capacity);
    save_gsama_store(runtime_root, &store).expect("write empty gsama store");
}

fn setup_demo_runtime(runtime_root: &Path, requires_approval: bool, filesystem: bool) {
    write_initial_state(runtime_root);
    write_router_config(runtime_root, "mock_tool");
    write_skill_manifest(runtime_root, "demo", "demo.contract");
    write_output_contract(runtime_root, "demo.contract");
    write_noop_tool_spec(runtime_root, requires_approval, filesystem);
    write_tool_policy(runtime_root, &["tools.noop"]);
    write_workspace_policy(runtime_root);
    write_fixture_workspace(runtime_root);
    write_retrieval_config(runtime_root);
    initialize_empty_gsama_store(runtime_root);
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

// Assert replay runtime isolation before replay execution.
fn assert_replay_runtime_isolation(runtime_root: &Path) {
    let allow_top_level = [
        "artifacts",
        "contracts",
        "memory",
        "retrieval",
        "router",
        "skills",
        "state",
        "tools",
        "workspace",
    ];
    for entry in std::fs::read_dir(runtime_root).expect("read runtime root") {
        let entry = entry.expect("runtime root entry");
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<invalid>");
        if !allow_top_level.contains(&name) {
            panic!(
                "replay runtime contains disallowed top-level path: {:?}",
                path
            );
        }
    }

    // Recursive walk to deny audit files anywhere.
    let mut dirs_to_visit = vec![runtime_root.to_path_buf()];
    while let Some(current) = dirs_to_visit.pop() {
        for entry in std::fs::read_dir(&current).expect("read dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                dirs_to_visit.push(path);
                continue;
            }
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // Deny audit files anywhere
            if file_name == "audit_rust.jsonl" {
                panic!("replay runtime must not contain audit file: {:?}", path);
            }
        }
    }
}

// Stage 2: Future-safe ref extraction from result rows
fn result_row_ref(row: &serde_json::Value) -> Option<&str> {
    row.get("ref")
        .and_then(|v| v.as_str())
        .or_else(|| row.get("context_ref").and_then(|v| v.as_str()))
        .or_else(|| row.get("artifact_ref").and_then(|v| v.as_str()))
}

fn parse_run_output(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("route output json")
}

fn parse_verify_output(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("verify output json")
}

fn copy_provider_response_artifact(
    source_runtime: &Path,
    destination_runtime: &Path,
    request_hash: &str,
) {
    let source = artifact_path(source_runtime, "provider_responses", request_hash);
    let destination = artifact_path(destination_runtime, "provider_responses", request_hash);
    fs::create_dir_all(
        destination
            .parent()
            .expect("provider_responses destination parent"),
    )
    .expect("create provider_responses destination dir");
    let bytes = fs::read(source).expect("read source provider response artifact");
    fs::write(destination, bytes).expect("write provider response artifact");
}

fn read_capsule_provider_mode(runtime_root: &Path, capsule_ref: &str) -> String {
    let path = artifact_path(runtime_root, "run_capsules", capsule_ref);
    let bytes = fs::read(path).expect("read run capsule");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("run capsule json");
    value
        .get("run")
        .and_then(|v| v.get("provider_mode"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn split_ref_with_default(value: &str, default_namespace: &str) -> (String, String) {
    match value.split_once('/') {
        Some((namespace, reference)) if !namespace.is_empty() && !reference.is_empty() => {
            (namespace.to_string(), reference.to_string())
        }
        _ => (default_namespace.to_string(), value.to_string()),
    }
}

fn read_artifact_json(
    runtime_root: &Path,
    namespace: &str,
    artifact_ref: &str,
) -> serde_json::Value {
    let bytes = fs::read(artifact_path(runtime_root, namespace, artifact_ref))
        .expect("read artifact bytes");
    serde_json::from_slice(&bytes).expect("artifact json")
}

fn read_artifact_json_from_ref(
    runtime_root: &Path,
    artifact_ref: &str,
    default_namespace: &str,
) -> serde_json::Value {
    let (namespace, reference) = split_ref_with_default(artifact_ref, default_namespace);
    read_artifact_json(runtime_root, &namespace, &reference)
}

fn copy_gsama_store_snapshot(source_runtime: &Path, destination_runtime: &Path) {
    // Stage 5: Snapshot copy isolation - only copy store_snapshot.json, no working memory
    let source = source_runtime
        .join("memory")
        .join("gsama")
        .join("store_snapshot.json");
    let destination = destination_runtime
        .join("memory")
        .join("gsama")
        .join("store_snapshot.json");
    fs::create_dir_all(
        destination
            .parent()
            .expect("gsama snapshot destination parent"),
    )
    .expect("create gsama snapshot destination dir");
    let bytes = fs::read(source).expect("read source gsama snapshot");
    fs::write(destination, bytes).expect("write gsama snapshot");
}

fn copy_artifact_ref(
    source_runtime: &Path,
    destination_runtime: &Path,
    artifact_ref: &str,
    default_namespace: &str,
) {
    let (namespace, reference) = split_ref_with_default(artifact_ref, default_namespace);
    let source = artifact_path(source_runtime, &namespace, &reference);
    let destination = artifact_path(destination_runtime, &namespace, &reference);
    fs::create_dir_all(destination.parent().expect("artifact destination parent"))
        .expect("create artifact destination dir");
    let bytes = fs::read(source).expect("read source artifact");
    fs::write(destination, bytes).expect("write destination artifact");
}

fn read_gsama_store_snapshot(runtime_root: &Path) -> serde_json::Value {
    let path = runtime_root
        .join("memory")
        .join("gsama")
        .join("store_snapshot.json");
    let bytes = fs::read(path).expect("read gsama snapshot");
    serde_json::from_slice(&bytes).expect("gsama snapshot json")
}

fn gsama_context_refs(snapshot: &serde_json::Value) -> Vec<String> {
    let mut refs: Vec<String> = Vec::new();
    let entries = snapshot
        .get("entries")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for entry in entries {
        let tags = entry
            .get("tags")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for tag in tags {
            let Some(pair) = tag.as_array() else {
                continue;
            };
            if pair.len() != 2 {
                continue;
            }
            if pair[0].as_str() == Some("context_ref") {
                if let Some(value) = pair[1].as_str() {
                    refs.push(value.to_string());
                }
            }
        }
    }
    refs.sort();
    refs.dedup();
    refs
}

fn event_types_index(types: &[String], event_type: &str) -> usize {
    types
        .iter()
        .position(|v| v == event_type)
        .unwrap_or_else(|| panic!("missing {}", event_type))
}

fn assert_before(types: &[String], first: &str, second: &str) {
    let first_idx = event_types_index(types, first);
    let second_idx = event_types_index(types, second);
    assert!(
        first_idx < second_idx,
        "{} must occur before {}",
        first,
        second
    );
}

#[test]
fn workflow_gsama_continuity_survives_context_reset() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let runtime_record =
        std::env::temp_dir().join(format!("pie_b5_context_seed_{}", Uuid::new_v4()));
    let runtime_prep = std::env::temp_dir().join(format!("pie_b5_context_prep_{}", Uuid::new_v4()));
    let runtime_replay =
        std::env::temp_dir().join(format!("pie_b5_context_reset_{}", Uuid::new_v4()));
    setup_demo_runtime(&runtime_record, false, true);
    setup_demo_runtime(&runtime_prep, false, true);
    setup_demo_runtime(&runtime_replay, false, true);

    let record_envs = [
        ("TOOLS_ENABLE", "1"),
        ("TOOLS_ARM", "1"),
        ("MOCK_TOOL_INPUT_PATH", "allowed.txt"),
    ];
    let out_record = run_serverd_route(
        &runtime_record,
        1,
        "tick:0",
        "record",
        Some("demo"),
        &record_envs,
    );
    assert!(
        out_record.status.success(),
        "seed record run failed: {}",
        String::from_utf8_lossy(&out_record.stderr)
    );
    let seed_events = read_event_payloads(&runtime_record);
    let run1_request_hash = find_event(&seed_events, "provider_request_written")
        .get("request_hash")
        .and_then(|v| v.as_str())
        .expect("missing request_hash")
        .to_string();
    let gsama_snapshot = read_gsama_store_snapshot(&runtime_record);
    let continuity_context_refs = gsama_context_refs(&gsama_snapshot);
    assert!(
        !continuity_context_refs.is_empty(),
        "seed run must emit at least one GSAMA context pointer"
    );
    let continuity_context_ref = continuity_context_refs[0].clone();

    for runtime_target in [&runtime_prep, &runtime_replay] {
        copy_gsama_store_snapshot(&runtime_record, runtime_target);
        for context_ref in &continuity_context_refs {
            copy_artifact_ref(&runtime_record, runtime_target, context_ref, "contexts");
        }
    }
    let out_prep = run_serverd_route(
        &runtime_prep,
        1,
        "tick:0",
        "record",
        Some("demo"),
        &record_envs,
    );
    assert!(
        out_prep.status.success(),
        "context replay prep record run failed: {}",
        String::from_utf8_lossy(&out_prep.stderr)
    );
    let prep_events = read_event_payloads(&runtime_prep);
    let run2_request_hash = find_event(&prep_events, "provider_request_written")
        .get("request_hash")
        .and_then(|v| v.as_str())
        .expect("missing prep request_hash")
        .to_string();
    copy_provider_response_artifact(&runtime_prep, &runtime_replay, &run2_request_hash);
    assert_ne!(
        run1_request_hash, run2_request_hash,
        "run 2 request hash should differ once run 1 continuity artifacts exist"
    );

    let source_working = runtime_record.join("memory").join("working.json");
    let replay_working = runtime_replay.join("memory").join("working.json");
    fs::create_dir_all(
        replay_working
            .parent()
            .expect("working memory destination parent"),
    )
    .expect("create working memory destination dir");
    if source_working.is_file() {
        let bytes = fs::read(source_working).expect("read source working memory");
        fs::write(&replay_working, bytes).expect("write replay working memory");
    } else {
        fs::write(
            &replay_working,
            br#"{"schema":"serverd.working_memory.v1","tick_index":0,"entries":[]}"#,
        )
        .expect("write placeholder working memory");
    }
    assert!(
        replay_working.is_file(),
        "working memory snapshot should exist"
    );
    fs::remove_file(&replay_working).expect("remove working memory snapshot");
    assert!(
        !replay_working.exists(),
        "working memory snapshot should be removed before replay"
    );

    // Ensure replay runtime isolation before running.
    assert_replay_runtime_isolation(&runtime_replay);
    let snapshot_path = runtime_replay
        .join("memory")
        .join("gsama")
        .join("store_snapshot.json");
    let snapshot_before = fs::read(&snapshot_path).expect("read gsama snapshot before replay");
    let hash_before = hash_bytes(&snapshot_before);

    let replay_envs = [
        ("TOOLS_ENABLE", "1"),
        ("TOOLS_ARM", "1"),
        ("MOCK_TOOL_INPUT_PATH", "allowed.txt"),
        ("MOCK_PROVIDER_PANIC_IF_CALLED", "1"),
    ];
    let out_replay = run_serverd_route(
        &runtime_replay,
        1,
        "tick:0",
        "replay",
        Some("demo"),
        &replay_envs,
    );
    assert!(
        out_replay.status.success(),
        "replay after context reset failed: {}",
        String::from_utf8_lossy(&out_replay.stderr)
    );

    let snapshot_after = fs::read(&snapshot_path).expect("read gsama snapshot after replay");
    let hash_after = hash_bytes(&snapshot_after);
    assert_eq!(
        hash_before, hash_after,
        "GSAMA snapshot must not change during replay"
    );

    let replay_events = read_event_payloads(&runtime_replay);
    let replay_types = read_event_types(&runtime_replay);
    assert!(replay_types
        .iter()
        .any(|event_type| event_type == "provider_response_artifact_loaded"));
    assert!(!replay_types
        .iter()
        .any(|event_type| event_type == "provider_response_artifact_written"));
    // retrieval_executed must occur before context_selected.
    assert_before(&replay_types, "retrieval_executed", "context_selected");
    assert!(replay_types
        .iter()
        .any(|event_type| event_type == "retrieval_executed"));
    let results_ref = find_event(&replay_events, "retrieval_results_written")
        .get("results_ref")
        .and_then(|v| v.as_str())
        .expect("missing retrieval results_ref")
        .to_string();
    let retrieval_results = read_artifact_json(&runtime_replay, "retrieval_results", &results_ref);
    let context_candidates = value_as_strings(
        retrieval_results
            .get("context_candidates")
            .unwrap_or(&serde_json::Value::Null),
    );
    assert!(
        context_candidates
            .iter()
            .any(|value| value == &continuity_context_ref),
        "replay retrieval should still return GSAMA context pointer after context reset"
    );
    let continuity_from_gsama = retrieval_results
        .get("results")
        .and_then(|v| v.as_array())
        .map(|rows| {
            rows.iter().any(|row| {
                row.get("source").and_then(|v| v.as_str()) == Some("gsama")
                    && result_row_ref(row) == Some(continuity_context_ref.as_str())
            })
        })
        .unwrap_or(false);
    assert!(
        continuity_from_gsama,
        "replay continuity context pointer must come from a GSAMA-sourced result row"
    );
}

fn value_as_strings(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug)]
struct ReplayRunEvidence {
    run_id: String,
    state_hash: String,
    query_ref: String,
    results_ref: String,
    result_set_hash: String,
    context_selected_ref: String,
    capsule_ref: String,
}

fn run_replay_and_collect(
    runtime_root: &Path,
    replay_envs: &[(&str, &str)],
    continuity_context_ref: &str,
    request_hash: &str,
) -> ReplayRunEvidence {
    let out_replay = run_serverd_route(
        runtime_root,
        1,
        "tick:0",
        "replay",
        Some("demo"),
        replay_envs,
    );
    assert!(
        out_replay.status.success(),
        "replay run failed: {}",
        String::from_utf8_lossy(&out_replay.stderr)
    );
    let replay_value = parse_run_output(&out_replay);
    let run_id = replay_value
        .get("run_id")
        .and_then(|v| v.as_str())
        .expect("missing replay run_id")
        .to_string();
    let state_hash = replay_value
        .get("state_hash")
        .and_then(|v| v.as_str())
        .expect("missing replay state_hash")
        .to_string();
    let replay_events = read_event_payloads(runtime_root);
    let replay_types = read_event_types(runtime_root);
    assert!(replay_types
        .iter()
        .any(|event_type| event_type == "provider_response_artifact_loaded"));
    assert!(!replay_types
        .iter()
        .any(|event_type| event_type == "provider_response_artifact_written"));
    assert_before(&replay_types, "retrieval_query_written", "context_selected");
    assert_before(
        &replay_types,
        "retrieval_results_written",
        "context_selected",
    );
    let query_ref = find_event(&replay_events, "retrieval_query_written")
        .get("query_ref")
        .and_then(|v| v.as_str())
        .expect("missing retrieval query_ref")
        .to_string();
    let results_ref = find_event(&replay_events, "retrieval_results_written")
        .get("results_ref")
        .and_then(|v| v.as_str())
        .expect("missing retrieval results_ref")
        .to_string();
    let result_set_hash = find_event(&replay_events, "retrieval_executed")
        .get("result_set_hash")
        .and_then(|v| v.as_str())
        .expect("missing retrieval result_set_hash")
        .to_string();
    let retrieval_results = read_artifact_json(runtime_root, "retrieval_results", &results_ref);
    let context_candidates = value_as_strings(
        retrieval_results
            .get("context_candidates")
            .unwrap_or(&serde_json::Value::Null),
    );
    assert!(
        context_candidates
            .iter()
            .any(|value| value == continuity_context_ref),
        "retrieval context_candidates must include GSAMA context pointer"
    );
    // Confirm GSAMA is the active retrieval substrate.
    let has_gsama_source = retrieval_results
        .get("results")
        .and_then(|v| v.as_array())
        .map(|rows| {
            rows.iter()
                .any(|row| row.get("source").and_then(|v| v.as_str()) == Some("gsama"))
        })
        .unwrap_or(false);
    assert!(
        has_gsama_source,
        "retrieval results must include at least one GSAMA source result"
    );
    // Enforce that continuity_context_ref is returned via a GSAMA-sourced result row.
    let continuity_from_gsama = retrieval_results
        .get("results")
        .and_then(|v| v.as_array())
        .map(|rows| {
            rows.iter().any(|row| {
                row.get("source").and_then(|v| v.as_str()) == Some("gsama")
                    && result_row_ref(row) == Some(continuity_context_ref)
            })
        })
        .unwrap_or(false);
    assert!(
        continuity_from_gsama,
        "continuity_context_ref must be returned via a GSAMA-sourced result row"
    );
    // Ensure continuity context pointer came from GSAMA, not episodic/working.
    let context_selected_ref = find_event(&replay_events, "context_selected")
        .get("context_ref")
        .and_then(|v| v.as_str())
        .expect("missing context_selected context_ref")
        .to_string();
    let context_selection = read_artifact_json(runtime_root, "contexts", &context_selected_ref);
    let selected_context_refs = value_as_strings(
        context_selection
            .get("context_refs")
            .unwrap_or(&serde_json::Value::Null),
    );
    assert!(
        selected_context_refs
            .iter()
            .any(|value| value == continuity_context_ref),
        "context selection must include GSAMA context pointer"
    );
    let capsule_ref = find_event(&replay_events, "run_capsule_written")
        .get("capsule_ref")
        .and_then(|v| v.as_str())
        .expect("missing replay capsule_ref")
        .to_string();
    let capsule = read_artifact_json(runtime_root, "run_capsules", &capsule_ref);
    assert_eq!(
        capsule
            .get("run")
            .and_then(|run| run.get("provider_mode"))
            .and_then(|v| v.as_str()),
        Some("replay")
    );
    let capsule_provider_response_ref = capsule
        .get("providers")
        .and_then(|v| v.as_array())
        .and_then(|providers| providers.first())
        .and_then(|provider| provider.get("provider_response_artifact_ref"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(capsule_provider_response_ref, request_hash);
    let capsule_context_refs = capsule
        .get("context")
        .and_then(|context| context.get("context_refs"))
        .map(value_as_strings)
        .unwrap_or_default();
    assert!(
        capsule_context_refs
            .iter()
            .any(|value| value == &context_selected_ref),
        "capsule context refs must include selected context artifact ref"
    );
    ReplayRunEvidence {
        run_id,
        state_hash,
        query_ref,
        results_ref,
        result_set_hash,
        context_selected_ref,
        capsule_ref,
    }
}

#[test]
fn workflow_record_then_replay_is_deterministic_and_replayable() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let runtime_record = std::env::temp_dir().join(format!("pie_b5_record_{}", Uuid::new_v4()));
    let runtime_prep = std::env::temp_dir().join(format!("pie_b5_replay_prep_{}", Uuid::new_v4()));
    let runtime_replay_a = std::env::temp_dir().join(format!("pie_b5_replay_a_{}", Uuid::new_v4()));
    let runtime_replay_b = std::env::temp_dir().join(format!("pie_b5_replay_b_{}", Uuid::new_v4()));
    setup_demo_runtime(&runtime_record, false, true);
    setup_demo_runtime(&runtime_prep, false, true);
    setup_demo_runtime(&runtime_replay_a, false, true);
    setup_demo_runtime(&runtime_replay_b, false, true);

    let record_envs = [
        ("TOOLS_ENABLE", "1"),
        ("TOOLS_ARM", "1"),
        ("MOCK_TOOL_INPUT_PATH", "allowed.txt"),
    ];
    let out_record = run_serverd_route(
        &runtime_record,
        1,
        "tick:0",
        "record",
        Some("demo"),
        &record_envs,
    );
    assert!(
        out_record.status.success(),
        "record run failed: {}",
        String::from_utf8_lossy(&out_record.stderr)
    );
    let record_value = parse_run_output(&out_record);
    let record_run_id = record_value
        .get("run_id")
        .and_then(|v| v.as_str())
        .expect("missing record run_id")
        .to_string();
    let record_state_hash = record_value
        .get("state_hash")
        .and_then(|v| v.as_str())
        .expect("missing record state_hash")
        .to_string();
    let record_events = read_event_payloads(&runtime_record);
    let record_types = read_event_types(&runtime_record);
    assert_before(&record_types, "retrieval_query_written", "context_selected");
    assert_before(
        &record_types,
        "retrieval_results_written",
        "context_selected",
    );
    assert!(record_types
        .iter()
        .any(|e| e == "retrieval_results_written"));
    // retrieval_executed must occur before context_selected in record run.
    assert_before(&record_types, "retrieval_executed", "context_selected");
    assert!(record_types.iter().any(|e| e == "retrieval_executed"));
    assert!(record_types.iter().any(|e| e == "tool_executed"));
    assert!(record_types.iter().any(|e| e == "run_capsule_written"));
    assert!(record_types.iter().any(|e| e == "tool_executed"));
    assert!(record_types.iter().any(|e| e == "run_capsule_written"));
    let run1_request_hash = find_event(&record_events, "provider_request_written")
        .get("request_hash")
        .and_then(|v| v.as_str())
        .expect("missing request_hash")
        .to_string();
    let capsule_ref_record = find_event(&record_events, "run_capsule_written")
        .get("capsule_ref")
        .and_then(|v| v.as_str())
        .expect("missing record capsule_ref")
        .to_string();
    assert_eq!(
        read_capsule_provider_mode(&runtime_record, &capsule_ref_record),
        "record"
    );
    let gsama_snapshot = read_gsama_store_snapshot(&runtime_record);
    let gsama_entries = gsama_snapshot
        .get("entries")
        .and_then(|v| v.as_array())
        .expect("gsama entries array");
    assert_eq!(
        gsama_entries.len(),
        1,
        "run 1 must append exactly one GSAMA entry"
    );
    let continuity_context_refs = gsama_context_refs(&gsama_snapshot);
    assert_eq!(
        continuity_context_refs.len(),
        1,
        "run 1 GSAMA entry must include one context pointer ref"
    );
    let continuity_context_ref = continuity_context_refs[0].clone();
    let context_pointer =
        read_artifact_json_from_ref(&runtime_record, &continuity_context_ref, "contexts");
    assert_eq!(
        context_pointer.get("schema").and_then(|v| v.as_str()),
        Some(CONTEXT_POINTER_SCHEMA)
    );
    assert_eq!(
        context_pointer.get("run_id").and_then(|v| v.as_str()),
        Some(record_run_id.as_str())
    );
    assert!(
        context_pointer
            .get("episode_ref")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .starts_with("episodes/"),
        "context pointer must anchor to episode ref"
    );

    for runtime_replay in [&runtime_prep, &runtime_replay_a, &runtime_replay_b] {
        copy_gsama_store_snapshot(&runtime_record, runtime_replay);
        for context_ref in &continuity_context_refs {
            copy_artifact_ref(&runtime_record, runtime_replay, context_ref, "contexts");
        }
    }
    let out_prep = run_serverd_route(
        &runtime_prep,
        1,
        "tick:0",
        "record",
        Some("demo"),
        &record_envs,
    );
    assert!(
        out_prep.status.success(),
        "replay prep record run failed: {}",
        String::from_utf8_lossy(&out_prep.stderr)
    );
    let prep_events = read_event_payloads(&runtime_prep);
    let run2_request_hash = find_event(&prep_events, "provider_request_written")
        .get("request_hash")
        .and_then(|v| v.as_str())
        .expect("missing prep request_hash")
        .to_string();
    copy_provider_response_artifact(&runtime_prep, &runtime_replay_a, &run2_request_hash);
    copy_provider_response_artifact(&runtime_prep, &runtime_replay_b, &run2_request_hash);
    assert_ne!(
        run1_request_hash, run2_request_hash,
        "run 2 request hash should differ once run 1 continuity artifacts exist"
    );

    // Ensure replay runtime isolation before running.
    assert_replay_runtime_isolation(&runtime_replay_a);
    assert_replay_runtime_isolation(&runtime_replay_b);

    let replay_envs = [
        ("TOOLS_ENABLE", "1"),
        ("TOOLS_ARM", "1"),
        ("MOCK_TOOL_INPUT_PATH", "allowed.txt"),
        ("MOCK_PROVIDER_PANIC_IF_CALLED", "1"),
    ];
    let replay_a = run_replay_and_collect(
        &runtime_replay_a,
        &replay_envs,
        &continuity_context_ref,
        &run2_request_hash,
    );
    let replay_b = run_replay_and_collect(
        &runtime_replay_b,
        &replay_envs,
        &continuity_context_ref,
        &run2_request_hash,
    );
    assert_eq!(replay_a.state_hash, replay_b.state_hash);
    assert_eq!(replay_a.query_ref, replay_b.query_ref);
    assert_eq!(replay_a.results_ref, replay_b.results_ref);
    assert_eq!(replay_a.result_set_hash, replay_b.result_set_hash);
    assert_eq!(replay_a.context_selected_ref, replay_b.context_selected_ref);
    assert_eq!(replay_a.capsule_ref, replay_b.capsule_ref);

    let verify_record = run_serverd_verify(&runtime_record, &record_run_id);
    assert!(
        verify_record.status.success(),
        "verify record failed: {}",
        String::from_utf8_lossy(&verify_record.stderr)
    );
    let verify_record_value = parse_verify_output(&verify_record);
    assert_eq!(
        verify_record_value
            .get("final_state_hash")
            .and_then(|v| v.as_str()),
        Some(record_state_hash.as_str())
    );
    let verify_replay_a = run_serverd_verify(&runtime_replay_a, &replay_a.run_id);
    assert!(
        verify_replay_a.status.success(),
        "verify replay A failed: {}",
        String::from_utf8_lossy(&verify_replay_a.stderr)
    );
    let verify_replay_a_value = parse_verify_output(&verify_replay_a);
    assert_eq!(
        verify_replay_a_value
            .get("final_state_hash")
            .and_then(|v| v.as_str()),
        Some(replay_a.state_hash.as_str())
    );
    let verify_replay_b = run_serverd_verify(&runtime_replay_b, &replay_b.run_id);
    assert!(
        verify_replay_b.status.success(),
        "verify replay B failed: {}",
        String::from_utf8_lossy(&verify_replay_b.stderr)
    );
    let verify_replay_b_value = parse_verify_output(&verify_replay_b);
    assert_eq!(
        verify_replay_b_value
            .get("final_state_hash")
            .and_then(|v| v.as_str()),
        Some(replay_b.state_hash.as_str())
    );
}

#[test]
fn workflow_tool_approval_is_fail_closed_then_allows_execution_after_approval() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let runtime_seed = std::env::temp_dir().join(format!("pie_b5_seed_{}", Uuid::new_v4()));
    let runtime_fail = std::env::temp_dir().join(format!("pie_b5_approval_{}", Uuid::new_v4()));
    setup_demo_runtime(&runtime_seed, false, false);
    setup_demo_runtime(&runtime_fail, true, false);

    let envs = [
        ("TOOLS_ENABLE", "1"),
        ("TOOLS_ARM", "1"),
        ("MOCK_TOOL_INPUT_PATH", "allowed.txt"),
    ];
    let out_seed = run_serverd_route(&runtime_seed, 1, "tick:0", "record", Some("demo"), &envs);
    assert!(
        out_seed.status.success(),
        "seed record run failed: {}",
        String::from_utf8_lossy(&out_seed.stderr)
    );
    let seed_events = read_event_payloads(&runtime_seed);
    let request_hash = find_event(&seed_events, "provider_request_written")
        .get("request_hash")
        .and_then(|v| v.as_str())
        .expect("missing request_hash")
        .to_string();
    copy_provider_response_artifact(&runtime_seed, &runtime_fail, &request_hash);

    let fail_envs = [
        ("TOOLS_ENABLE", "1"),
        ("TOOLS_ARM", "1"),
        ("MOCK_TOOL_INPUT_PATH", "allowed.txt"),
        ("MOCK_PROVIDER_PANIC_IF_CALLED", "1"),
    ];
    let out_fail = run_serverd_route(
        &runtime_fail,
        1,
        "tick:0",
        "replay",
        Some("demo"),
        &fail_envs,
    );
    assert!(
        !out_fail.status.success(),
        "expected fail-closed approval gate"
    );
    let fail_value: serde_json::Value =
        serde_json::from_slice(&out_fail.stdout).expect("fail output json");
    assert_eq!(
        fail_value.get("error").and_then(|v| v.as_str()),
        Some("tool_approval_required")
    );
    let fail_events = read_event_payloads(&runtime_fail);
    let fail_types = read_event_types(&runtime_fail);
    assert!(fail_types
        .iter()
        .any(|e| e == "provider_response_artifact_loaded"));
    assert!(fail_types.iter().any(|e| e == "tool_approval_required"));
    assert!(!fail_types.iter().any(|e| e == "tool_executed"));
    let approval_ref = find_event(&fail_events, "tool_approval_required")
        .get("approval_ref")
        .and_then(|v| v.as_str())
        .expect("missing approval_ref")
        .to_string();
    let approval_request_value: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_path(&runtime_fail, "approvals", &approval_ref))
            .expect("read approval request artifact"),
    )
    .expect("approval request json");
    assert_eq!(
        approval_request_value
            .get("schema")
            .and_then(|v| v.as_str()),
        Some(TOOL_APPROVAL_REQUEST_SCHEMA)
    );
    let input_ref = approval_request_value
        .get("input_ref")
        .and_then(|v| v.as_str())
        .expect("approval request input_ref")
        .to_string();

    let out_approve = run_serverd_approve(&runtime_fail, "tools.noop", &input_ref);
    assert!(
        out_approve.status.success(),
        "approve failed: {}",
        String::from_utf8_lossy(&out_approve.stderr)
    );
    let approve_value: serde_json::Value =
        serde_json::from_slice(&out_approve.stdout).expect("approve output json");
    assert_eq!(
        approve_value.get("ok").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        approve_value.get("approval_ref").and_then(|v| v.as_str()),
        Some(approval_ref.as_str())
    );

    std::env::set_var("TOOLS_ENABLE", "1");
    std::env::set_var("TOOLS_ARM", "1");
    let registry = ToolRegistry::load_tools(&runtime_fail).expect("load tools");
    let tool_id = ToolId::parse("tools.noop").expect("parse tools.noop");
    let spec = registry.get(&tool_id).expect("missing tools.noop spec");
    let policy = load_policy_config(&runtime_fail).expect("load policy");
    let mut audit = AuditAppender::open(runtime_fail.join("logs").join("audit_rust.jsonl"))
        .expect("open audit log");
    let input = ToolPolicyInput {
        tool_id: &spec.id,
        spec,
        mode: "route",
        request_hash: &request_hash,
        input_ref: &input_ref,
    };
    let output_ref = execute_tool(&runtime_fail, &registry, &policy, &input, None, &mut audit)
        .expect("execute tool after approval");
    std::env::remove_var("TOOLS_ENABLE");
    std::env::remove_var("TOOLS_ARM");

    let output_path = artifact_path(&runtime_fail, "tool_outputs", &output_ref);
    assert!(output_path.is_file(), "tool output artifact missing");
    let final_types = read_event_types(&runtime_fail);
    assert!(final_types.iter().any(|e| e == "approval_created"));
    assert!(final_types.iter().any(|e| e == "tool_executed"));
}
