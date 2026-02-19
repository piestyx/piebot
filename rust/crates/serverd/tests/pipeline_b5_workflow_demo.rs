#![cfg(feature = "bin")]

use pie_audit_log::AuditAppender;
use serverd::output_contract::OUTPUT_CONTRACT_SCHEMA;
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

static ENV_LOCK: Mutex<()> = Mutex::new(());
const WORKSPACE_POLICY_SCHEMA: &str = "serverd.workspace_policy.v1";

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

fn setup_demo_runtime(runtime_root: &Path, requires_approval: bool, filesystem: bool) {
    write_initial_state(runtime_root);
    write_router_config(runtime_root, "mock_tool");
    write_skill_manifest(runtime_root, "demo", "demo.contract");
    write_output_contract(runtime_root, "demo.contract");
    write_noop_tool_spec(runtime_root, requires_approval, filesystem);
    write_tool_policy(runtime_root, &["tools.noop"]);
    write_workspace_policy(runtime_root);
    write_fixture_workspace(runtime_root);
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

#[test]
fn workflow_record_then_replay_is_deterministic_and_replayable() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let runtime_record = std::env::temp_dir().join(format!("pie_b5_record_{}", Uuid::new_v4()));
    let runtime_replay = std::env::temp_dir().join(format!("pie_b5_replay_{}", Uuid::new_v4()));
    setup_demo_runtime(&runtime_record, false, true);
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
    assert!(record_types
        .iter()
        .any(|e| e == "provider_response_artifact_written"));
    assert!(record_types.iter().any(|e| e == "tool_executed"));
    assert!(record_types.iter().any(|e| e == "run_capsule_written"));
    let request_hash = find_event(&record_events, "provider_request_written")
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

    copy_provider_response_artifact(&runtime_record, &runtime_replay, &request_hash);

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
        "replay run failed: {}",
        String::from_utf8_lossy(&out_replay.stderr)
    );
    let replay_value = parse_run_output(&out_replay);
    let replay_run_id = replay_value
        .get("run_id")
        .and_then(|v| v.as_str())
        .expect("missing replay run_id")
        .to_string();
    let replay_state_hash = replay_value
        .get("state_hash")
        .and_then(|v| v.as_str())
        .expect("missing replay state_hash")
        .to_string();
    assert_eq!(record_state_hash, replay_state_hash);
    let replay_events = read_event_payloads(&runtime_replay);
    let replay_types = read_event_types(&runtime_replay);
    assert!(replay_types
        .iter()
        .any(|e| e == "provider_response_artifact_loaded"));
    assert!(replay_types.iter().any(|e| e == "tool_executed"));
    assert!(replay_types.iter().any(|e| e == "run_capsule_written"));
    let capsule_ref_replay = find_event(&replay_events, "run_capsule_written")
        .get("capsule_ref")
        .and_then(|v| v.as_str())
        .expect("missing replay capsule_ref")
        .to_string();
    assert_eq!(
        read_capsule_provider_mode(&runtime_replay, &capsule_ref_replay),
        "replay"
    );

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
    let verify_replay = run_serverd_verify(&runtime_replay, &replay_run_id);
    assert!(
        verify_replay.status.success(),
        "verify replay failed: {}",
        String::from_utf8_lossy(&verify_replay.stderr)
    );
    let verify_replay_value = parse_verify_output(&verify_replay);
    assert_eq!(
        verify_replay_value
            .get("final_state_hash")
            .and_then(|v| v.as_str()),
        Some(replay_state_hash.as_str())
    );
}

#[test]
fn workflow_tool_approval_is_fail_closed_then_allows_execution_after_approval() {
    let _guard = ENV_LOCK.lock().expect("env lock");
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
