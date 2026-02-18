#![cfg(feature = "bin")]

use pie_audit_log::verify_log;
use pie_common::{canonical_json_bytes, sha256_bytes};
use serverd::output_contract::{read_output_from_response, OUTPUT_CONTRACT_SCHEMA};
use serverd::provider::PROVIDER_RESPONSE_SCHEMA;
use serverd::skills::SKILL_MANIFEST_SCHEMA;
use serverd::tools::execute::{TOOL_INPUT_NOOP_SCHEMA, TOOL_OUTPUT_NOOP_SCHEMA};
use serverd::tools::policy::TOOL_POLICY_SCHEMA;
use serverd::tools::TOOL_SPEC_SCHEMA;
use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use uuid::Uuid;
mod common;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn run_serverd_route(
    runtime_root: &Path,
    ticks: u64,
    delta: &str,
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
    cmd.output().expect("failed to run serverd")
}

fn write_initial_state(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
}

fn write_skill_manifest(runtime_root: &Path, skill_id: &str, output_contract: Option<&str>) {
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

fn write_output_contract(runtime_root: &Path, value: serde_json::Value) {
    let dir = runtime_root.join("contracts");
    fs::create_dir_all(&dir).expect("create contracts dir");
    let contract_id = value
        .get("contract_id")
        .and_then(|v| v.as_str())
        .unwrap_or("contract");
    let bytes = serde_json::to_vec(&value).expect("serialize contract");
    fs::write(dir.join(format!("{}.json", contract_id)), bytes).expect("write contract");
}

fn write_noop_tool_spec(runtime_root: &Path) {
    let dir = runtime_root.join("tools");
    fs::create_dir_all(&dir).expect("create tools dir");
    let value = serde_json::json!({
        "schema": TOOL_SPEC_SCHEMA,
        "id": "tools.noop",
        "input_schema": TOOL_INPUT_NOOP_SCHEMA,
        "output_schema": TOOL_OUTPUT_NOOP_SCHEMA,
        "deterministic": true,
        "risk_level": "low",
        "requires_approval": false,
        "requires_arming": false,
        "filesystem": false,
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

fn write_noop_tool_input(runtime_root: &Path) {
    let dir = runtime_root.join("artifacts").join("tool_inputs");
    fs::create_dir_all(&dir).expect("create tool inputs dir");
    let value = serde_json::json!({
        "schema": TOOL_INPUT_NOOP_SCHEMA
    });
    let bytes = canonical_json_bytes(&value).expect("canonical tool input");
    let hash = sha256_bytes(&bytes);
    let trimmed = hash.strip_prefix("sha256:").unwrap_or(&hash);
    let path = dir.join(format!("{}.json", trimmed));
    fs::write(path, bytes).expect("write tool input");
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

fn base_contract(contract_id: &str, allowed_tool_calls: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "schema": OUTPUT_CONTRACT_SCHEMA,
        "contract_id": contract_id,
        "allowed_tool_calls": allowed_tool_calls,
        "allowed_fields": ["schema", "output", "tool_call"],
        "required_fields": ["schema", "output", "tool_call"],
        "field_constraints": {
            "schema": { "type": "string" },
            "output": { "type": "string" },
            "tool_call.tool_id": { "type": "string" },
            "tool_call.input_ref": { "type": "string" }
        }
    })
}

#[test]
fn output_contract_allows_valid_tool_call() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let runtime_root = std::env::temp_dir().join(format!("pie_stage9_valid_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_skill_manifest(&runtime_root, "demo", Some("demo.contract"));
    write_output_contract(
        &runtime_root,
        base_contract("demo.contract", &["tools.noop"]),
    );
    write_noop_tool_spec(&runtime_root);
    write_tool_policy(&runtime_root, &["tools.noop"]);
    write_noop_tool_input(&runtime_root);
    write_router_config(&runtime_root, "mock_tool");

    let envs = [("TOOLS_ENABLE", "1"), ("TOOLS_ARM", "1")];
    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"), &envs);
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let events = read_event_payloads(&runtime_root);
    let validated = find_event(&events, "provider_output_validated");
    assert_eq!(validated.get("ok").and_then(|v| v.as_bool()), Some(true));
    let types = read_event_types(&runtime_root);
    assert!(types.iter().any(|e| e == "tool_executed"));
}

#[test]
fn output_contract_rejects_disallowed_tool_call() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let runtime_root = std::env::temp_dir().join(format!("pie_stage9_invalid_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_skill_manifest(&runtime_root, "demo", Some("demo.contract"));
    write_output_contract(&runtime_root, base_contract("demo.contract", &[]));
    write_noop_tool_spec(&runtime_root);
    write_tool_policy(&runtime_root, &["tools.noop"]);
    write_noop_tool_input(&runtime_root);
    write_router_config(&runtime_root, "mock_tool");

    let envs = [("TOOLS_ENABLE", "1"), ("TOOLS_ARM", "1")];
    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"), &envs);
    assert!(!out.status.success(), "run should fail");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("provider_output_contract_violation")
    );

    let events = read_event_payloads(&runtime_root);
    let rejected = find_event(&events, "provider_output_rejected");
    assert_eq!(
        rejected.get("reason").and_then(|v| v.as_str()),
        Some("provider_output_contract_violation")
    );
    let types = read_event_types(&runtime_root);
    assert!(!types.iter().any(|e| e == "tool_executed"));
}
#[test]
fn output_contract_rejects_tool_call_with_input_and_input_ref() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage9_both_inputs_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_skill_manifest(&runtime_root, "demo", Some("demo.contract"));
    write_output_contract(
        &runtime_root,
        base_contract("demo.contract", &["tools.noop"]),
    );
    write_noop_tool_spec(&runtime_root);
    write_tool_policy(&runtime_root, &["tools.noop"]);
    write_router_config(&runtime_root, "mock_tool");

    let envs = [
        ("TOOLS_ENABLE", "1"),
        ("TOOLS_ARM", "1"),
        ("MOCK_TOOL_BOTH_INPUTS", "1"),
    ];
    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"), &envs);
    assert!(!out.status.success(), "run should fail");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("provider_output_contract_violation")
    );

    let events = read_event_payloads(&runtime_root);
    let rejected = find_event(&events, "provider_output_rejected");
    assert_eq!(
        rejected.get("reason").and_then(|v| v.as_str()),
        Some("provider_output_contract_violation")
    );
    let types = read_event_types(&runtime_root);
    assert!(!types.iter().any(|e| e == "tool_executed"));
}
#[test]
fn no_contract_and_no_tool_call_allows_run() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage9_no_contract_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_skill_manifest(&runtime_root, "demo", None);
    write_router_config(&runtime_root, "mock");

    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"), &[]);
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let types = read_event_types(&runtime_root);
    assert!(!types.iter().any(|e| e == "tool_executed"));
    assert!(!types.iter().any(|e| e == "provider_output_rejected"));
}

#[test]
fn output_contract_deterministic_across_runtimes() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let runtime_one = std::env::temp_dir().join(format!("pie_stage9_det_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_stage9_det_two_{}", Uuid::new_v4()));
    for runtime_root in [&runtime_one, &runtime_two] {
        write_initial_state(runtime_root);
        write_skill_manifest(runtime_root, "demo", Some("demo.contract"));
        write_output_contract(
            runtime_root,
            base_contract("demo.contract", &["tools.noop"]),
        );
        write_noop_tool_spec(runtime_root);
        write_tool_policy(runtime_root, &["tools.noop"]);
        write_noop_tool_input(runtime_root);
        write_router_config(runtime_root, "mock_tool");
    }

    let envs = [("TOOLS_ENABLE", "1"), ("TOOLS_ARM", "1")];
    let out_one = run_serverd_route(&runtime_one, 1, "tick:0", Some("demo"), &envs);
    let out_two = run_serverd_route(&runtime_two, 1, "tick:0", Some("demo"), &envs);
    assert!(out_one.status.success(), "run one failed");
    assert!(out_two.status.success(), "run two failed");

    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let loaded_one = find_event(&events_one, "output_contract_loaded");
    let loaded_two = find_event(&events_two, "output_contract_loaded");
    assert_eq!(
        loaded_one.get("contract_hash").and_then(|v| v.as_str()),
        loaded_two.get("contract_hash").and_then(|v| v.as_str())
    );
    verify_log(&runtime_one.join("logs").join("audit_rust.jsonl")).expect("verify log one");
    verify_log(&runtime_two.join("logs").join("audit_rust.jsonl")).expect("verify log two");
}

#[test]
fn contract_hash_changes_with_content() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let runtime_one = std::env::temp_dir().join(format!("pie_stage9_hash_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_stage9_hash_two_{}", Uuid::new_v4()));
    for (runtime_root, allowed) in [
        (&runtime_one, vec!["tools.noop"]),
        (&runtime_two, vec!["tools.noop", "tools.other"]),
    ] {
        write_initial_state(runtime_root);
        write_skill_manifest(runtime_root, "demo", Some("demo.contract"));
        write_output_contract(runtime_root, base_contract("demo.contract", &allowed));
        write_noop_tool_spec(runtime_root);
        write_tool_policy(runtime_root, &["tools.noop"]);
        write_noop_tool_input(runtime_root);
        write_router_config(runtime_root, "mock_tool");
    }

    let envs = [("TOOLS_ENABLE", "1"), ("TOOLS_ARM", "1")];
    let out_one = run_serverd_route(&runtime_one, 1, "tick:0", Some("demo"), &envs);
    let out_two = run_serverd_route(&runtime_two, 1, "tick:0", Some("demo"), &envs);
    assert!(out_one.status.success(), "run one failed");
    assert!(out_two.status.success(), "run two failed");

    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let loaded_one = find_event(&events_one, "output_contract_loaded");
    let loaded_two = find_event(&events_two, "output_contract_loaded");
    assert_ne!(
        loaded_one.get("contract_hash").and_then(|v| v.as_str()),
        loaded_two.get("contract_hash").and_then(|v| v.as_str())
    );
}

#[test]
fn missing_contract_fails_closed_when_tool_call_present() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let runtime_root = std::env::temp_dir().join(format!("pie_stage9_missing_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_skill_manifest(&runtime_root, "demo", Some("missing.contract"));
    write_noop_tool_spec(&runtime_root);
    write_tool_policy(&runtime_root, &["tools.noop"]);
    write_noop_tool_input(&runtime_root);
    write_router_config(&runtime_root, "mock_tool");

    let envs = [("TOOLS_ENABLE", "1"), ("TOOLS_ARM", "1")];
    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"), &envs);
    assert!(!out.status.success(), "run should fail");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("output_contract_not_found")
    );
    let types = read_event_types(&runtime_root);
    assert!(!types.iter().any(|e| e == "tool_executed"));
}

#[test]
fn read_output_from_response_artifact() {
    let runtime_root = std::env::temp_dir().join(format!("pie_stage9_read_{}", Uuid::new_v4()));
    let output_value = serde_json::json!({
        "schema": "serverd.provider_output.v1",
        "output": "ok"
    });
    let bytes = canonical_json_bytes(&output_value).expect("canonical output");
    let output_ref = sha256_bytes(&bytes);
    let output_dir = runtime_root.join("artifacts").join("outputs");
    fs::create_dir_all(&output_dir).expect("create outputs dir");
    let trimmed = output_ref.strip_prefix("sha256:").unwrap_or(&output_ref);
    fs::write(output_dir.join(format!("{}.json", trimmed)), bytes).expect("write output");

    let response_value = serde_json::json!({
        "schema": PROVIDER_RESPONSE_SCHEMA,
        "request_hash": "sha256:request",
        "output_ref": output_ref
    });
    let response_bytes = canonical_json_bytes(&response_value).expect("canonical response");
    let response_ref = sha256_bytes(&response_bytes);
    let response_dir = runtime_root.join("artifacts").join("responses");
    fs::create_dir_all(&response_dir).expect("create responses dir");
    let trimmed = response_ref
        .strip_prefix("sha256:")
        .unwrap_or(&response_ref);
    fs::write(
        response_dir.join(format!("{}.json", trimmed)),
        response_bytes,
    )
    .expect("write response");

    let read_value = read_output_from_response(&runtime_root, &response_ref).expect("read output");
    assert_eq!(read_value, output_value);
}
