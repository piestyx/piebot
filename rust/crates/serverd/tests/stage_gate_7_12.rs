#![cfg(feature = "bin")]

use pie_audit_log::verify_log;
use pie_common::{canonical_json_bytes, sha256_bytes};
use serverd::output_contract::OUTPUT_CONTRACT_SCHEMA;
use serverd::prompt::PROMPT_TEMPLATE_SCHEMA;
use serverd::redaction::REDACTION_CONFIG_SCHEMA;
use serverd::skills::SKILL_MANIFEST_SCHEMA;
use serverd::tools::execute::{TOOL_INPUT_NOOP_SCHEMA, TOOL_OUTPUT_NOOP_SCHEMA};
use serverd::tools::policy::TOOL_POLICY_SCHEMA;
use serverd::tools::TOOL_SPEC_SCHEMA;
use serverd::CONTEXT_POLICY_SCHEMA;
use serverd::EXPLAIN_SCHEMA;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use uuid::Uuid;
mod common;

static ENV_LOCK: Mutex<()> = Mutex::new(());
const WORKSPACE_POLICY_SCHEMA: &str = "serverd.workspace_policy.v1";

fn run_serverd_route_with_envs(
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

fn run_serverd_explain_by_run(runtime_root: &Path, run_id: &str) -> Output {
    let mut cmd = Command::new(common::serverd_exe());
    cmd.arg("explain")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--run")
        .arg(run_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.output().expect("failed to run explain")
}

fn write_initial_state(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
}

fn write_redaction_config(runtime_root: &Path) {
    let dir = runtime_root.join("redaction");
    fs::create_dir_all(&dir).expect("create redaction dir");
    let value = serde_json::json!({
        "schema": REDACTION_CONFIG_SCHEMA,
        "enabled": true,
        "max_provider_input_bytes": 1024 * 1024,
        "strategies": {
            "drop_fields": ["observation_hash"],
            "redact_fields": ["state_hash"],
            "regex_redactions": [
                {
                    "name": "intent_kind",
                    "pattern": "no_op",
                    "replace": "noop"
                }
            ],
            "allow_raw_artifacts": false
        }
    });
    let bytes = serde_json::to_vec(&value).expect("serialize config");
    fs::write(dir.join("config.json"), bytes).expect("write config");
}

fn write_context_policy(runtime_root: &Path) {
    let dir = runtime_root.join("context");
    fs::create_dir_all(&dir).expect("create context dir");
    let value = serde_json::json!({
        "schema": CONTEXT_POLICY_SCHEMA,
        "enabled": true,
        "max_items": 5,
        "max_bytes": 2048,
        "allowed_namespaces": ["prompt_templates"],
        "ordering": "lexicographic",
        "allow_skill_overrides": false
    });
    let bytes = serde_json::to_vec(&value).expect("serialize policy");
    fs::write(dir.join("policy.json"), bytes).expect("write policy");
}

fn write_prompt_template(runtime_root: &Path, template_text: &str) -> String {
    let value = serde_json::json!({
        "schema": PROMPT_TEMPLATE_SCHEMA,
        "template_text": template_text
    });
    let bytes = canonical_json_bytes(&value).expect("canonical prompt template");
    let hash = sha256_bytes(&bytes);
    let trimmed = hash.strip_prefix("sha256:").unwrap_or(&hash);
    let dir = runtime_root.join("artifacts").join("prompt_templates");
    fs::create_dir_all(&dir).expect("create prompt_templates dir");
    let path = dir.join(format!("{}.json", trimmed));
    fs::write(path, bytes).expect("write prompt template");
    format!("prompt_templates/{}", hash)
}

fn write_skill_manifest(
    runtime_root: &Path,
    skill_id: &str,
    allowed_tools: &[&str],
    prompt_template_refs: &[String],
    output_contract: Option<&str>,
) {
    let dir = runtime_root.join("skills").join(skill_id);
    fs::create_dir_all(&dir).expect("create skills dir");
    let value = serde_json::json!({
        "schema": SKILL_MANIFEST_SCHEMA,
        "skill_id": skill_id,
        "allowed_tools": allowed_tools,
        "tool_constraints": [],
        "prompt_template_refs": prompt_template_refs,
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
            "tool_call.input_ref": { "type": "string" },
            "tool_call.input": { "type": "object" }
        }
    })
}

fn write_noop_tool_spec(runtime_root: &Path, filesystem: bool) {
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

fn write_workspace_policy(runtime_root: &Path, value: serde_json::Value) {
    let dir = runtime_root.join("workspace");
    fs::create_dir_all(&dir).expect("create workspace dir");
    let bytes = serde_json::to_vec(&value).expect("serialize workspace policy");
    fs::write(dir.join("policy.json"), bytes).expect("write workspace policy");
}

fn workspace_policy_value(
    workspace_root: &str,
    allow_repo_root: bool,
    per_run_dir: bool,
) -> serde_json::Value {
    serde_json::json!({
        "schema": WORKSPACE_POLICY_SCHEMA,
        "enabled": true,
        "workspace_root": workspace_root,
        "allow_repo_root": allow_repo_root,
        "per_run_dir": per_run_dir
    })
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

fn find_explain_ref_for_capsule(events: &[serde_json::Value], capsule_ref: &str) -> String {
    let mut found: Option<String> = None;
    for event in events {
        if event.get("event_type").and_then(|v| v.as_str()) != Some("explain_written") {
            continue;
        }
        if event.get("capsule_ref").and_then(|v| v.as_str()) != Some(capsule_ref) {
            continue;
        }
        let explain_ref = event
            .get("explain_ref")
            .and_then(|v| v.as_str())
            .expect("explain_ref missing");
        found = Some(explain_ref.to_string());
    }
    found.expect("missing explain_written for capsule")
}

fn artifact_path(runtime_root: &Path, subdir: &str, artifact_ref: &str) -> PathBuf {
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    runtime_root
        .join("artifacts")
        .join(subdir)
        .join(format!("{}.json", trimmed))
}

fn assert_before(types: &[String], first: &str, second: &str) {
    let first_idx = types
        .iter()
        .position(|e| e == first)
        .unwrap_or_else(|| panic!("missing {}", first));
    let second_idx = types
        .iter()
        .position(|e| e == second)
        .unwrap_or_else(|| panic!("missing {}", second));
    assert!(
        first_idx < second_idx,
        "{} must occur before {}",
        first,
        second
    );
}

fn assert_audit_ordering(types: &[String]) {
    assert_eq!(
        types.first().map(|v| v.as_str()),
        Some("run_started"),
        "run_started must be first"
    );
    assert_before(types, "run_started", "workspace_policy_loaded");
    assert_before(types, "workspace_policy_loaded", "tool_selected");
    assert_before(types, "redaction_config_loaded", "provider_request_written");
    assert_before(types, "provider_input_redacted", "provider_request_written");
    assert_before(types, "context_policy_loaded", "context_selected");
    assert_before(types, "context_policy_loaded", "prompt_built");
    assert_before(types, "context_selected", "prompt_built");
    assert_before(types, "prompt_built", "provider_request_written");
    assert_before(types, "provider_output_validated", "tool_selected");
    assert_before(types, "run_capsule_written", "run_completed");
}

#[test]
fn stage_gate_7_12_full_stack_deterministic_across_two_runtimes() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let runtime_one = std::env::temp_dir().join(format!("pie_stage_gate_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_stage_gate_two_{}", Uuid::new_v4()));

    for runtime_root in [&runtime_one, &runtime_two] {
        write_initial_state(runtime_root);
        write_redaction_config(runtime_root);
        write_context_policy(runtime_root);
        let template_a = write_prompt_template(runtime_root, "secret-template");
        let template_b = write_prompt_template(runtime_root, "template-b");
        let prompt_refs = vec![template_a, template_b];
        write_skill_manifest(
            runtime_root,
            "demo",
            &["tools.noop"],
            &prompt_refs,
            Some("demo.contract"),
        );
        write_output_contract(
            runtime_root,
            base_contract("demo.contract", &["tools.noop"]),
        );
        write_noop_tool_spec(runtime_root, true);
        write_tool_policy(runtime_root, &["tools.noop"]);
        write_router_config(runtime_root, "mock_tool");
        write_workspace_policy(
            runtime_root,
            workspace_policy_value("workspace", false, true),
        );
    }

    let envs = [("TOOLS_ENABLE", "1"), ("TOOLS_ARM", "1")];
    let out_one = run_serverd_route_with_envs(&runtime_one, 1, "tick:0", Some("demo"), &envs);
    let out_two = run_serverd_route_with_envs(&runtime_two, 1, "tick:0", Some("demo"), &envs);
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

    let run_one: serde_json::Value =
        serde_json::from_slice(&out_one.stdout).expect("run one output not json");
    let run_two: serde_json::Value =
        serde_json::from_slice(&out_two.stdout).expect("run two output not json");
    let state_hash_one = run_one
        .get("state_hash")
        .and_then(|v| v.as_str())
        .expect("state_hash one missing")
        .to_string();
    let state_hash_two = run_two
        .get("state_hash")
        .and_then(|v| v.as_str())
        .expect("state_hash two missing")
        .to_string();
    assert_eq!(state_hash_one, state_hash_two);
    let run_id_one = run_one
        .get("run_id")
        .and_then(|v| v.as_str())
        .expect("run_id one missing")
        .to_string();
    let run_id_two = run_two
        .get("run_id")
        .and_then(|v| v.as_str())
        .expect("run_id two missing")
        .to_string();
    assert!(!run_id_one.is_empty());
    assert!(!run_id_two.is_empty());

    let audit_path_one = runtime_one.join("logs").join("audit_rust.jsonl");
    let audit_path_two = runtime_two.join("logs").join("audit_rust.jsonl");
    let audit_hash_one = verify_log(&audit_path_one).expect("verify audit one");
    let audit_hash_two = verify_log(&audit_path_two).expect("verify audit two");
    assert!(audit_hash_one.starts_with("sha256:"));
    assert_eq!(audit_hash_one, audit_hash_two);

    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let types_one = read_event_types(&runtime_one);
    let types_two = read_event_types(&runtime_two);
    assert_eq!(types_one, types_two);
    assert_audit_ordering(&types_one);
    assert!(types_one.iter().any(|t| t == "tool_executed"));
    assert!(!types_one.iter().any(|t| t == "workspace_violation"));
    let tool_selected_one = find_event(&events_one, "tool_selected");
    let tool_selected_two = find_event(&events_two, "tool_selected");
    let tool_input_ref_one = tool_selected_one
        .get("input_ref")
        .and_then(|v| v.as_str())
        .expect("tool input_ref one missing");
    let tool_input_ref_two = tool_selected_two
        .get("input_ref")
        .and_then(|v| v.as_str())
        .expect("tool input_ref two missing");
    assert_eq!(tool_input_ref_one, tool_input_ref_two);
    assert!(artifact_path(&runtime_one, "tool_inputs", tool_input_ref_one).exists());
    assert!(artifact_path(&runtime_two, "tool_inputs", tool_input_ref_two).exists());

    let capsule_one = find_event(&events_one, "run_capsule_written");
    let capsule_two = find_event(&events_two, "run_capsule_written");
    let capsule_ref_one = capsule_one
        .get("capsule_ref")
        .and_then(|v| v.as_str())
        .expect("capsule_ref one missing");
    let capsule_ref_two = capsule_two
        .get("capsule_ref")
        .and_then(|v| v.as_str())
        .expect("capsule_ref two missing");
    let capsule_hash_one = capsule_one
        .get("capsule_hash")
        .and_then(|v| v.as_str())
        .expect("capsule_hash one missing");
    let capsule_hash_two = capsule_two
        .get("capsule_hash")
        .and_then(|v| v.as_str())
        .expect("capsule_hash two missing");
    assert_eq!(capsule_ref_one, capsule_ref_two);
    assert_eq!(capsule_hash_one, capsule_hash_two);

    let explain_one = run_serverd_explain_by_run(&runtime_one, &run_id_one);
    let explain_two = run_serverd_explain_by_run(&runtime_two, &run_id_two);
    assert!(
        explain_one.status.success(),
        "explain one failed: {}",
        String::from_utf8_lossy(&explain_one.stderr)
    );
    assert!(
        explain_two.status.success(),
        "explain two failed: {}",
        String::from_utf8_lossy(&explain_two.stderr)
    );

    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let explain_ref_one = find_explain_ref_for_capsule(&events_one, capsule_ref_one);
    let explain_ref_two = find_explain_ref_for_capsule(&events_two, capsule_ref_two);
    assert_eq!(explain_ref_one, explain_ref_two);

    let explain_bytes_one = fs::read(artifact_path(&runtime_one, "explains", &explain_ref_one))
        .expect("read explain one");
    let explain_bytes_two = fs::read(artifact_path(&runtime_two, "explains", &explain_ref_two))
        .expect("read explain two");
    assert_eq!(explain_bytes_one, explain_bytes_two);
    let explain_value: serde_json::Value =
        serde_json::from_slice(&explain_bytes_one).expect("explain not json");
    assert_eq!(
        explain_value.get("schema").and_then(|v| v.as_str()),
        Some(EXPLAIN_SCHEMA)
    );
    let explain_text = String::from_utf8_lossy(&explain_bytes_one);
    assert!(
        !explain_text.contains("secret-template"),
        "explain must not contain prompt template text"
    );
}
