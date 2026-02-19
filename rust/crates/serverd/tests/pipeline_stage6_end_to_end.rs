#![cfg(feature = "bin")]

use pie_audit_log::verify_log;
use pie_common::{canonical_json_bytes, sha256_bytes};
use serverd::output_contract::OUTPUT_CONTRACT_SCHEMA;
use serverd::prompt::PROMPT_TEMPLATE_SCHEMA;
use serverd::skills::SKILL_MANIFEST_SCHEMA;
use serverd::tools::execute::{TOOL_INPUT_NOOP_SCHEMA, TOOL_OUTPUT_NOOP_SCHEMA};
use serverd::tools::policy::TOOL_POLICY_SCHEMA;
use serverd::tools::TOOL_SPEC_SCHEMA;
use std::fs;
use std::path::{Path, PathBuf};
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

fn write_initial_state(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
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

fn write_noop_tool_input(runtime_root: &Path) -> String {
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
    hash
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

fn artifact_path(runtime_root: &Path, subdir: &str, artifact_ref: &str) -> PathBuf {
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    runtime_root
        .join("artifacts")
        .join(subdir)
        .join(format!("{}.json", trimmed))
}

#[test]
fn context_selection_audited_and_bound_to_provider_request() {
    let runtime_root = std::env::temp_dir().join(format!("pie_stage6_ctx_{}", Uuid::new_v4()));
    let template_a = write_prompt_template(&runtime_root, "template-a");
    let template_b = write_prompt_template(&runtime_root, "template-b");
    let prompt_refs = vec![template_a.clone(), template_b.clone()];
    write_skill_manifest(&runtime_root, "demo", &["tools.noop"], &prompt_refs, None);

    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"), &[]);
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let events = read_event_payloads(&runtime_root);
    let types = read_event_types(&runtime_root);
    let ctx_idx = types
        .iter()
        .position(|e| e == "context_selected")
        .expect("missing context_selected");
    let req_idx = types
        .iter()
        .position(|e| e == "provider_request_written")
        .expect("missing provider_request_written");
    assert!(ctx_idx < req_idx);

    let context_event = find_event(&events, "context_selected");
    let context_ref = context_event
        .get("context_ref")
        .and_then(|v| v.as_str())
        .expect("context_ref missing");
    let context_bytes =
        fs::read(artifact_path(&runtime_root, "contexts", context_ref)).expect("read context");
    let context_value: serde_json::Value =
        serde_json::from_slice(&context_bytes).expect("context not json");
    let context_refs = context_value
        .get("context_refs")
        .and_then(|v| v.as_array())
        .expect("context_refs missing");
    let expected: Vec<&str> = vec![template_a.as_str(), template_b.as_str()];
    let got: Vec<&str> = context_refs.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(got, expected);

    let request_event = find_event(&events, "provider_request_written");
    let request_ref = request_event
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("request artifact_ref missing");
    let request_bytes =
        fs::read(artifact_path(&runtime_root, "requests", request_ref)).expect("read request");
    let request_value: serde_json::Value =
        serde_json::from_slice(&request_bytes).expect("request not json");
    assert_eq!(
        request_value.get("context_ref").and_then(|v| v.as_str()),
        Some(context_ref)
    );
}

#[test]
fn end_to_end_tick_with_tools_is_deterministic() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let runtime_one = std::env::temp_dir().join(format!("pie_stage6_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_stage6_two_{}", Uuid::new_v4()));

    for runtime_root in [&runtime_one, &runtime_two] {
        write_initial_state(runtime_root);
        let template_a = write_prompt_template(runtime_root, "prompt-a");
        let template_b = write_prompt_template(runtime_root, "prompt-b");
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
            serde_json::json!({
                "schema": OUTPUT_CONTRACT_SCHEMA,
                "contract_id": "demo.contract",
                "allowed_tool_calls": ["tools.noop"],
                "allowed_fields": ["schema", "output", "tool_call"],
                "required_fields": ["schema", "output", "tool_call"],
                "field_constraints": {
                    "schema": { "type": "string" },
                    "output": { "type": "string" },
                    "tool_call.tool_id": { "type": "string" },
                    "tool_call.input_ref": { "type": "string" }
                }
            }),
        );
        write_noop_tool_spec(runtime_root);
        write_tool_policy(runtime_root, &["tools.noop"]);
        let _ = write_noop_tool_input(runtime_root);
        write_router_config(runtime_root, "mock_tool");
    }

    let envs = [("TOOLS_ENABLE", "1"), ("TOOLS_ARM", "1")];

    let out_one = run_serverd_route(&runtime_one, 1, "tick:0", Some("demo"), &envs);
    let out_two = run_serverd_route(&runtime_two, 1, "tick:0", Some("demo"), &envs);
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

    let audit_one = runtime_one.join("logs").join("audit_rust.jsonl");
    let audit_two = runtime_two.join("logs").join("audit_rust.jsonl");
    verify_log(&audit_one).expect("verify log one");
    verify_log(&audit_two).expect("verify log two");

    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let types_one = read_event_types(&runtime_one);
    let types_two = read_event_types(&runtime_two);
    assert_eq!(types_one, types_two);
    assert!(types_one.iter().any(|e| e == "context_selected"));
    assert!(types_one.iter().any(|e| e == "tool_executed"));
    assert!(!types_one.iter().any(|e| e == "tool_execution_denied"));

    let ctx_one = find_event(&events_one, "context_selected");
    let ctx_two = find_event(&events_two, "context_selected");
    let ctx_ref_one = ctx_one
        .get("context_ref")
        .and_then(|v| v.as_str())
        .expect("context_ref one missing");
    let ctx_ref_two = ctx_two
        .get("context_ref")
        .and_then(|v| v.as_str())
        .expect("context_ref two missing");
    assert_eq!(ctx_ref_one, ctx_ref_two);

    let req_one = find_event(&events_one, "provider_request_written");
    let req_two = find_event(&events_two, "provider_request_written");
    let req_ref_one = req_one
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("request ref one missing");
    let req_ref_two = req_two
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("request ref two missing");
    let req_bytes_one =
        fs::read(artifact_path(&runtime_one, "requests", req_ref_one)).expect("read request one");
    let req_bytes_two =
        fs::read(artifact_path(&runtime_two, "requests", req_ref_two)).expect("read request two");
    assert_eq!(req_bytes_one, req_bytes_two);

    let tick_one = find_event(&events_one, "tick_completed");
    let tick_two = find_event(&events_two, "tick_completed");
    let hash_one = tick_one
        .get("state_hash")
        .and_then(|v| v.as_str())
        .expect("state_hash one missing");
    let hash_two = tick_two
        .get("state_hash")
        .and_then(|v| v.as_str())
        .expect("state_hash two missing");
    assert_eq!(hash_one, hash_two);
}
