#![cfg(feature = "bin")]

use serverd::output_contract::OUTPUT_CONTRACT_SCHEMA;
use serverd::skills::SKILL_MANIFEST_SCHEMA;
use serverd::tools::execute::{TOOL_INPUT_NOOP_SCHEMA, TOOL_OUTPUT_NOOP_SCHEMA};
use serverd::tools::policy::TOOL_POLICY_SCHEMA;
use serverd::tools::TOOL_SPEC_SCHEMA;
use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

fn run_serverd_route(runtime_root: &Path, envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(common::serverd_exe());
    command
        .arg("--mode")
        .arg("route")
        .arg("--ticks")
        .arg("1")
        .arg("--delta")
        .arg("tick:0")
        .arg("--provider")
        .arg("live")
        .arg("--skill")
        .arg("demo")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        command.env(k, v);
    }
    command.output().expect("failed to run serverd")
}

fn setup_runtime(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
    write_router_config(runtime_root);
    write_skill_manifest(runtime_root);
    write_output_contract(runtime_root);
    write_noop_tool_spec(runtime_root);
    write_tool_policy(runtime_root);
}

fn write_router_config(runtime_root: &Path) {
    let dir = runtime_root.join("router");
    fs::create_dir_all(&dir).expect("create router dir");
    let value = serde_json::json!({
        "schema": "serverd.router.v1",
        "default_provider": "mock_tool",
        "routes": [],
        "policy": { "fail_if_unavailable": true }
    });
    fs::write(
        dir.join("config.json"),
        serde_json::to_vec(&value).expect("serialize router config"),
    )
    .expect("write router config");
}

fn write_skill_manifest(runtime_root: &Path) {
    let dir = runtime_root.join("skills").join("demo");
    fs::create_dir_all(&dir).expect("create skills dir");
    let value = serde_json::json!({
        "schema": SKILL_MANIFEST_SCHEMA,
        "skill_id": "demo",
        "allowed_tools": ["tools.noop"],
        "tool_constraints": [],
        "prompt_template_refs": [],
        "output_contract": "demo.contract"
    });
    fs::write(
        dir.join("skill.json"),
        serde_json::to_vec(&value).expect("serialize skill manifest"),
    )
    .expect("write skill manifest");
}

fn write_output_contract(runtime_root: &Path) {
    let dir = runtime_root.join("contracts");
    fs::create_dir_all(&dir).expect("create contracts dir");
    let value = serde_json::json!({
        "schema": OUTPUT_CONTRACT_SCHEMA,
        "contract_id": "demo.contract",
        "allowed_tool_calls": ["tools.noop"],
        "allowed_fields": ["schema", "output", "tool_call"],
        "required_fields": ["schema", "output", "tool_call"],
        "field_constraints": {
            "schema": { "type": "string" },
            "output": { "type": "string" },
            "tool_call.tool_id": { "type": "string" },
            "tool_call.input": { "type": "object" }
        }
    });
    fs::write(
        dir.join("demo.contract.json"),
        serde_json::to_vec(&value).expect("serialize output contract"),
    )
    .expect("write output contract");
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
    fs::write(
        dir.join("noop.json"),
        serde_json::to_vec(&value).expect("serialize tool spec"),
    )
    .expect("write tool spec");
}

fn write_tool_policy(runtime_root: &Path) {
    let dir = runtime_root.join("tools");
    fs::create_dir_all(&dir).expect("create tools dir");
    let value = serde_json::json!({
        "schema": TOOL_POLICY_SCHEMA,
        "allowed_tools": ["tools.noop"],
        "default_allow": false
    });
    fs::write(
        dir.join("policy.json"),
        serde_json::to_vec(&value).expect("serialize tool policy"),
    )
    .expect("write tool policy");
}

#[cfg(not(feature = "test_providers"))]
#[test]
fn mock_tool_env_overrides_ignored_without_test_providers_feature() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_mock_env_override_{}", Uuid::new_v4()));
    setup_runtime(&runtime_root);
    let workspace_patch_input = serde_json::json!({
        "schema": "serverd.workspace_apply_patch_request.v1",
        "target_path": "target.txt",
        "mode": "full_replace",
        "allow_create": true,
        "allow_create_parents": false,
        "content": "unexpected"
    });
    let out = run_serverd_route(
        &runtime_root,
        &[
            ("TOOLS_ENABLE", "1"),
            ("TOOLS_ARM", "1"),
            ("MOCK_TOOL_TOOL_ID", "workspace.apply_patch.v1"),
            (
                "MOCK_TOOL_INPUT_JSON",
                &serde_json::to_string(&workspace_patch_input).expect("input json"),
            ),
        ],
    );
    assert!(
        out.status.success(),
        "route run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let events = common::read_event_payloads(&runtime_root);
    let tool_selected = events
        .iter()
        .find(|event| event.get("event_type").and_then(|v| v.as_str()) == Some("tool_selected"))
        .expect("tool_selected event");
    assert_eq!(
        tool_selected.get("tool_id").and_then(|v| v.as_str()),
        Some("tools.noop")
    );
}
