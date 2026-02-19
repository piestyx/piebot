#![cfg(feature = "bin")]

use pie_common::{canonical_json_bytes, sha256_bytes};
use serverd::output_contract::OUTPUT_CONTRACT_SCHEMA;
use serverd::prompt::PROMPT_TEMPLATE_SCHEMA;
use serverd::skills::SKILL_MANIFEST_SCHEMA;
use serverd::tools::execute::{TOOL_INPUT_NOOP_SCHEMA, TOOL_OUTPUT_NOOP_SCHEMA};
use serverd::tools::policy::TOOL_POLICY_SCHEMA;
use serverd::tools::TOOL_SPEC_SCHEMA;
use serverd::CONTEXT_POLICY_SCHEMA;
use serverd::RUN_CAPSULE_SCHEMA;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use uuid::Uuid;
mod common;
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn run_serverd_route(runtime_root: &Path, ticks: u64, delta: &str, skill: Option<&str>) -> Output {
    run_serverd_route_with_envs(runtime_root, ticks, delta, skill, &[])
}

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

fn write_initial_state(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
}

fn write_skill_manifest(
    runtime_root: &Path,
    skill_id: &str,
    allowed_tools: &[&str],
    prompt_refs: &[String],
    output_contract: Option<&str>,
) {
    let dir = runtime_root.join("skills").join(skill_id);
    fs::create_dir_all(&dir).expect("create skills dir");
    let value = serde_json::json!({
        "schema": SKILL_MANIFEST_SCHEMA,
        "skill_id": skill_id,
        "allowed_tools": allowed_tools,
        "tool_constraints": [],
        "prompt_template_refs": prompt_refs,
        "output_contract": output_contract
    });
    let bytes = serde_json::to_vec(&value).expect("serialize skill manifest");
    fs::write(dir.join("skill.json"), bytes).expect("write skill manifest");
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
            "tool_call.input_ref": { "type": "string" }
        }
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

fn artifact_path(runtime_root: &Path, subdir: &str, artifact_ref: &str) -> PathBuf {
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    runtime_root
        .join("artifacts")
        .join(subdir)
        .join(format!("{}.json", trimmed))
}

fn read_capsule(runtime_root: &Path) -> (String, serde_json::Value, Vec<u8>) {
    let events = read_event_payloads(runtime_root);
    let capsule_event = find_event(&events, "run_capsule_written");
    let capsule_ref = capsule_event
        .get("capsule_ref")
        .and_then(|v| v.as_str())
        .expect("capsule_ref missing")
        .to_string();
    let capsule_path = artifact_path(runtime_root, "run_capsules", &capsule_ref);
    let capsule_bytes = fs::read(&capsule_path).expect("read capsule");
    let capsule_value: serde_json::Value =
        serde_json::from_slice(&capsule_bytes).expect("capsule not json");
    (capsule_ref, capsule_value, capsule_bytes)
}

fn assert_sha256_prefixed(value: &str, label: &str) {
    assert!(
        value.starts_with("sha256:"),
        "{} must be sha256: prefixed",
        label
    );
}

fn assert_no_forbidden_keys(value: &serde_json::Value, forbidden: &[&str]) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if forbidden.iter().any(|f| *f == key) {
                    panic!("capsule must not contain raw body key {}", key);
                }
                assert_no_forbidden_keys(child, forbidden);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                assert_no_forbidden_keys(item, forbidden);
            }
        }
        _ => {}
    }
}

#[test]
fn run_capsule_emits_and_hides_prompt_text() {
    let runtime_root = std::env::temp_dir().join(format!("pie_capsule_emit_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_context_policy(&runtime_root);
    write_router_config(&runtime_root, "mock");
    let template_ref = write_prompt_template(&runtime_root, "secret-template");
    write_skill_manifest(&runtime_root, "demo", &[], &[template_ref.clone()], None);

    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"));
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let event_types = read_event_types(&runtime_root);
    let capsule_idx = event_types
        .iter()
        .position(|t| t == "run_capsule_written")
        .expect("missing run_capsule_written");
    let completed_idx = event_types
        .iter()
        .position(|t| t == "run_completed")
        .expect("missing run_completed");
    assert!(capsule_idx < completed_idx);

    let events = read_event_payloads(&runtime_root);
    let capsule_event = find_event(&events, "run_capsule_written");
    let capsule_ref = capsule_event
        .get("capsule_ref")
        .and_then(|v| v.as_str())
        .expect("capsule_ref missing");
    let capsule_hash = capsule_event
        .get("capsule_hash")
        .and_then(|v| v.as_str())
        .expect("capsule_hash missing");
    assert_eq!(capsule_ref, capsule_hash);

    let capsule_path = artifact_path(&runtime_root, "run_capsules", capsule_ref);
    let capsule_bytes = fs::read(&capsule_path).expect("read capsule");
    let capsule_value: serde_json::Value =
        serde_json::from_slice(&capsule_bytes).expect("capsule not json");
    assert_eq!(
        capsule_value.get("schema").and_then(|v| v.as_str()),
        Some(RUN_CAPSULE_SCHEMA)
    );
    let prompt_refs = capsule_value
        .get("context")
        .and_then(|v| v.get("prompt_template_refs"))
        .and_then(|v| v.as_array())
        .expect("prompt_template_refs missing");
    assert!(
        prompt_refs
            .iter()
            .any(|v| v.as_str() == Some(template_ref.as_str())),
        "capsule missing prompt template ref"
    );

    let capsule_text = String::from_utf8_lossy(&capsule_bytes);
    assert!(
        !capsule_text.contains("secret-template"),
        "capsule must not contain prompt template text"
    );
}

#[test]
fn run_capsule_is_deterministic_across_runtimes() {
    let runtime_one = std::env::temp_dir().join(format!("pie_capsule_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_capsule_two_{}", Uuid::new_v4()));

    for runtime_root in [&runtime_one, &runtime_two] {
        write_initial_state(runtime_root);
        write_context_policy(runtime_root);
        write_router_config(runtime_root, "mock");
        let template_ref = write_prompt_template(runtime_root, "secret-template");
        write_skill_manifest(runtime_root, "demo", &[], &[template_ref], None);
    }

    let out_one = run_serverd_route(&runtime_one, 1, "tick:0", Some("demo"));
    let out_two = run_serverd_route(&runtime_two, 1, "tick:0", Some("demo"));
    assert!(out_one.status.success(), "run one failed");
    assert!(out_two.status.success(), "run two failed");

    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
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
    assert_eq!(capsule_ref_one, capsule_ref_two);

    let bytes_one = fs::read(artifact_path(&runtime_one, "run_capsules", capsule_ref_one))
        .expect("read capsule one");
    let bytes_two = fs::read(artifact_path(&runtime_two, "run_capsules", capsule_ref_two))
        .expect("read capsule two");
    assert_eq!(bytes_one, bytes_two);

    let capsule_value: serde_json::Value =
        serde_json::from_slice(&bytes_one).expect("capsule not json");
    let capsule_value_two: serde_json::Value =
        serde_json::from_slice(&bytes_two).expect("capsule not json two");
    assert_eq!(
        capsule_value
            .get("run")
            .and_then(|v| v.get("run_id"))
            .and_then(|v| v.as_str()),
        capsule_value_two
            .get("run")
            .and_then(|v| v.get("run_id"))
            .and_then(|v| v.as_str())
    );
}

#[test]
fn run_capsule_contains_required_provenance() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_capsule_provenance_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_context_policy(&runtime_root);
    write_router_config(&runtime_root, "mock");
    let template_ref = write_prompt_template(&runtime_root, "secret-template");
    write_skill_manifest(&runtime_root, "demo", &[], &[template_ref.clone()], None);

    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"));
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let (_capsule_ref, capsule_value, capsule_bytes) = read_capsule(&runtime_root);
    let run = capsule_value.get("run").expect("run missing");
    let run_id = run
        .get("run_id")
        .and_then(|v| v.as_str())
        .expect("run_id missing");
    assert_sha256_prefixed(run_id, "run.run_id");
    assert_eq!(run.get("mode").and_then(|v| v.as_str()), Some("route"));
    let audit_hash = capsule_value
        .get("audit")
        .and_then(|v| v.get("audit_head_hash"))
        .and_then(|v| v.as_str())
        .expect("audit_head_hash missing");
    assert_sha256_prefixed(audit_hash, "audit.audit_head_hash");
    let state = capsule_value.get("state").expect("state missing");
    let initial_state_hash = state
        .get("initial_state_hash")
        .and_then(|v| v.as_str())
        .expect("state.initial_state_hash missing");
    let final_state_hash = state
        .get("final_state_hash")
        .and_then(|v| v.as_str())
        .expect("state.final_state_hash missing");
    assert_sha256_prefixed(initial_state_hash, "state.initial_state_hash");
    assert_sha256_prefixed(final_state_hash, "state.final_state_hash");
    let skill = capsule_value.get("skill").expect("skill missing");
    assert_eq!(skill.get("skill_id").and_then(|v| v.as_str()), Some("demo"));
    let manifest_hash = skill
        .get("skill_manifest_hash")
        .and_then(|v| v.as_str())
        .expect("skill_manifest_hash missing");
    assert_sha256_prefixed(manifest_hash, "skill.skill_manifest_hash");
    let router_hash = capsule_value
        .get("router")
        .and_then(|v| v.get("router_config_hash"))
        .and_then(|v| v.as_str())
        .expect("router.router_config_hash missing");
    assert_sha256_prefixed(router_hash, "router.router_config_hash");

    let forbidden_keys = [
        "prompt_text",
        "template_text",
        "output",
        "raw",
        "content",
        "messages",
    ];
    assert_no_forbidden_keys(&capsule_value, &forbidden_keys);
    let capsule_text = String::from_utf8_lossy(&capsule_bytes);
    assert!(
        !capsule_text.contains("secret-template"),
        "capsule must not contain prompt template text"
    );
}

#[test]
fn run_capsule_tool_hashes_absent_without_tool_execution() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let runtime_root = std::env::temp_dir().join(format!("pie_capsule_notools_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_context_policy(&runtime_root);
    write_router_config(&runtime_root, "mock");
    let template_ref = write_prompt_template(&runtime_root, "template");
    write_skill_manifest(&runtime_root, "demo", &[], &[template_ref], None);

    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"));
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let (_capsule_ref, capsule_value, _capsule_bytes) = read_capsule(&runtime_root);
    match capsule_value.get("tools") {
        None => {}
        Some(tools) => {
            assert!(
                tools.get("tool_registry_hash").is_none(),
                "tool_registry_hash should be absent when no tool execution"
            );
            assert!(
                tools.get("tool_policy_hash").is_none(),
                "tool_policy_hash should be absent when no tool execution"
            );
        }
    }
    match capsule_value.get("tool_io") {
        None => {}
        Some(tool_io) => {
            let entries = tool_io.as_array().expect("tool_io not array");
            assert!(
                entries.is_empty(),
                "tool_io should be empty when no tool execution"
            );
        }
    }
}

#[test]
fn run_capsule_tool_hashes_present_with_tool_execution() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let runtime_root = std::env::temp_dir().join(format!("pie_capsule_tools_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_context_policy(&runtime_root);
    write_router_config(&runtime_root, "mock_tool");
    let template_ref = write_prompt_template(&runtime_root, "template");
    write_skill_manifest(
        &runtime_root,
        "demo",
        &["tools.noop"],
        &[template_ref],
        Some("demo.contract"),
    );
    write_output_contract(
        &runtime_root,
        base_contract("demo.contract", &["tools.noop"]),
    );
    write_noop_tool_spec(&runtime_root);
    write_tool_policy(&runtime_root, &["tools.noop"]);
    let input_path = "allowed.txt";
    let input_value = serde_json::json!({
        "schema": TOOL_INPUT_NOOP_SCHEMA,
        "path": input_path
    });
    let input_bytes = canonical_json_bytes(&input_value).expect("canonical tool input");
    let expected_input_ref = sha256_bytes(&input_bytes);

    let envs = [
        ("TOOLS_ENABLE", "1"),
        ("TOOLS_ARM", "1"),
        ("MOCK_TOOL_INPUT_PATH", input_path),
    ];
    let out = run_serverd_route_with_envs(&runtime_root, 1, "tick:0", Some("demo"), &envs);
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let (_capsule_ref, capsule_value, _capsule_bytes) = read_capsule(&runtime_root);
    let tools = capsule_value.get("tools").expect("tools missing");
    let registry_hash = tools
        .get("tool_registry_hash")
        .and_then(|v| v.as_str())
        .expect("tool_registry_hash missing");
    let policy_hash = tools
        .get("tool_policy_hash")
        .and_then(|v| v.as_str())
        .expect("tool_policy_hash missing");
    assert_sha256_prefixed(registry_hash, "tools.tool_registry_hash");
    assert_sha256_prefixed(policy_hash, "tools.tool_policy_hash");
    let tool_io = capsule_value.get("tool_io").expect("tool_io missing");
    let entries = tool_io.as_array().expect("tool_io not array");
    let mut found = false;
    for entry in entries {
        let tool_id = entry.get("tool_id").and_then(|v| v.as_str());
        if tool_id == Some("tools.noop") {
            let input_ref = entry
                .get("input_ref")
                .and_then(|v| v.as_str())
                .expect("tool_io input_ref missing");
            let output_ref = entry
                .get("output_ref")
                .and_then(|v| v.as_str())
                .expect("tool_io output_ref missing");
            assert_eq!(input_ref, expected_input_ref);
            assert_sha256_prefixed(output_ref, "tool_io.output_ref");
            found = true;
        }
    }
    assert!(found, "tool_io entry for tools.noop missing");
}
