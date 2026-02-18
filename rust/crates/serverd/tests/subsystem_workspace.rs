#![cfg(feature = "bin")]

use pie_common::{canonical_json_bytes, sha256_bytes};
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

fn run_serverd_route(runtime_root: &Path, ticks: u64, delta: &str, skill: Option<&str>) -> Output {
    run_serverd_route_with_envs(runtime_root, ticks, delta, skill, &[])
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

fn write_skill_manifest(
    runtime_root: &Path,
    skill_id: &str,
    allowed_tools: &[&str],
    output_contract: Option<&str>,
) {
    let dir = runtime_root.join("skills").join(skill_id);
    fs::create_dir_all(&dir).expect("create skills dir");
    let mut value = serde_json::json!({
        "schema": SKILL_MANIFEST_SCHEMA,
        "skill_id": skill_id,
        "allowed_tools": allowed_tools,
        "tool_constraints": [],
        "prompt_template_refs": []
    });
    if let Some(contract_id) = output_contract {
        value["output_contract"] = serde_json::json!(contract_id);
    }
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
            "tool_call.input_ref": { "type": "string" }
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

#[test]
fn workspace_policy_hash_deterministic_and_emitted() {
    let runtime_one =
        std::env::temp_dir().join(format!("pie_workspace_policy_one_{}", Uuid::new_v4()));
    let runtime_two =
        std::env::temp_dir().join(format!("pie_workspace_policy_two_{}", Uuid::new_v4()));
    let policy = workspace_policy_value("workspace", false, true);
    let bytes = canonical_json_bytes(&policy).expect("canonical policy");
    let expected_hash = sha256_bytes(&bytes);

    for runtime_root in [&runtime_one, &runtime_two] {
        write_workspace_policy(runtime_root, policy.clone());
        let out = run_serverd_route(runtime_root, 1, "tick:0", None);
        assert!(
            out.status.success(),
            "run failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let events = read_event_payloads(runtime_root);
        let loaded = find_event(&events, "workspace_policy_loaded");
        let policy_hash = loaded
            .get("policy_hash")
            .and_then(|v| v.as_str())
            .expect("policy_hash missing");
        assert_eq!(policy_hash, expected_hash);
    }

    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let hash_one = find_event(&events_one, "workspace_policy_loaded")
        .get("policy_hash")
        .and_then(|v| v.as_str())
        .expect("policy_hash one missing")
        .to_string();
    let hash_two = find_event(&events_two, "workspace_policy_loaded")
        .get("policy_hash")
        .and_then(|v| v.as_str())
        .expect("policy_hash two missing")
        .to_string();
    assert_eq!(hash_one, hash_two);
}

#[test]
fn workspace_repo_root_disallowed_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_workspace_repo_root_{}", Uuid::new_v4()));
    write_workspace_policy(
        runtime_root.as_path(),
        workspace_policy_value(".", false, true),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0", None);
    assert!(!out.status.success(), "run should fail");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("workspace_repo_root_disallowed")
    );
    let events = read_event_types(&runtime_root);
    assert_eq!(events, vec!["run_started", "run_completed"]);
}

#[test]
fn workspace_violation_emitted_for_traversal_and_absolute_paths() {
    let envs_traversal = [
        ("TOOLS_ENABLE", "1"),
        ("TOOLS_ARM", "1"),
        ("MOCK_TOOL_INPUT_PATH", "../escape.txt"),
    ];

    let runtime_traversal =
        std::env::temp_dir().join(format!("pie_workspace_traversal_{}", Uuid::new_v4()));
    write_router_config(&runtime_traversal, "mock_tool");
    write_skill_manifest(
        &runtime_traversal,
        "demo",
        &["tools.noop"],
        Some("demo.contract"),
    );
    write_output_contract(
        &runtime_traversal,
        base_contract("demo.contract", &["tools.noop"]),
    );
    write_noop_tool_spec(&runtime_traversal, true);
    write_tool_policy(&runtime_traversal, &["tools.noop"]);
    write_workspace_policy(
        &runtime_traversal,
        workspace_policy_value("workspace", false, true),
    );
    let out = run_serverd_route_with_envs(
        &runtime_traversal,
        1,
        "tick:0",
        Some("demo"),
        &envs_traversal,
    );
    assert!(!out.status.success(), "run should fail");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("workspace_path_traversal")
    );
    let events = read_event_payloads(&runtime_traversal);
    let violation = find_event(&events, "workspace_violation");
    assert_eq!(
        violation.get("reason").and_then(|v| v.as_str()),
        Some("workspace_path_traversal")
    );

    let runtime_absolute =
        std::env::temp_dir().join(format!("pie_workspace_absolute_{}", Uuid::new_v4()));
    write_router_config(&runtime_absolute, "mock_tool");
    write_skill_manifest(
        &runtime_absolute,
        "demo",
        &["tools.noop"],
        Some("demo.contract"),
    );
    write_output_contract(
        &runtime_absolute,
        base_contract("demo.contract", &["tools.noop"]),
    );
    write_noop_tool_spec(&runtime_absolute, true);
    write_tool_policy(&runtime_absolute, &["tools.noop"]);
    write_workspace_policy(
        &runtime_absolute,
        workspace_policy_value("workspace", false, true),
    );
    let envs_absolute = [
        ("TOOLS_ENABLE", "1"),
        ("TOOLS_ARM", "1"),
        ("MOCK_TOOL_INPUT_PATH", "/tmp/escape.txt"),
    ];
    let out =
        run_serverd_route_with_envs(&runtime_absolute, 1, "tick:0", Some("demo"), &envs_absolute);
    assert!(!out.status.success(), "run should fail");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("workspace_path_escape")
    );
    let events = read_event_payloads(&runtime_absolute);
    let violation = find_event(&events, "workspace_violation");
    assert_eq!(
        violation.get("reason").and_then(|v| v.as_str()),
        Some("workspace_path_escape")
    );
}

#[cfg(unix)]
fn create_symlink_dir(link: &Path, target: &Path) {
    std::os::unix::fs::symlink(target, link).expect("create symlink");
}

#[cfg(windows)]
fn create_symlink_dir(link: &Path, target: &Path) {
    std::os::windows::fs::symlink_dir(target, link).expect("create symlink");
}
#[cfg(unix)]
fn create_symlink_file(link: &Path, target: &Path) {
    std::os::unix::fs::symlink(target, link).expect("create symlink");
}

#[cfg(windows)]
fn create_symlink_file(link: &Path, target: &Path) {
    std::os::windows::fs::symlink_file(target, link).expect("create symlink");
}

#[test]
fn workspace_symlink_escape_fails_closed() {
    let envs = [
        ("TOOLS_ENABLE", "1"),
        ("TOOLS_ARM", "1"),
        ("MOCK_TOOL_INPUT_PATH", "escape/target.txt"),
    ];
    let runtime_root =
        std::env::temp_dir().join(format!("pie_workspace_symlink_{}", Uuid::new_v4()));
    write_router_config(&runtime_root, "mock_tool");
    write_skill_manifest(
        &runtime_root,
        "demo",
        &["tools.noop"],
        Some("demo.contract"),
    );
    write_output_contract(
        &runtime_root,
        base_contract("demo.contract", &["tools.noop"]),
    );
    write_noop_tool_spec(&runtime_root, true);
    write_tool_policy(&runtime_root, &["tools.noop"]);
    write_workspace_policy(
        &runtime_root,
        workspace_policy_value("workspace", false, false),
    );

    let workspace_root = runtime_root.join("workspace");
    let outside = runtime_root.join("outside");
    fs::create_dir_all(&workspace_root).expect("create workspace root");
    fs::create_dir_all(&outside).expect("create outside dir");
    create_symlink_dir(&workspace_root.join("escape"), &outside);

    let out = run_serverd_route_with_envs(&runtime_root, 1, "tick:0", Some("demo"), &envs);
    assert!(!out.status.success(), "run should fail");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("workspace_symlink_escape")
    );
    let events = read_event_payloads(&runtime_root);
    let violation = find_event(&events, "workspace_violation");
    assert_eq!(
        violation.get("reason").and_then(|v| v.as_str()),
        Some("workspace_symlink_escape")
    );
}
#[test]
fn workspace_symlink_file_escape_fails_closed() {
    let envs = [
        ("TOOLS_ENABLE", "1"),
        ("TOOLS_ARM", "1"),
        ("MOCK_TOOL_INPUT_PATH", "escape.txt"),
    ];
    let runtime_root =
        std::env::temp_dir().join(format!("pie_workspace_symlink_file_{}", Uuid::new_v4()));
    write_router_config(&runtime_root, "mock_tool");
    write_skill_manifest(
        &runtime_root,
        "demo",
        &["tools.noop"],
        Some("demo.contract"),
    );
    write_output_contract(
        &runtime_root,
        base_contract("demo.contract", &["tools.noop"]),
    );
    write_noop_tool_spec(&runtime_root, true);
    write_tool_policy(&runtime_root, &["tools.noop"]);
    write_workspace_policy(
        &runtime_root,
        workspace_policy_value("workspace", false, false),
    );

    let workspace_root = runtime_root.join("workspace");
    let outside = runtime_root.join("outside");
    fs::create_dir_all(&workspace_root).expect("create workspace root");
    fs::create_dir_all(&outside).expect("create outside dir");
    let target = outside.join("target.txt");
    fs::write(&target, b"outside").expect("write target");
    create_symlink_file(&workspace_root.join("escape.txt"), &target);

    let out = run_serverd_route_with_envs(&runtime_root, 1, "tick:0", Some("demo"), &envs);
    assert!(!out.status.success(), "run should fail");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("workspace_symlink_escape")
    );
    let events = read_event_payloads(&runtime_root);
    let violation = find_event(&events, "workspace_violation");
    assert_eq!(
        violation.get("reason").and_then(|v| v.as_str()),
        Some("workspace_symlink_escape")
    );
}

#[test]
fn run_workspace_dir_deterministic_across_runtimes() {
    let envs = [
        ("TOOLS_ENABLE", "1"),
        ("TOOLS_ARM", "1"),
        ("MOCK_TOOL_INPUT_PATH", "safe.txt"),
    ];
    let runtime_one =
        std::env::temp_dir().join(format!("pie_workspace_run_one_{}", Uuid::new_v4()));
    let runtime_two =
        std::env::temp_dir().join(format!("pie_workspace_run_two_{}", Uuid::new_v4()));

    for runtime_root in [&runtime_one, &runtime_two] {
        write_initial_state(runtime_root);
        write_router_config(runtime_root, "mock_tool");
        write_skill_manifest(runtime_root, "demo", &["tools.noop"], Some("demo.contract"));
        write_output_contract(
            runtime_root,
            base_contract("demo.contract", &["tools.noop"]),
        );
        write_noop_tool_spec(runtime_root, true);
        write_tool_policy(runtime_root, &["tools.noop"]);
        write_workspace_policy(
            runtime_root,
            workspace_policy_value("workspace", false, true),
        );
        let out = run_serverd_route_with_envs(runtime_root, 1, "tick:0", Some("demo"), &envs);
        assert!(
            out.status.success(),
            "run failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let run_dir_one = single_run_dir(&runtime_one);
    let run_dir_two = single_run_dir(&runtime_two);
    assert_eq!(run_dir_one, run_dir_two);
}

fn single_run_dir(runtime_root: &Path) -> String {
    let runs_dir = runtime_root.join("workspace").join("runs");
    let mut entries = Vec::new();
    for entry in fs::read_dir(&runs_dir).expect("read runs dir") {
        let entry = entry.expect("read dir entry");
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            entries.push(name);
        }
    }
    assert_eq!(entries.len(), 1, "expected single run dir");
    entries[0].clone()
}
