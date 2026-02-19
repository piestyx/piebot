#![cfg(feature = "bin")]

use pie_common::{canonical_json_bytes, sha256_bytes};
use serverd::output_contract::OUTPUT_CONTRACT_SCHEMA;
use serverd::skills::SKILL_MANIFEST_SCHEMA;
use serverd::tools::execute::{
    TOOL_CALL_SCHEMA, TOOL_INPUT_WORKSPACE_APPLY_PATCH_SCHEMA, TOOL_OUTPUT_SCHEMA,
};
use serverd::tools::TOOL_SPEC_SCHEMA;
use serverd::tools::policy::TOOL_POLICY_SCHEMA;
use serverd::tools::workspace_apply_patch::{
    approval_scope_request_hash_hex, WorkspaceApplyPatchMode, WorkspaceApplyPatchRequest,
    WorkspaceApplyPatchResult, WorkspacePatchAction, WORKSPACE_APPLY_PATCH_NOT_APPROVED,
    WORKSPACE_APPLY_PATCH_PRECONDITION_MISMATCH, WORKSPACE_APPLY_PATCH_RESULT_SCHEMA,
    WORKSPACE_APPLY_PATCH_TOOL_ID, WORKSPACE_APPROVAL_SCHEMA,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use uuid::Uuid;
mod common;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn run_serverd_route(runtime_root: &Path, provider_mode: &str, envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(common::serverd_exe());
    cmd.arg("--mode")
        .arg("route")
        .arg("--ticks")
        .arg("1")
        .arg("--delta")
        .arg("tick:0")
        .arg("--provider")
        .arg(provider_mode)
        .arg("--skill")
        .arg("demo")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output().expect("failed to run serverd route")
}

fn run_workspace_patch_route(
    runtime_root: &Path,
    provider_mode: &str,
    input: &serde_json::Value,
    extra_envs: &[(&str, &str)],
) -> Output {
    let input_json = serde_json::to_string(input).expect("serialize mock tool input");
    let mut envs = vec![
        ("TOOLS_ENABLE", "1"),
        ("TOOLS_ARM", "1"),
        ("MOCK_TOOL_TOOL_ID", WORKSPACE_APPLY_PATCH_TOOL_ID),
        ("MOCK_TOOL_INPUT_JSON", input_json.as_str()),
    ];
    envs.extend_from_slice(extra_envs);
    run_serverd_route(runtime_root, provider_mode, &envs)
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
    fs::write(
        dir.join("config.json"),
        serde_json::to_vec(&value).expect("serialize router config"),
    )
    .expect("write router config");
}

fn write_skill_manifest(runtime_root: &Path, skill_id: &str, output_contract: &str) {
    let dir = runtime_root.join("skills").join(skill_id);
    fs::create_dir_all(&dir).expect("create skills dir");
    let value = serde_json::json!({
        "schema": SKILL_MANIFEST_SCHEMA,
        "skill_id": skill_id,
        "allowed_tools": [WORKSPACE_APPLY_PATCH_TOOL_ID],
        "tool_constraints": [],
        "prompt_template_refs": [],
        "output_contract": output_contract
    });
    fs::write(
        dir.join("skill.json"),
        serde_json::to_vec(&value).expect("serialize skill manifest"),
    )
    .expect("write skill manifest");
}

fn write_output_contract(runtime_root: &Path, contract_id: &str) {
    let dir = runtime_root.join("contracts");
    fs::create_dir_all(&dir).expect("create contracts dir");
    let value = serde_json::json!({
        "schema": OUTPUT_CONTRACT_SCHEMA,
        "contract_id": contract_id,
        "allowed_tool_calls": [WORKSPACE_APPLY_PATCH_TOOL_ID],
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
        dir.join(format!("{}.json", contract_id)),
        serde_json::to_vec(&value).expect("serialize output contract"),
    )
    .expect("write output contract");
}

fn write_workspace_apply_patch_tool_spec(runtime_root: &Path) {
    let dir = runtime_root.join("tools");
    fs::create_dir_all(&dir).expect("create tools dir");
    let value = serde_json::json!({
        "schema": TOOL_SPEC_SCHEMA,
        "id": WORKSPACE_APPLY_PATCH_TOOL_ID,
        "input_schema": TOOL_INPUT_WORKSPACE_APPLY_PATCH_SCHEMA,
        "output_schema": WORKSPACE_APPLY_PATCH_RESULT_SCHEMA,
        "deterministic": true,
        "risk_level": "low",
        "requires_approval": false,
        "requires_arming": false,
        "filesystem": false,
        "version": "v1"
    });
    fs::write(
        dir.join("workspace_apply_patch.json"),
        serde_json::to_vec(&value).expect("serialize tool spec"),
    )
    .expect("write tool spec");
}

fn write_tool_policy(runtime_root: &Path) {
    let dir = runtime_root.join("tools");
    fs::create_dir_all(&dir).expect("create tools dir");
    let value = serde_json::json!({
        "schema": TOOL_POLICY_SCHEMA,
        "allowed_tools": [WORKSPACE_APPLY_PATCH_TOOL_ID],
        "default_allow": false
    });
    fs::write(
        dir.join("policy.json"),
        serde_json::to_vec(&value).expect("serialize tool policy"),
    )
    .expect("write tool policy");
}

fn write_workspace_policy(runtime_root: &Path) {
    let dir = runtime_root.join("workspace");
    fs::create_dir_all(&dir).expect("create workspace dir");
    let value = serde_json::json!({
        "schema": "serverd.workspace_policy.v1",
        "enabled": true,
        "workspace_root": "workspace",
        "allow_repo_root": false,
        "per_run_dir": false
    });
    fs::write(
        dir.join("policy.json"),
        serde_json::to_vec(&value).expect("serialize workspace policy"),
    )
    .expect("write workspace policy");
}

fn setup_runtime(runtime_root: &Path) {
    write_initial_state(runtime_root);
    write_router_config(runtime_root, "mock_tool");
    write_skill_manifest(runtime_root, "demo", "demo.contract");
    write_output_contract(runtime_root, "demo.contract");
    write_workspace_apply_patch_tool_spec(runtime_root);
    write_tool_policy(runtime_root);
    write_workspace_policy(runtime_root);
    fs::create_dir_all(runtime_root.join("workspace")).expect("create workspace root");
}

fn read_event_payloads(runtime_root: &Path) -> Vec<serde_json::Value> {
    common::read_event_payloads(runtime_root)
}

fn find_event(events: &[serde_json::Value], event_type: &str) -> serde_json::Value {
    common::find_event(events, event_type)
}

fn find_last_event(events: &[serde_json::Value], event_type: &str) -> serde_json::Value {
    for event in events.iter().rev() {
        if event.get("event_type").and_then(|v| v.as_str()) == Some(event_type) {
            return event.clone();
        }
    }
    panic!("missing {}", event_type);
}

fn parse_error_reason(output: &Output) -> String {
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("run output json");
    value
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn artifact_path(runtime_root: &Path, subdir: &str, artifact_ref: &str) -> PathBuf {
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    runtime_root
        .join("artifacts")
        .join(subdir)
        .join(format!("{}.json", trimmed))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let hash = sha256_bytes(bytes);
    hash.strip_prefix("sha256:")
        .unwrap_or(hash.as_str())
        .to_string()
}

fn full_replace_request(
    target_path: &str,
    content: &str,
    precondition_sha256_hex: Option<String>,
    approval_ref: Option<String>,
) -> WorkspaceApplyPatchRequest {
    WorkspaceApplyPatchRequest {
        schema: TOOL_INPUT_WORKSPACE_APPLY_PATCH_SCHEMA.to_string(),
        target_path: target_path.to_string(),
        mode: WorkspaceApplyPatchMode::FullReplace,
        precondition_sha256_hex,
        patch: None,
        content: Some(content.to_string()),
        approval_ref,
    }
}

fn write_approval_artifact(runtime_root: &Path, request: &WorkspaceApplyPatchRequest) -> String {
    let request_hash_hex = approval_scope_request_hash_hex(request).expect("request hash hex");
    let approval_value = serde_json::json!({
        "schema": WORKSPACE_APPROVAL_SCHEMA,
        "approved": true,
        "scope": {
            "kind": "tool_call",
            "tool_id": WORKSPACE_APPLY_PATCH_TOOL_ID,
            "request_hash_hex": request_hash_hex
        },
        "operator": "test",
        "note": "approved"
    });
    let bytes = canonical_json_bytes(&approval_value).expect("canonical approval bytes");
    let approval_ref = sha256_bytes(&bytes);
    let path = artifact_path(runtime_root, "approvals", &approval_ref);
    fs::create_dir_all(path.parent().expect("approvals parent")).expect("create approvals dir");
    fs::write(path, bytes).expect("write approval artifact");
    approval_ref
}

fn copy_artifact_ref(
    src_runtime: &Path,
    dst_runtime: &Path,
    subdir: &str,
    artifact_ref_or_hash: &str,
) {
    let src = artifact_path(src_runtime, subdir, artifact_ref_or_hash);
    let dst = artifact_path(dst_runtime, subdir, artifact_ref_or_hash);
    fs::create_dir_all(dst.parent().expect("artifact parent")).expect("create artifact dir");
    fs::copy(src, dst).expect("copy artifact");
}

fn write_provider_response_artifact_with_tool_call(
    runtime_root: &Path,
    request_hash: &str,
    input: &serde_json::Value,
) {
    let output = serde_json::json!({
        "schema": serverd::provider::PROVIDER_OUTPUT_SCHEMA,
        "output": "replay_output",
        "tool_call": {
            "schema": TOOL_CALL_SCHEMA,
            "tool_id": WORKSPACE_APPLY_PATCH_TOOL_ID,
            "request_hash": request_hash,
            "input": input
        }
    });
    let response = serde_json::json!({
        "schema": serverd::provider::PROVIDER_RESPONSE_SCHEMA,
        "request_hash": request_hash,
        "model": "mock_tool",
        "output": output
    });
    let response_hash =
        sha256_bytes(&canonical_json_bytes(&response).expect("canonical response"));
    let artifact = serde_json::json!({
        "schema": serverd::provider::PROVIDER_RESPONSE_ARTIFACT_SCHEMA,
        "request_hash": request_hash,
        "provider_id": "mock_tool",
        "response": response,
        "response_hash": response_hash,
        "created_from_run_id": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "created_from_tick_index": 0
    });
    let path = artifact_path(runtime_root, "provider_responses", request_hash);
    fs::create_dir_all(path.parent().expect("provider response parent"))
        .expect("create provider response dir");
    fs::write(
        path,
        canonical_json_bytes(&artifact).expect("canonical provider response artifact"),
    )
    .expect("write provider response artifact");
}

fn observed_files_for_request_hash(runtime_root: &Path) -> Vec<String> {
    fn collect_files(base: &Path, dir: &Path, out: &mut Vec<String>) {
        if !dir.exists() {
            return;
        }
        let entries = fs::read_dir(dir).expect("read_dir failed");
        for entry in entries {
            let entry = entry.expect("read_dir entry failed");
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str());
                if name == Some("logs")
                    || name == Some("provider_responses")
                    || name == Some("tool_outputs")
                {
                    continue;
                }
                collect_files(base, &path, out);
            } else if path.is_file() {
                let rel = path.strip_prefix(base).unwrap_or(&path);
                out.push(rel.to_string_lossy().to_string());
            }
        }
    }

    let mut observed = Vec::new();
    collect_files(runtime_root, runtime_root, &mut observed);
    observed.sort();
    observed
}

fn compute_route_request_hash_tick0(runtime_root: &Path) -> String {
    let state_path = runtime_root.join("state").join("kernel_state.json");
    let state = pie_kernel_state::load_or_init(&state_path).expect("load state");
    let state_hash = pie_kernel_state::state_hash(&state);
    let observation = serde_json::json!({
        "tick_index": 0,
        "observed_files": observed_files_for_request_hash(runtime_root)
    });
    let observation_hash =
        sha256_bytes(&canonical_json_bytes(&observation).expect("canonical observation"));
    let request_input = serde_json::json!({
        "tick_index": 0,
        "state_hash": state_hash,
        "observation_hash": observation_hash,
        "intent": { "kind": "no_op" },
        "requested_tick": 0
    });
    sha256_bytes(&canonical_json_bytes(&request_input).expect("canonical request hash input"))
}

#[test]
fn traversal_denied() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let runtime_root = std::env::temp_dir().join(format!("pie_wsp_traversal_{}", Uuid::new_v4()));
    setup_runtime(&runtime_root);
    let request = full_replace_request("../escape.txt", "x", None, None);
    let input = serde_json::to_value(request).expect("request to json");
    let out = run_workspace_patch_route(
        &runtime_root,
        "live",
        &input,
        &[("WORKSPACE_PATCH_APPROVAL_BYPASS", "1")],
    );
    assert!(!out.status.success(), "run should fail closed");
    assert_eq!(parse_error_reason(&out), "workspace_path_traversal");
}

#[test]
fn symlink_denied() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let runtime_root = std::env::temp_dir().join(format!("pie_wsp_symlink_{}", Uuid::new_v4()));
    setup_runtime(&runtime_root);
    let workspace_root = runtime_root.join("workspace");
    let outside_root = runtime_root.join("outside");
    fs::create_dir_all(&outside_root).expect("create outside root");
    let outside_target = outside_root.join("target.txt");
    fs::write(&outside_target, b"outside").expect("write outside target");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside_target, workspace_root.join("escape.txt"))
        .expect("create symlink");
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&outside_target, workspace_root.join("escape.txt"))
        .expect("create symlink");
    let request = full_replace_request("escape.txt", "x", None, None);
    let input = serde_json::to_value(request).expect("request to json");
    let out = run_workspace_patch_route(
        &runtime_root,
        "live",
        &input,
        &[("WORKSPACE_PATCH_APPROVAL_BYPASS", "1")],
    );
    assert!(!out.status.success(), "run should fail closed");
    assert_eq!(parse_error_reason(&out), "workspace_symlink_escape");
}

#[test]
fn precondition_mismatch_fails_closed() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let runtime_root = std::env::temp_dir().join(format!("pie_wsp_precondition_{}", Uuid::new_v4()));
    setup_runtime(&runtime_root);
    let target = runtime_root.join("workspace").join("target.txt");
    fs::write(&target, b"old").expect("write old");
    let old_hash = sha256_hex(b"old");
    fs::write(&target, b"new").expect("write new");
    let request = full_replace_request("target.txt", "final", Some(old_hash), None);
    let input = serde_json::to_value(request).expect("request to json");
    let out = run_workspace_patch_route(
        &runtime_root,
        "live",
        &input,
        &[("WORKSPACE_PATCH_APPROVAL_BYPASS", "1")],
    );
    assert!(!out.status.success(), "run should fail closed");
    assert_eq!(
        parse_error_reason(&out),
        WORKSPACE_APPLY_PATCH_PRECONDITION_MISMATCH
    );
}

#[test]
fn approval_required() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let runtime_root = std::env::temp_dir().join(format!("pie_wsp_approval_required_{}", Uuid::new_v4()));
    setup_runtime(&runtime_root);
    fs::write(runtime_root.join("workspace").join("target.txt"), b"before").expect("write before");
    let request = full_replace_request("target.txt", "after", None, None);
    let input = serde_json::to_value(request).expect("request to json");
    let out = run_workspace_patch_route(&runtime_root, "live", &input, &[]);
    assert!(!out.status.success(), "run should fail closed");
    assert_eq!(parse_error_reason(&out), WORKSPACE_APPLY_PATCH_NOT_APPROVED);
}

#[test]
fn approval_success() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let runtime_root = std::env::temp_dir().join(format!("pie_wsp_approval_success_{}", Uuid::new_v4()));
    setup_runtime(&runtime_root);
    let target = runtime_root.join("workspace").join("target.txt");
    fs::write(&target, b"before").expect("write before");
    let mut request = full_replace_request("target.txt", "after", None, None);
    let approval_ref = write_approval_artifact(&runtime_root, &request);
    request.approval_ref = Some(approval_ref.clone());
    let input = serde_json::to_value(request).expect("request to json");
    let out = run_workspace_patch_route(&runtime_root, "live", &input, &[]);
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read(&target).expect("read target"), b"after");
    let events = read_event_payloads(&runtime_root);
    let request_hash = find_event(&events, "provider_request_written")
        .get("request_hash")
        .and_then(|v| v.as_str())
        .expect("missing request_hash")
        .to_string();
    let output_ref = find_last_event(&events, "tool_output_written")
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("missing output_ref")
        .to_string();
    let output_value: serde_json::Value =
        serde_json::from_slice(&fs::read(artifact_path(&runtime_root, "tool_outputs", &output_ref)).expect("read output artifact"))
            .expect("output artifact json");
    assert_eq!(
        output_value.get("schema").and_then(|v| v.as_str()),
        Some(TOOL_OUTPUT_SCHEMA)
    );
    let result: WorkspaceApplyPatchResult = serde_json::from_value(
        output_value
            .get("output")
            .cloned()
            .expect("tool output payload"),
    )
    .expect("workspace patch result");
    assert_eq!(result.schema, WORKSPACE_APPLY_PATCH_RESULT_SCHEMA);
    assert_eq!(result.action, WorkspacePatchAction::Applied);
    assert_eq!(result.approval_ref.as_deref(), Some(approval_ref.as_str()));
    assert!(artifact_path(&runtime_root, "tool_outputs", &request_hash).is_file());
    let applied_event = find_last_event(&events, "workspace_patch_applied");
    assert_eq!(
        applied_event.get("target_path").and_then(|v| v.as_str()),
        Some("target.txt")
    );
}

#[test]
fn deterministic_outputs_across_runtime_roots() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let runtime_one = std::env::temp_dir().join(format!("pie_wsp_det_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_wsp_det_two_{}", Uuid::new_v4()));
    for runtime_root in [&runtime_one, &runtime_two] {
        setup_runtime(runtime_root);
        fs::write(runtime_root.join("workspace").join("target.txt"), b"before").expect("write before");
    }
    let request = full_replace_request("target.txt", "after", None, None);
    let input = serde_json::to_value(request).expect("request to json");
    let out_one = run_workspace_patch_route(
        &runtime_one,
        "live",
        &input,
        &[("WORKSPACE_PATCH_APPROVAL_BYPASS", "1")],
    );
    let out_two = run_workspace_patch_route(
        &runtime_two,
        "live",
        &input,
        &[("WORKSPACE_PATCH_APPROVAL_BYPASS", "1")],
    );
    assert!(out_one.status.success(), "run one failed");
    assert!(out_two.status.success(), "run two failed");
    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let request_hash_one = find_event(&events_one, "provider_request_written")
        .get("request_hash")
        .and_then(|v| v.as_str())
        .expect("request hash one")
        .to_string();
    let request_hash_two = find_event(&events_two, "provider_request_written")
        .get("request_hash")
        .and_then(|v| v.as_str())
        .expect("request hash two")
        .to_string();
    assert_eq!(request_hash_one, request_hash_two);
    let output_ref_one = find_last_event(&events_one, "tool_output_written")
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("output ref one")
        .to_string();
    let output_ref_two = find_last_event(&events_two, "tool_output_written")
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("output ref two")
        .to_string();
    assert_eq!(output_ref_one, output_ref_two);
    let bytes_one =
        fs::read(artifact_path(&runtime_one, "tool_outputs", &output_ref_one)).expect("read one");
    let bytes_two =
        fs::read(artifact_path(&runtime_two, "tool_outputs", &output_ref_two)).expect("read two");
    assert_eq!(bytes_one, bytes_two);
    let alias_one =
        fs::read(artifact_path(&runtime_one, "tool_outputs", &request_hash_one)).expect("alias one");
    let alias_two =
        fs::read(artifact_path(&runtime_two, "tool_outputs", &request_hash_two)).expect("alias two");
    assert_eq!(alias_one, alias_two);
}

#[test]
fn replay_uses_recorded_tool_output_without_tool_execution_or_fs_write() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let runtime_record = std::env::temp_dir().join(format!("pie_wsp_replay_record_{}", Uuid::new_v4()));
    let runtime_replay = std::env::temp_dir().join(format!("pie_wsp_replay_replay_{}", Uuid::new_v4()));
    setup_runtime(&runtime_record);
    setup_runtime(&runtime_replay);
    let record_target = runtime_record.join("workspace").join("target.txt");
    let replay_target = runtime_replay.join("workspace").join("target.txt");
    fs::write(&record_target, b"before").expect("write record target");
    fs::write(&replay_target, b"before").expect("write replay target");
    let request = full_replace_request("target.txt", "after", None, None);
    let input = serde_json::to_value(request).expect("request to json");
    let out_record = run_workspace_patch_route(
        &runtime_record,
        "live",
        &input,
        &[("WORKSPACE_PATCH_APPROVAL_BYPASS", "1")],
    );
    assert!(
        out_record.status.success(),
        "record run failed: {}",
        String::from_utf8_lossy(&out_record.stderr)
    );
    assert_eq!(fs::read(&record_target).expect("read record target"), b"after");
    let record_events = read_event_payloads(&runtime_record);
    let output_ref = find_last_event(&record_events, "tool_output_written")
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("record output ref")
        .to_string();
    let replay_request_hash = compute_route_request_hash_tick0(&runtime_replay);
    write_provider_response_artifact_with_tool_call(&runtime_replay, &replay_request_hash, &input);
    copy_artifact_ref(&runtime_record, &runtime_replay, "tool_outputs", &output_ref);
    let output_bytes = fs::read(artifact_path(&runtime_record, "tool_outputs", &output_ref))
        .expect("read record output bytes");
    fs::write(
        artifact_path(&runtime_replay, "tool_outputs", &replay_request_hash),
        &output_bytes,
    )
    .expect("write replay request-keyed output");
    let out_replay = run_serverd_route(
        &runtime_replay,
        "replay",
        &[
            ("TOOLS_ENABLE", "1"),
            ("TOOLS_ARM", "1"),
            ("MOCK_PROVIDER_PANIC_IF_CALLED", "1"),
            ("PANIC_IF_WORKSPACE_APPLY_PATCH_CALLED", "1"),
        ],
    );
    let out_replay = if out_replay.status.success() {
        out_replay
    } else if parse_error_reason(&out_replay) == "provider_replay_missing_artifact" {
        let replay_events = read_event_payloads(&runtime_replay);
        let expected_hash = find_last_event(&replay_events, "provider_replay_missing_artifact")
            .get("request_hash")
            .and_then(|v| v.as_str())
            .expect("missing replay request hash")
            .to_string();
        write_provider_response_artifact_with_tool_call(&runtime_replay, &expected_hash, &input);
        fs::write(
            artifact_path(&runtime_replay, "tool_outputs", &expected_hash),
            &output_bytes,
        )
        .expect("write fallback replay request-keyed output");
        run_serverd_route(
            &runtime_replay,
            "replay",
            &[
                ("TOOLS_ENABLE", "1"),
                ("TOOLS_ARM", "1"),
                ("MOCK_PROVIDER_PANIC_IF_CALLED", "1"),
                ("PANIC_IF_WORKSPACE_APPLY_PATCH_CALLED", "1"),
            ],
        )
    } else {
        out_replay
    };
    assert!(
        out_replay.status.success(),
        "replay run failed: {}",
        String::from_utf8_lossy(&out_replay.stderr)
    );
    assert_eq!(fs::read(&replay_target).expect("read replay target"), b"before");
    let replay_events = read_event_payloads(&runtime_replay);
    let event_types: Vec<&str> = replay_events
        .iter()
        .filter_map(|event| event.get("event_type").and_then(|v| v.as_str()))
        .collect();
    assert!(event_types.contains(&"provider_response_artifact_loaded"));
    assert!(!event_types.contains(&"workspace_patch_requested"));
}
