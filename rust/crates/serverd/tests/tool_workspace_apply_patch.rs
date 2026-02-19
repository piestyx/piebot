#![cfg(feature = "bin")]

use pie_common::{canonical_json_bytes, sha256_bytes};
use serverd::output_contract::OUTPUT_CONTRACT_SCHEMA;
use serverd::skills::SKILL_MANIFEST_SCHEMA;
use serverd::tools::execute::{
    ToolOutput, TOOL_CALL_SCHEMA, TOOL_INPUT_WORKSPACE_APPLY_PATCH_SCHEMA, TOOL_OUTPUT_SCHEMA,
};
use serverd::tools::policy::TOOL_POLICY_SCHEMA;
use serverd::tools::workspace_apply_patch::{
    approval_scope_request_hash_hex, execute_request_with_workspace_policy, LinePatchOp,
    WorkspaceApplyPatchMode, WorkspaceApplyPatchRequest, WorkspaceApplyPatchResult,
    WorkspacePatchAction, WORKSPACE_APPLY_PATCH_NOT_APPROVED,
    WORKSPACE_APPLY_PATCH_PRECONDITION_MISMATCH, WORKSPACE_APPLY_PATCH_RESULT_SCHEMA,
    WORKSPACE_APPLY_PATCH_TOOL_ID, WORKSPACE_APPROVAL_SCHEMA,
};
use serverd::tools::{ToolId, TOOL_SPEC_SCHEMA};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use uuid::Uuid;
mod common;

static ENV_LOCK: Mutex<()> = Mutex::new(());
const RUN_ID: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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

fn artifact_path(runtime_root: &Path, subdir: &str, artifact_ref: &str) -> PathBuf {
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    runtime_root
        .join("artifacts")
        .join(subdir)
        .join(format!("{}.json", trimmed))
}

fn write_initial_state(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
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

fn setup_workspace_runtime(runtime_root: &Path) {
    write_initial_state(runtime_root);
    write_workspace_policy(runtime_root);
    fs::create_dir_all(runtime_root.join("workspace")).expect("create workspace root");
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

fn setup_route_runtime(runtime_root: &Path) {
    setup_workspace_runtime(runtime_root);
    write_router_config(runtime_root, "mock_tool");
    write_skill_manifest(runtime_root, "demo", "demo.contract");
    write_output_contract(runtime_root, "demo.contract");
    write_workspace_apply_patch_tool_spec(runtime_root);
    write_tool_policy(runtime_root);
}

fn sha256_hex(bytes: &[u8]) -> String {
    let hash = sha256_bytes(bytes);
    hash.strip_prefix("sha256:")
        .unwrap_or(hash.as_str())
        .to_string()
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

fn full_replace_request(target_path: &str, content: &str) -> WorkspaceApplyPatchRequest {
    WorkspaceApplyPatchRequest {
        schema: TOOL_INPUT_WORKSPACE_APPLY_PATCH_SCHEMA.to_string(),
        target_path: target_path.to_string(),
        mode: WorkspaceApplyPatchMode::FullReplace,
        allow_create: false,
        allow_create_parents: false,
        precondition_sha256_hex: None,
        patch: None,
        line_patch: None,
        content: Some(content.to_string()),
        approval_ref: None,
    }
}

fn line_patch_request(target_path: &str, ops: Vec<LinePatchOp>) -> WorkspaceApplyPatchRequest {
    WorkspaceApplyPatchRequest {
        schema: TOOL_INPUT_WORKSPACE_APPLY_PATCH_SCHEMA.to_string(),
        target_path: target_path.to_string(),
        mode: WorkspaceApplyPatchMode::LinePatch,
        allow_create: false,
        allow_create_parents: false,
        precondition_sha256_hex: None,
        patch: None,
        line_patch: Some(ops),
        content: None,
        approval_ref: None,
    }
}

fn execute_workspace_patch_direct(
    runtime_root: &Path,
    request: &WorkspaceApplyPatchRequest,
) -> Result<WorkspaceApplyPatchResult, String> {
    let input_value = serde_json::to_value(request).expect("request to value");
    execute_request_with_workspace_policy(runtime_root, RUN_ID, "sha256:test_request", &input_value)
        .map(|execution| execution.result)
        .map_err(|error| error.reason().to_string())
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
    fs::create_dir_all(path.parent().expect("approval parent")).expect("create approvals dir");
    fs::write(path, bytes).expect("write approval artifact");
    approval_ref
}

fn write_provider_response_artifact_with_tool_call(
    runtime_root: &Path,
    request_hash: &str,
    input_value: &serde_json::Value,
) {
    let output = serde_json::json!({
        "schema": serverd::provider::PROVIDER_OUTPUT_SCHEMA,
        "output": "replay_output",
        "tool_call": {
            "schema": TOOL_CALL_SCHEMA,
            "tool_id": WORKSPACE_APPLY_PATCH_TOOL_ID,
            "request_hash": request_hash,
            "input": input_value
        }
    });
    let response = serde_json::json!({
        "schema": serverd::provider::PROVIDER_RESPONSE_SCHEMA,
        "request_hash": request_hash,
        "model": "mock_tool",
        "output": output
    });
    let response_hash =
        sha256_bytes(&canonical_json_bytes(&response).expect("canonical response value"));
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
    fs::create_dir_all(path.parent().expect("provider_responses parent"))
        .expect("create provider_responses dir");
    fs::write(
        path,
        canonical_json_bytes(&artifact).expect("canonical provider response artifact"),
    )
    .expect("write provider response artifact");
}

fn write_recorded_tool_output_for_request(
    runtime_root: &Path,
    request_hash: &str,
    input_value: &serde_json::Value,
    result: &WorkspaceApplyPatchResult,
) {
    let input_ref =
        sha256_bytes(&canonical_json_bytes(input_value).expect("canonical input value"));
    let tool_output = ToolOutput {
        schema: TOOL_OUTPUT_SCHEMA.to_string(),
        tool_id: ToolId::parse(WORKSPACE_APPLY_PATCH_TOOL_ID).expect("tool id parse"),
        input_ref,
        output: serde_json::to_value(result).expect("result to value"),
        tool_version: "v1".to_string(),
        deterministic: true,
    };
    let output_value = serde_json::to_value(&tool_output).expect("tool output to value");
    let output_bytes = canonical_json_bytes(&output_value).expect("canonical tool output bytes");
    let output_ref = sha256_bytes(&output_bytes);
    let hash_path = artifact_path(runtime_root, "tool_outputs", &output_ref);
    fs::create_dir_all(hash_path.parent().expect("tool output parent"))
        .expect("create tool_outputs dir");
    fs::write(&hash_path, &output_bytes).expect("write hash-addressed output");
    fs::write(
        artifact_path(runtime_root, "tool_outputs", request_hash),
        output_bytes,
    )
    .expect("write request-keyed output");
}

#[test]
fn traversal_denied() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("WORKSPACE_PATCH_APPROVAL_BYPASS", "1");
    let runtime_root = std::env::temp_dir().join(format!("pie_wsp_traversal_{}", Uuid::new_v4()));
    setup_workspace_runtime(&runtime_root);
    let request = full_replace_request("../escape.txt", "x");
    let result = execute_workspace_patch_direct(&runtime_root, &request);
    assert_eq!(
        result.expect_err("expected traversal denial"),
        "workspace_path_traversal"
    );
    std::env::remove_var("WORKSPACE_PATCH_APPROVAL_BYPASS");
}

#[test]
fn symlink_denied() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("WORKSPACE_PATCH_APPROVAL_BYPASS", "1");
    let runtime_root = std::env::temp_dir().join(format!("pie_wsp_symlink_{}", Uuid::new_v4()));
    setup_workspace_runtime(&runtime_root);
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
    let request = full_replace_request("escape.txt", "x");
    let result = execute_workspace_patch_direct(&runtime_root, &request);
    assert_eq!(
        result.expect_err("expected symlink denial"),
        "workspace_symlink_escape"
    );
    std::env::remove_var("WORKSPACE_PATCH_APPROVAL_BYPASS");
}

#[test]
fn precondition_mismatch_fails_closed() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("WORKSPACE_PATCH_APPROVAL_BYPASS", "1");
    let runtime_root =
        std::env::temp_dir().join(format!("pie_wsp_precondition_{}", Uuid::new_v4()));
    setup_workspace_runtime(&runtime_root);
    let target = runtime_root.join("workspace").join("target.txt");
    fs::write(&target, b"old").expect("write old");
    let old_hash = sha256_hex(b"old");
    fs::write(&target, b"new").expect("write new");
    let mut request = full_replace_request("target.txt", "final");
    request.precondition_sha256_hex = Some(old_hash);
    let result = execute_workspace_patch_direct(&runtime_root, &request);
    assert_eq!(
        result.expect_err("expected precondition mismatch"),
        WORKSPACE_APPLY_PATCH_PRECONDITION_MISMATCH
    );
    std::env::remove_var("WORKSPACE_PATCH_APPROVAL_BYPASS");
}

#[test]
fn approval_required() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("WORKSPACE_PATCH_APPROVAL_BYPASS");
    let runtime_root =
        std::env::temp_dir().join(format!("pie_wsp_approval_required_{}", Uuid::new_v4()));
    setup_workspace_runtime(&runtime_root);
    fs::write(runtime_root.join("workspace").join("target.txt"), b"before").expect("write before");
    let request = full_replace_request("target.txt", "after");
    let result = execute_workspace_patch_direct(&runtime_root, &request);
    assert_eq!(
        result.expect_err("expected approval required"),
        WORKSPACE_APPLY_PATCH_NOT_APPROVED
    );
}

#[test]
fn approval_success() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("WORKSPACE_PATCH_APPROVAL_BYPASS");
    let runtime_root =
        std::env::temp_dir().join(format!("pie_wsp_approval_success_{}", Uuid::new_v4()));
    setup_workspace_runtime(&runtime_root);
    let target = runtime_root.join("workspace").join("target.txt");
    fs::write(&target, b"before").expect("write before");
    let mut request = full_replace_request("target.txt", "after");
    let approval_ref = write_approval_artifact(&runtime_root, &request);
    request.approval_ref = Some(approval_ref.clone());
    let result = execute_workspace_patch_direct(&runtime_root, &request).expect("direct execute");
    assert_eq!(result.action, WorkspacePatchAction::Applied);
    assert!(!result.created);
    assert_eq!(result.approval_ref.as_deref(), Some(approval_ref.as_str()));
    assert_eq!(fs::read(&target).expect("read target"), b"after");
}

#[test]
fn create_new_file_denied_by_default() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("WORKSPACE_PATCH_APPROVAL_BYPASS", "1");
    let runtime_root =
        std::env::temp_dir().join(format!("pie_wsp_create_denied_{}", Uuid::new_v4()));
    setup_workspace_runtime(&runtime_root);
    let request = full_replace_request("new_file.txt", "hello");
    let result = execute_workspace_patch_direct(&runtime_root, &request);
    assert_eq!(
        result.expect_err("expected missing target failure"),
        "workspace_path_nonexistent"
    );
    std::env::remove_var("WORKSPACE_PATCH_APPROVAL_BYPASS");
}

#[test]
fn create_new_file_allowed_with_allow_create() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("WORKSPACE_PATCH_APPROVAL_BYPASS", "1");
    let runtime_root =
        std::env::temp_dir().join(format!("pie_wsp_create_allowed_{}", Uuid::new_v4()));
    setup_workspace_runtime(&runtime_root);
    let mut request = full_replace_request("new_file.txt", "hello");
    request.allow_create = true;
    let result = execute_workspace_patch_direct(&runtime_root, &request).expect("direct execute");
    assert_eq!(result.action, WorkspacePatchAction::Applied);
    assert!(result.created);
    assert_eq!(
        fs::read(runtime_root.join("workspace").join("new_file.txt")).expect("read new file"),
        b"hello"
    );
    std::env::remove_var("WORKSPACE_PATCH_APPROVAL_BYPASS");
}

#[test]
fn create_new_dirs_denied_by_default() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("WORKSPACE_PATCH_APPROVAL_BYPASS", "1");
    let runtime_root = std::env::temp_dir().join(format!("pie_wsp_dirs_denied_{}", Uuid::new_v4()));
    setup_workspace_runtime(&runtime_root);
    let mut request = full_replace_request("newdir/sub/file.txt", "hello");
    request.allow_create = true;
    request.allow_create_parents = false;
    let result = execute_workspace_patch_direct(&runtime_root, &request);
    assert_eq!(
        result.expect_err("expected missing parent failure"),
        "workspace_path_nonexistent"
    );
    std::env::remove_var("WORKSPACE_PATCH_APPROVAL_BYPASS");
}

#[test]
fn create_new_dirs_allowed() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("WORKSPACE_PATCH_APPROVAL_BYPASS", "1");
    let runtime_root =
        std::env::temp_dir().join(format!("pie_wsp_dirs_allowed_{}", Uuid::new_v4()));
    setup_workspace_runtime(&runtime_root);
    let mut request = full_replace_request("newdir/sub/file.txt", "hello");
    request.allow_create = true;
    request.allow_create_parents = true;
    let result = execute_workspace_patch_direct(&runtime_root, &request).expect("direct execute");
    assert_eq!(result.action, WorkspacePatchAction::Applied);
    assert!(result.created);
    assert_eq!(
        fs::read(
            runtime_root
                .join("workspace")
                .join("newdir")
                .join("sub")
                .join("file.txt")
        )
        .expect("read created file"),
        b"hello"
    );
    std::env::remove_var("WORKSPACE_PATCH_APPROVAL_BYPASS");
}

#[test]
fn create_parents_symlink_escape_denied() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("WORKSPACE_PATCH_APPROVAL_BYPASS", "1");
    let runtime_root =
        std::env::temp_dir().join(format!("pie_wsp_dirs_symlink_escape_{}", Uuid::new_v4()));
    setup_workspace_runtime(&runtime_root);
    let outside = runtime_root.join("outside");
    fs::create_dir_all(&outside).expect("create outside root");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, runtime_root.join("workspace").join("newdir"))
        .expect("create symlink dir");
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&outside, runtime_root.join("workspace").join("newdir"))
        .expect("create symlink dir");
    let mut request = full_replace_request("newdir/sub/file.txt", "hello");
    request.allow_create = true;
    request.allow_create_parents = true;
    let result = execute_workspace_patch_direct(&runtime_root, &request);
    assert_eq!(
        result.expect_err("expected symlink escape failure"),
        "workspace_symlink_escape"
    );
    std::env::remove_var("WORKSPACE_PATCH_APPROVAL_BYPASS");
}

#[test]
fn line_patch_applies_deterministically() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("WORKSPACE_PATCH_APPROVAL_BYPASS", "1");
    let runtime_one = std::env::temp_dir().join(format!("pie_wsp_line_det_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_wsp_line_det_two_{}", Uuid::new_v4()));
    for runtime_root in [&runtime_one, &runtime_two] {
        setup_workspace_runtime(runtime_root);
        fs::write(
            runtime_root.join("workspace").join("target.txt"),
            b"alpha\r\nbeta\r\n",
        )
        .expect("write seed file");
    }
    let request = line_patch_request(
        "target.txt",
        vec![
            LinePatchOp::ReplaceLines {
                start_line: 1,
                end_line_exclusive: 2,
                lines: vec!["bravo".to_string()],
            },
            LinePatchOp::InsertLines {
                at_line: 2,
                lines: vec!["charlie".to_string()],
            },
        ],
    );
    let result_one = execute_workspace_patch_direct(&runtime_one, &request).expect("execute one");
    let result_two = execute_workspace_patch_direct(&runtime_two, &request).expect("execute two");
    assert_eq!(result_one, result_two);
    let bytes_one = fs::read(runtime_one.join("workspace").join("target.txt")).expect("read one");
    let bytes_two = fs::read(runtime_two.join("workspace").join("target.txt")).expect("read two");
    assert_eq!(bytes_one, bytes_two);
    assert_eq!(bytes_one, b"alpha\nbravo\ncharlie\n");
    std::env::remove_var("WORKSPACE_PATCH_APPROVAL_BYPASS");
}

#[test]
fn line_patch_replay_uses_recorded_output() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let runtime_root = std::env::temp_dir().join(format!("pie_wsp_line_replay_{}", Uuid::new_v4()));
    setup_route_runtime(&runtime_root);
    let target = runtime_root.join("workspace").join("target.txt");
    fs::write(&target, b"before\n").expect("write initial target");

    let request = line_patch_request(
        "target.txt",
        vec![LinePatchOp::ReplaceLines {
            start_line: 0,
            end_line_exclusive: 1,
            lines: vec!["after".to_string()],
        }],
    );
    let request_value = serde_json::to_value(&request).expect("request value");

    let request_hash = compute_route_request_hash_tick0(&runtime_root);

    write_provider_response_artifact_with_tool_call(&runtime_root, &request_hash, &request_value);
    let recorded_result = WorkspaceApplyPatchResult {
        schema: WORKSPACE_APPLY_PATCH_RESULT_SCHEMA.to_string(),
        target_path: "target.txt".to_string(),
        action: WorkspacePatchAction::Applied,
        created: false,
        before_sha256_hex: sha256_hex(b"before\n"),
        after_sha256_hex: sha256_hex(b"after\n"),
        bytes_written: 6,
        applied_patch_sha256_hex: sha256_hex(
            &canonical_json_bytes(
                &serde_json::to_value(&request.line_patch).expect("line patch value"),
            )
            .expect("line patch canonical bytes"),
        ),
        precondition_checked: false,
        approval_ref: None,
    };
    write_recorded_tool_output_for_request(
        &runtime_root,
        &request_hash,
        &request_value,
        &recorded_result,
    );

    let replay = run_serverd_route(
        &runtime_root,
        "replay",
        &[
            ("TOOLS_ENABLE", "1"),
            ("TOOLS_ARM", "1"),
            ("MOCK_PROVIDER_PANIC_IF_CALLED", "1"),
            ("PANIC_IF_WORKSPACE_APPLY_PATCH_CALLED", "1"),
        ],
    );
    assert!(
        replay.status.success(),
        "replay run failed: {}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert_eq!(fs::read(&target).expect("read replay target"), b"before\n");
}
