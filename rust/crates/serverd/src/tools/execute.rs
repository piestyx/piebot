use super::policy::{PolicyConfig, PolicyOutcome, ToolPolicy, ToolPolicyInput};
use super::{ToolError, ToolId, ToolRegistry, ToolSpec};
use crate::audit::{append_event, AuditEvent};
use crate::policy::workspace::{enforce_workspace_path, WorkspaceContext};
use crate::runtime::artifacts::{
    artifact_filename, is_sha256_ref, write_json_artifact_at_ref_atomic, write_json_artifact_atomic,
};
use crate::tools::workspace_apply_patch;
use pie_audit_log::AuditAppender;
use pie_common::{canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const TOOL_CALL_SCHEMA: &str = "serverd.tool_call.v1";
pub const TOOL_OUTPUT_SCHEMA: &str = "serverd.tool_output.v1";
pub const TOOL_INPUT_NOOP_SCHEMA: &str = "serverd.tool_input.noop.v1";
pub const TOOL_OUTPUT_NOOP_SCHEMA: &str = "serverd.tool_output.noop.v1";
pub const TOOL_INPUT_FS_PROBE_SCHEMA: &str = "serverd.tool_input.fs_probe.v1";
pub const TOOL_OUTPUT_FS_PROBE_SCHEMA: &str = "serverd.tool_output.fs_probe.v1";
pub const TOOL_INPUT_WORKSPACE_APPLY_PATCH_SCHEMA: &str =
    workspace_apply_patch::WORKSPACE_APPLY_PATCH_REQUEST_SCHEMA;
pub const TOOL_OUTPUT_WORKSPACE_APPLY_PATCH_SCHEMA: &str =
    workspace_apply_patch::WORKSPACE_APPLY_PATCH_RESULT_SCHEMA;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ToolCall {
    pub schema: String,
    pub tool_id: ToolId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<serde_json::Value>,
    pub request_hash: String,
}

#[derive(Debug, Clone)]
struct BuiltinToolExecution {
    output_value: serde_json::Value,
    workspace_patch: Option<workspace_apply_patch::WorkspaceApplyPatchExecution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ToolOutput {
    pub schema: String,
    pub tool_id: ToolId,
    pub input_ref: String,
    pub output: serde_json::Value,
    pub tool_version: String,
    pub deterministic: bool,
}

pub fn execute_tool(
    runtime_root: &Path,
    registry: &ToolRegistry,
    config: &PolicyConfig,
    input: &ToolPolicyInput<'_>,
    workspace_ctx: Option<&WorkspaceContext>,
    audit: &mut AuditAppender,
) -> Result<String, ToolError> {
    match ToolPolicy::check(input, config, runtime_root, audit)? {
        PolicyOutcome::Allowed => {}
        PolicyOutcome::Denied { reason } => return Err(ToolError::new(reason)),
        PolicyOutcome::NeedsArming { reason } => return Err(ToolError::new(reason)),
        PolicyOutcome::NeedsApproval { approval_ref } => {
            let _ = approval_ref;
            return Err(ToolError::new("tool_approval_required"));
        }
    }

    let spec = registry
        .get(input.tool_id)
        .ok_or_else(|| ToolError::new("tool_spec_missing"))?;

    emit_tool_selected(audit, input.tool_id, input.input_ref, input.request_hash)?;

    let tool_call = ToolCall {
        schema: TOOL_CALL_SCHEMA.to_string(),
        tool_id: spec.id.clone(),
        input_ref: Some(input.input_ref.to_string()),
        input: None,
        request_hash: input.request_hash.to_string(),
    };
    let tool_call_value =
        serde_json::to_value(&tool_call).map_err(|_| ToolError::new("tool_call_invalid"))?;
    let tool_call_ref = write_json_artifact_atomic(runtime_root, "tool_calls", &tool_call_value)?;
    emit_tool_call_written(audit, input.tool_id, &tool_call_ref, input.request_hash)?;

    let input_value = read_tool_input(runtime_root, input.input_ref)?;
    validate_input_schema(&input_value, &spec.input_schema)?;
    if spec.filesystem {
        let path_value = input_value
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::new("tool_input_invalid"))?;
        let ctx = workspace_ctx.ok_or_else(|| ToolError::new("workspace_root_invalid"))?;
        if let Err(e) = enforce_workspace_path(ctx, Path::new(path_value)) {
            emit_workspace_violation(audit, input.tool_id, e.reason(), input.request_hash)?;
            return Err(ToolError::new(e.reason()));
        }
    }

    let execution = execute_builtin_tool(
        runtime_root,
        workspace_ctx,
        spec,
        &input_value,
        input.input_ref,
        input.request_hash,
        audit,
    )?;
    let output_value = execution.output_value;
    validate_output_schema(&output_value, &spec.output_schema)?;
    let output = ToolOutput {
        schema: TOOL_OUTPUT_SCHEMA.to_string(),
        tool_id: spec.id.clone(),
        input_ref: input.input_ref.to_string(),
        output: output_value,
        tool_version: spec.version.clone(),
        deterministic: spec.deterministic,
    };
    let output_value =
        serde_json::to_value(&output).map_err(|_| ToolError::new("tool_output_invalid"))?;
    let output_ref = write_json_artifact_atomic(runtime_root, "tool_outputs", &output_value)?;
    if let Some(workspace_execution) = execution.workspace_patch.as_ref() {
        write_json_artifact_at_ref_atomic(
            runtime_root,
            "tool_outputs",
            input.request_hash,
            &output_value,
        )?;
        let receipt_value =
            workspace_apply_patch::build_receipt_value(workspace_execution, output_ref.as_str())?;
        let receipt_ref =
            write_json_artifact_atomic(runtime_root, "workspace_patch_receipt", &receipt_value)?;
        emit_workspace_patch_applied(
            audit,
            workspace_execution.request_ref.as_str(),
            output_ref.as_str(),
            workspace_execution.result.target_path.as_str(),
            workspace_execution.result.before_sha256_hex.as_str(),
            workspace_execution.result.after_sha256_hex.as_str(),
            receipt_ref.as_str(),
        )?;
    }

    emit_tool_executed(
        audit,
        input.tool_id,
        input.input_ref,
        &output_ref,
        input.request_hash,
    )?;
    emit_tool_output_written(audit, input.tool_id, &output_ref, input.request_hash)?;

    Ok(output_ref)
}

pub fn parse_tool_call_from_provider_output(
    value: &serde_json::Value,
) -> Result<Option<ToolCall>, ToolError> {
    let tool_call_value = match value.get("tool_call") {
        Some(value) => value,
        None => return Ok(None),
    };
    let call: ToolCall = serde_json::from_value(tool_call_value.clone())
        .map_err(|_| ToolError::new("tool_call_invalid"))?;
    if call.schema != TOOL_CALL_SCHEMA {
        return Err(ToolError::new("tool_call_invalid"));
    }
    validate_tool_call_input(&call)?;
    Ok(Some(call))
}

fn validate_tool_call_input(call: &ToolCall) -> Result<(), ToolError> {
    let input_ref = call.input_ref.as_deref().unwrap_or("");
    let has_ref = !input_ref.is_empty();
    let has_input = call.input.is_some();
    if has_ref == has_input {
        return Err(ToolError::new("tool_call_invalid"));
    }
    if has_ref && input_ref.trim().is_empty() {
        return Err(ToolError::new("tool_call_invalid"));
    }
    if let Some(input) = call.input.as_ref() {
        if !input.is_object() {
            return Err(ToolError::new("tool_call_invalid"));
        }
    }
    Ok(())
}

fn execute_builtin_tool(
    runtime_root: &Path,
    workspace_ctx: Option<&WorkspaceContext>,
    spec: &ToolSpec,
    input: &serde_json::Value,
    input_ref: &str,
    request_hash: &str,
    audit: &mut AuditAppender,
) -> Result<BuiltinToolExecution, ToolError> {
    match spec.id.as_str() {
        "tools.noop" => {
            if spec.input_schema != TOOL_INPUT_NOOP_SCHEMA
                || spec.output_schema != TOOL_OUTPUT_NOOP_SCHEMA
            {
                return Err(ToolError::new("tool_spec_invalid"));
            }
            Ok(BuiltinToolExecution {
                output_value: serde_json::json!({
                    "schema": TOOL_OUTPUT_NOOP_SCHEMA,
                    "ok": true
                }),
                workspace_patch: None,
            })
        }
        "tools.fs_probe" => {
            if spec.input_schema != TOOL_INPUT_FS_PROBE_SCHEMA
                || spec.output_schema != TOOL_OUTPUT_FS_PROBE_SCHEMA
            {
                return Err(ToolError::new("tool_spec_invalid"));
            }
            Ok(BuiltinToolExecution {
                output_value: serde_json::json!({
                    "schema": TOOL_OUTPUT_FS_PROBE_SCHEMA,
                    "ok": true
                }),
                workspace_patch: None,
            })
        }
        workspace_apply_patch::WORKSPACE_APPLY_PATCH_TOOL_ID => {
            if spec.input_schema != TOOL_INPUT_WORKSPACE_APPLY_PATCH_SCHEMA
                || spec.output_schema != TOOL_OUTPUT_WORKSPACE_APPLY_PATCH_SCHEMA
            {
                return Err(ToolError::new("tool_spec_invalid"));
            }
            let workspace_ctx = workspace_ctx.ok_or_else(|| ToolError::new("workspace_root_invalid"))?;
            emit_workspace_patch_requested(audit, input_ref)?;
            let execution =
                match workspace_apply_patch::execute(runtime_root, workspace_ctx, input_ref, input) {
                    Ok(value) => value,
                    Err(err) => {
                        emit_workspace_patch_rejected(audit, input_ref, err.reason())?;
                        return Err(err);
                    }
                };
            let output_value = serde_json::to_value(&execution.result)
                .map_err(|_| ToolError::new("tool_output_invalid"))?;
            let _ = request_hash;
            Ok(BuiltinToolExecution {
                output_value,
                workspace_patch: Some(execution),
            })
        }
        _ => Err(ToolError::new("tool_not_implemented")),
    }
}

fn validate_input_schema(value: &serde_json::Value, expected: &str) -> Result<(), ToolError> {
    let schema = value.get("schema").and_then(|v| v.as_str()).unwrap_or("");
    if schema != expected {
        return Err(ToolError::new("tool_input_invalid"));
    }
    Ok(())
}

fn validate_output_schema(value: &serde_json::Value, expected: &str) -> Result<(), ToolError> {
    let schema = value.get("schema").and_then(|v| v.as_str()).unwrap_or("");
    if schema != expected {
        return Err(ToolError::new("tool_output_invalid"));
    }
    Ok(())
}

pub(crate) fn read_tool_input(
    runtime_root: &Path,
    input_ref: &str,
) -> Result<serde_json::Value, ToolError> {
    let path = tool_artifact_path(runtime_root, "tool_inputs", input_ref);
    let bytes = fs::read(&path).map_err(|e| ToolError::with_source("tool_input_read_failed", e))?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| ToolError::new("tool_input_invalid"))?;
    Ok(value)
}

fn tool_artifact_path(runtime_root: &Path, subdir: &str, artifact_ref: &str) -> PathBuf {
    runtime_root
        .join("artifacts")
        .join(subdir)
        .join(artifact_filename(artifact_ref))
}

fn emit_tool_selected(
    audit: &mut AuditAppender,
    tool_id: &ToolId,
    input_ref: &str,
    request_hash: &str,
) -> Result<(), ToolError> {
    emit_audit_event(
        audit,
        AuditEvent::ToolSelected {
            tool_id: tool_id.as_str().to_string(),
            input_ref: input_ref.to_string(),
            request_hash: request_hash.to_string(),
        },
    )
}

fn emit_workspace_patch_requested(audit: &mut AuditAppender, request_ref: &str) -> Result<(), ToolError> {
    emit_audit_event(
        audit,
        AuditEvent::WorkspacePatchRequested {
            request_ref: request_ref.to_string(),
        },
    )
}

fn emit_workspace_patch_applied(
    audit: &mut AuditAppender,
    request_ref: &str,
    result_ref: &str,
    target_path: &str,
    before_hex: &str,
    after_hex: &str,
    receipt_ref: &str,
) -> Result<(), ToolError> {
    emit_audit_event(
        audit,
        AuditEvent::WorkspacePatchApplied {
            request_ref: request_ref.to_string(),
            result_ref: result_ref.to_string(),
            target_path: target_path.to_string(),
            before_hex: before_hex.to_string(),
            after_hex: after_hex.to_string(),
            receipt_ref: Some(receipt_ref.to_string()),
        },
    )
}

fn emit_workspace_patch_rejected(
    audit: &mut AuditAppender,
    request_ref: &str,
    reason: &'static str,
) -> Result<(), ToolError> {
    emit_audit_event(
        audit,
        AuditEvent::WorkspacePatchRejected {
            request_ref: request_ref.to_string(),
            reason: reason.to_string(),
        },
    )
}

pub(crate) fn read_tool_output(
    runtime_root: &Path,
    output_ref: &str,
) -> Result<ToolOutput, ToolError> {
    let path = tool_artifact_path(runtime_root, "tool_outputs", output_ref);
    let bytes = fs::read(&path).map_err(|e| ToolError::with_source("tool_output_read_failed", e))?;
    let output: ToolOutput =
        serde_json::from_slice(&bytes).map_err(|_| ToolError::new("tool_output_invalid"))?;
    if output.schema != TOOL_OUTPUT_SCHEMA {
        return Err(ToolError::new("tool_output_invalid"));
    }
    Ok(output)
}

pub(crate) fn load_tool_output_ref_from_request_hash(
    runtime_root: &Path,
    request_hash: &str,
    expected_tool_id: &ToolId,
    expected_output_schema: &str,
) -> Result<String, ToolError> {
    if !is_sha256_ref(request_hash) {
        return Err(ToolError::new("tool_request_hash_invalid"));
    }
    let path = tool_artifact_path(runtime_root, "tool_outputs", request_hash);
    let bytes =
        fs::read(&path).map_err(|_| ToolError::new("tool_replay_missing_output_artifact"))?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| ToolError::new("tool_output_invalid"))?;
    let output: ToolOutput =
        serde_json::from_value(value.clone()).map_err(|_| ToolError::new("tool_output_invalid"))?;
    if output.schema != TOOL_OUTPUT_SCHEMA || output.tool_id != *expected_tool_id {
        return Err(ToolError::new("tool_output_invalid"));
    }
    let schema = output
        .output
        .get("schema")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if schema != expected_output_schema {
        return Err(ToolError::new("tool_output_invalid"));
    }
    let canonical =
        canonical_json_bytes(&value).map_err(|_| ToolError::new("tool_output_invalid"))?;
    let output_ref = sha256_bytes(&canonical);
    let output_hash_path = tool_artifact_path(runtime_root, "tool_outputs", &output_ref);
    if !output_hash_path.is_file() {
        return Err(ToolError::new("tool_replay_missing_output_artifact"));
    }
    Ok(output_ref)
}

fn emit_tool_executed(
    audit: &mut AuditAppender,
    tool_id: &ToolId,
    input_ref: &str,
    output_ref: &str,
    request_hash: &str,
) -> Result<(), ToolError> {
    emit_audit_event(
        audit,
        AuditEvent::ToolExecuted {
            tool_id: tool_id.as_str().to_string(),
            input_ref: input_ref.to_string(),
            output_ref: output_ref.to_string(),
            request_hash: request_hash.to_string(),
        },
    )
}

fn emit_tool_output_written(
    audit: &mut AuditAppender,
    tool_id: &ToolId,
    artifact_ref: &str,
    request_hash: &str,
) -> Result<(), ToolError> {
    emit_audit_event(
        audit,
        AuditEvent::ToolOutputWritten {
            tool_id: tool_id.as_str().to_string(),
            artifact_ref: artifact_ref.to_string(),
            request_hash: request_hash.to_string(),
        },
    )
}

fn emit_tool_call_written(
    audit: &mut AuditAppender,
    tool_id: &ToolId,
    tool_call_ref: &str,
    request_hash: &str,
) -> Result<(), ToolError> {
    emit_audit_event(
        audit,
        AuditEvent::ToolCallWritten {
            tool_id: tool_id.as_str().to_string(),
            tool_call_ref: tool_call_ref.to_string(),
            request_hash: request_hash.to_string(),
        },
    )
}

fn emit_workspace_violation(
    audit: &mut AuditAppender,
    tool_id: &ToolId,
    reason: &'static str,
    request_hash: &str,
) -> Result<(), ToolError> {
    emit_audit_event(
        audit,
        AuditEvent::WorkspaceViolation {
            tool_id: tool_id.as_str().to_string(),
            reason: reason.to_string(),
            request_hash: request_hash.to_string(),
        },
    )
}
fn emit_audit_event(audit: &mut AuditAppender, event: AuditEvent) -> Result<(), ToolError> {
    append_event(audit, event).map(|_| ()).map_err(|e| {
        ToolError::with_source(
            "tool_execution_audit_failed",
            std::io::Error::other(e.to_string()),
        )
    })
}
