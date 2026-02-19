use super::policy::{PolicyConfig, PolicyOutcome, ToolPolicy, ToolPolicyInput};
use super::{ToolError, ToolId, ToolRegistry, ToolSpec};
use crate::audit::{append_event, AuditEvent};
use crate::policy::workspace::{enforce_workspace_path, WorkspaceContext};
use crate::runtime::artifacts::{artifact_filename, write_json_artifact_atomic};
use pie_audit_log::AuditAppender;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const TOOL_CALL_SCHEMA: &str = "serverd.tool_call.v1";
pub const TOOL_OUTPUT_SCHEMA: &str = "serverd.tool_output.v1";
pub const TOOL_INPUT_NOOP_SCHEMA: &str = "serverd.tool_input.noop.v1";
pub const TOOL_OUTPUT_NOOP_SCHEMA: &str = "serverd.tool_output.noop.v1";
pub const TOOL_INPUT_FS_PROBE_SCHEMA: &str = "serverd.tool_input.fs_probe.v1";
pub const TOOL_OUTPUT_FS_PROBE_SCHEMA: &str = "serverd.tool_output.fs_probe.v1";

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

    let output_value = execute_builtin_tool(spec, &input_value)?;
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
    spec: &ToolSpec,
    _input: &serde_json::Value,
) -> Result<serde_json::Value, ToolError> {
    match spec.id.as_str() {
        "tools.noop" => {
            if spec.input_schema != TOOL_INPUT_NOOP_SCHEMA
                || spec.output_schema != TOOL_OUTPUT_NOOP_SCHEMA
            {
                return Err(ToolError::new("tool_spec_invalid"));
            }
            Ok(serde_json::json!({
                "schema": TOOL_OUTPUT_NOOP_SCHEMA,
                "ok": true
            }))
        }
        "tools.fs_probe" => {
            if spec.input_schema != TOOL_INPUT_FS_PROBE_SCHEMA
                || spec.output_schema != TOOL_OUTPUT_FS_PROBE_SCHEMA
            {
                return Err(ToolError::new("tool_spec_invalid"));
            }
            Ok(serde_json::json!({
                "schema": TOOL_OUTPUT_FS_PROBE_SCHEMA,
                "ok": true
            }))
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
