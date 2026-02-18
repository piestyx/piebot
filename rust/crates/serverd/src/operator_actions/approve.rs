use crate::audit::{append_event, succeed_run, AuditEvent};
use crate::command::OperatorApproveArgs;
use crate::mutations::{
    find_approval_request, write_approval_file, MutationError, ToolApprovalRequest,
};
use crate::operator_actions::common::{
    emit_completed, emit_error, emit_refused_and_error, emit_requested, normalize_and_hash_reason,
    prepare_operator_audit, read_run_events_for_run_id, OperatorActionTarget,
    OPERATOR_APPROVE_ACTION,
};
use crate::runtime::artifacts::{artifact_filename, is_sha256_ref};
use crate::tools::policy::TOOL_APPROVAL_REQUEST_SCHEMA;
use crate::tools::ToolId;
use pie_common::sha256_bytes;
use std::cmp::Ordering;
use std::fs;
use std::path::Path;

pub(crate) fn run_operator_approve(
    args: OperatorApproveArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut audit, audit_path) = match prepare_operator_audit(&args.runtime_root) {
        Ok(value) => value,
        Err(err) => return emit_error(err.reason()),
    };
    let mut target = OperatorActionTarget {
        run_id: Some(args.run_id.clone()),
        target_id: Some(args.tool_or_action_id.clone()),
        target_ref: None,
    };

    let reason_hash_result = normalize_and_hash_reason(&args.reason);
    let reason_hash = reason_hash_result.as_ref().ok().cloned();
    if emit_requested(&mut audit, OPERATOR_APPROVE_ACTION, &target, reason_hash).is_err() {
        return emit_error("operator_audit_failed");
    }
    if let Err(err) = reason_hash_result {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_APPROVE_ACTION,
            &target,
            err.reason(),
        );
    }

    if !is_sha256_ref(&args.run_id) {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_APPROVE_ACTION,
            &target,
            "run_id_invalid",
        );
    }
    let tool_id = match ToolId::parse(&args.tool_or_action_id) {
        Ok(value) => value,
        Err(_) => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_APPROVE_ACTION,
                &target,
                "tool_or_action_id_unknown",
            )
        }
    };

    let run_events = match read_run_events_for_run_id(&args.runtime_root, &args.run_id) {
        Ok(value) => value,
        Err(err) => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_APPROVE_ACTION,
                &target,
                err.reason(),
            )
        }
    };
    if !run_has_tool_approval_requirement(&run_events, &tool_id) {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_APPROVE_ACTION,
            &target,
            "tool_or_action_id_unknown",
        );
    }

    let input_ref = match args.input_ref.as_ref() {
        Some(value) => {
            if !is_sha256_ref(value) {
                return emit_refused_and_error(
                    &mut audit,
                    &audit_path,
                    OPERATOR_APPROVE_ACTION,
                    &target,
                    "input_ref_invalid",
                );
            }
            value.clone()
        }
        None => match resolve_input_ref_for_run_tool(&run_events, &args.runtime_root, &tool_id) {
            Ok(value) => value,
            Err(err) => {
                return emit_refused_and_error(
                    &mut audit,
                    &audit_path,
                    OPERATOR_APPROVE_ACTION,
                    &target,
                    err.reason(),
                )
            }
        },
    };
    target.target_ref = Some(input_ref.clone());

    let approval_match = match find_approval_request(&args.runtime_root, &tool_id, &input_ref) {
        Ok(value) => value,
        Err(err) => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_APPROVE_ACTION,
                &target,
                err.reason(),
            )
        }
    };
    if !is_sha256_ref(&approval_match.request_hash) {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_APPROVE_ACTION,
            &target,
            "approval_request_invalid",
        );
    }
    if let Err(err) = write_approval_file(
        &args.runtime_root,
        &approval_match.approval_ref,
        &tool_id,
        &approval_match.request_hash,
        &input_ref,
    ) {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_APPROVE_ACTION,
            &target,
            err.reason(),
        );
    }
    let approval_path = approval_output_path(&args.runtime_root, &approval_match.approval_ref);
    let approval_bytes = match fs::read(&approval_path) {
        Ok(value) => value,
        Err(_) => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_APPROVE_ACTION,
                &target,
                "approval_read_failed",
            )
        }
    };
    let approval_artifact_hash = sha256_bytes(&approval_bytes);
    if append_event(
        &mut audit,
        AuditEvent::ApprovalCreated {
            tool_id: tool_id.as_str().to_string(),
            approval_ref: approval_match.approval_ref.clone(),
            input_ref: input_ref.clone(),
            request_hash: approval_match.request_hash.clone(),
            run_id: Some(args.run_id.clone()),
        },
    )
    .is_err()
    {
        return emit_error("operator_audit_failed");
    }
    if let Err(err) = emit_completed(
        &mut audit,
        OPERATOR_APPROVE_ACTION,
        &target,
        Some(approval_match.approval_ref.clone()),
        Some(approval_artifact_hash.clone()),
    ) {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_APPROVE_ACTION,
            &target,
            err.reason(),
        );
    }
    let mut payload = serde_json::Map::new();
    payload.insert("ok".to_string(), serde_json::Value::Bool(true));
    payload.insert(
        "action".to_string(),
        serde_json::Value::String(OPERATOR_APPROVE_ACTION.to_string()),
    );
    payload.insert(
        "run_id".to_string(),
        serde_json::Value::String(args.run_id.clone()),
    );
    payload.insert(
        "tool_id".to_string(),
        serde_json::Value::String(tool_id.as_str().to_string()),
    );
    payload.insert(
        "input_ref".to_string(),
        serde_json::Value::String(input_ref),
    );
    payload.insert(
        "approval_ref".to_string(),
        serde_json::Value::String(approval_match.approval_ref),
    );
    payload.insert(
        "audit_hash".to_string(),
        serde_json::Value::String(audit.last_hash().to_string()),
    );
    succeed_run(
        &mut audit,
        &audit_path,
        serde_json::Value::Object(payload),
        false,
    )
}

fn resolve_input_ref_for_run_tool(
    run_events: &[serde_json::Value],
    runtime_root: &Path,
    tool_id: &ToolId,
) -> Result<String, MutationError> {
    let mut approval_refs = Vec::new();
    for event in run_events {
        if event.get("event_type").and_then(|v| v.as_str()) != Some("tool_approval_required") {
            continue;
        }
        if event.get("tool_id").and_then(|v| v.as_str()) != Some(tool_id.as_str()) {
            continue;
        }
        let approval_ref = event
            .get("approval_ref")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MutationError::new("approval_request_invalid"))?;
        if !is_sha256_ref(approval_ref) {
            return Err(MutationError::new("approval_request_invalid"));
        }
        approval_refs.push(approval_ref.to_string());
    }
    approval_refs.sort();
    approval_refs.dedup();
    match approval_refs.len().cmp(&1) {
        Ordering::Less => Err(MutationError::new("approval_request_missing")),
        Ordering::Greater => Err(MutationError::new("approval_request_ambiguous")),
        Ordering::Equal => {
            read_input_ref_for_approval_ref(runtime_root, tool_id, &approval_refs[0])
        }
    }
}

fn run_has_tool_approval_requirement(run_events: &[serde_json::Value], tool_id: &ToolId) -> bool {
    run_events.iter().any(|event| {
        event.get("event_type").and_then(|v| v.as_str()) == Some("tool_approval_required")
            && event.get("tool_id").and_then(|v| v.as_str()) == Some(tool_id.as_str())
    })
}

fn read_input_ref_for_approval_ref(
    runtime_root: &Path,
    tool_id: &ToolId,
    approval_ref: &str,
) -> Result<String, MutationError> {
    let path = runtime_root
        .join("artifacts")
        .join("approvals")
        .join(artifact_filename(approval_ref));
    let bytes = fs::read(&path)
        .map_err(|e| MutationError::with_detail("approval_request_missing", e.to_string()))?;
    let request: ToolApprovalRequest = serde_json::from_slice(&bytes)
        .map_err(|_| MutationError::new("approval_request_invalid"))?;
    if request.schema != TOOL_APPROVAL_REQUEST_SCHEMA {
        return Err(MutationError::new("approval_request_invalid"));
    }
    if request.tool_id != tool_id.as_str() {
        return Err(MutationError::new("approval_request_invalid"));
    }
    if !is_sha256_ref(&request.request_hash) || !is_sha256_ref(&request.input_ref) {
        return Err(MutationError::new("approval_request_invalid"));
    }
    Ok(request.input_ref)
}

fn approval_output_path(runtime_root: &Path, approval_ref: &str) -> std::path::PathBuf {
    let trimmed = approval_ref.strip_prefix("sha256:").unwrap_or(approval_ref);
    runtime_root
        .join("approvals")
        .join(format!("{}.approved.json", trimmed))
}
