use crate::audit::{append_event, succeed_run, AuditEvent};
use crate::command::OperatorRefuseArgs;
use crate::mutations::{read_audit_events_checked, MutationError};
use crate::operator_actions::common::{
    emit_completed, emit_error, emit_refused_and_error, emit_requested, normalize_and_hash_reason,
    prepare_operator_audit, read_run_events_for_run_id, OperatorActionTarget,
    OPERATOR_REFUSE_ACTION,
};
use crate::runtime::artifacts::is_sha256_ref;
use crate::tools::ToolId;
use std::cmp::Ordering;

pub(crate) fn run_operator_refuse(
    args: OperatorRefuseArgs,
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
    if emit_requested(&mut audit, OPERATOR_REFUSE_ACTION, &target, reason_hash).is_err() {
        return emit_error("operator_audit_failed");
    }
    if let Err(err) = reason_hash_result {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_REFUSE_ACTION,
            &target,
            err.reason(),
        );
    }

    if !is_sha256_ref(&args.run_id) {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_REFUSE_ACTION,
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
                OPERATOR_REFUSE_ACTION,
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
                OPERATOR_REFUSE_ACTION,
                &target,
                err.reason(),
            )
        }
    };
    let all_events = match read_audit_events_checked(&audit_path) {
        Ok(value) => value,
        Err(err) => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_REFUSE_ACTION,
                &target,
                err.reason(),
            )
        }
    };
    let approval_ref =
        match resolve_pending_approval_ref(&run_events, &all_events, &args.run_id, &tool_id) {
            Ok(value) => value,
            Err(err) => {
                return emit_refused_and_error(
                    &mut audit,
                    &audit_path,
                    OPERATOR_REFUSE_ACTION,
                    &target,
                    err.reason(),
                )
            }
        };
    target.target_ref = Some(approval_ref.clone());

    if append_event(
        &mut audit,
        AuditEvent::OperatorActionRefused {
            action: OPERATOR_REFUSE_ACTION.to_string(),
            reason: "operator_refused".to_string(),
            run_id: target.run_id.clone(),
            target_id: target.target_id.clone(),
            target_ref: target.target_ref.clone(),
        },
    )
    .is_err()
    {
        return emit_error("operator_audit_failed");
    }

    if emit_completed(
        &mut audit,
        OPERATOR_REFUSE_ACTION,
        &target,
        Some(approval_ref.clone()),
        None,
    )
    .is_err()
    {
        return emit_error("operator_audit_failed");
    }

    let mut payload = serde_json::Map::new();
    payload.insert("ok".to_string(), serde_json::Value::Bool(true));
    payload.insert(
        "action".to_string(),
        serde_json::Value::String(OPERATOR_REFUSE_ACTION.to_string()),
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
        "approval_ref".to_string(),
        serde_json::Value::String(approval_ref),
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

fn resolve_pending_approval_ref(
    run_events: &[serde_json::Value],
    all_events: &[serde_json::Value],
    run_id: &str,
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
    if approval_refs.is_empty() {
        return Err(MutationError::new("tool_or_action_id_unknown"));
    }
    let mut pending_refs = Vec::new();
    for approval_ref in approval_refs {
        if !approval_already_resolved(all_events, run_id, tool_id, &approval_ref) {
            pending_refs.push(approval_ref);
        }
    }
    match pending_refs.len().cmp(&1) {
        Ordering::Less => Err(MutationError::new("tool_or_action_id_not_pending")),
        Ordering::Greater => Err(MutationError::new("approval_request_ambiguous")),
        Ordering::Equal => Ok(pending_refs.remove(0)),
    }
}

fn approval_already_resolved(
    all_events: &[serde_json::Value],
    run_id: &str,
    tool_id: &ToolId,
    approval_ref: &str,
) -> bool {
    all_events.iter().any(|event| {
        if event.get("event_type").and_then(|v| v.as_str()) == Some("approval_created")
            && event.get("run_id").and_then(|v| v.as_str()) == Some(run_id)
            && event.get("tool_id").and_then(|v| v.as_str()) == Some(tool_id.as_str())
            && event.get("approval_ref").and_then(|v| v.as_str()) == Some(approval_ref)
        {
            return true;
        }
        event.get("event_type").and_then(|v| v.as_str()) == Some("operator_action_completed")
            && event.get("action").and_then(|v| v.as_str()) == Some(OPERATOR_REFUSE_ACTION)
            && event.get("run_id").and_then(|v| v.as_str()) == Some(run_id)
            && event.get("target_id").and_then(|v| v.as_str()) == Some(tool_id.as_str())
            && event.get("artifact_ref").and_then(|v| v.as_str()) == Some(approval_ref)
    })
}
