use crate::audit::{append_event, filter_events_for_run, succeed_run, AuditEvent};
use crate::mutations::{
    ensure_runtime_root, map_audit_read_error, open_audit, read_audit_events_checked, MutationError,
};
use pie_audit_log::AuditAppender;
use pie_common::{canonical_json_bytes, sha256_bytes};
use std::path::{Path, PathBuf};

pub(crate) const OPERATOR_APPROVE_ACTION: &str = "operator_approve";
pub(crate) const OPERATOR_LEARNINGS_APPEND_ACTION: &str = "operator_learnings_append";
pub(crate) const OPERATOR_REPLAY_VERIFY_ACTION: &str = "operator_replay_verify";
pub(crate) const OPERATOR_CAPSULE_EXPORT_ACTION: &str = "operator_capsule_export";
pub(crate) const MAX_OPERATOR_REASON_BYTES: usize = 512;

#[derive(Debug, Clone, Default)]
pub(crate) struct OperatorActionTarget {
    pub(crate) run_id: Option<String>,
    pub(crate) target_id: Option<String>,
    pub(crate) target_ref: Option<String>,
}

pub(crate) fn prepare_operator_audit(
    runtime_root: &Path,
) -> Result<(AuditAppender, PathBuf), MutationError> {
    ensure_runtime_root(runtime_root)?;
    open_audit(runtime_root)
}

pub(crate) fn read_run_events_for_run_id(
    runtime_root: &Path,
    run_id: &str,
) -> Result<Vec<serde_json::Value>, MutationError> {
    let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
    let events = read_audit_events_checked(&audit_path)?;
    let run_exists = events.iter().any(|event| {
        event.get("event_type").and_then(|v| v.as_str()) == Some("run_started")
            && event.get("run_id").and_then(|v| v.as_str()) == Some(run_id)
    });
    if !run_exists {
        return Err(MutationError::new("run_id_unknown"));
    }
    filter_events_for_run(&events, run_id).map_err(map_audit_read_error)
}

pub(crate) fn normalize_and_hash_reason(reason: &str) -> Result<String, MutationError> {
    let normalized = normalize_reason(reason);
    if normalized.is_empty() {
        return Err(MutationError::new("operator_reason_empty"));
    }
    if normalized.as_bytes().len() > MAX_OPERATOR_REASON_BYTES {
        return Err(MutationError::new("operator_reason_too_large"));
    }
    let value = serde_json::json!({
        "reason": normalized
    });
    let bytes =
        canonical_json_bytes(&value).map_err(|_| MutationError::new("operator_reason_invalid"))?;
    Ok(sha256_bytes(&bytes))
}

pub(crate) fn emit_requested(
    audit: &mut AuditAppender,
    action: &str,
    target: &OperatorActionTarget,
    reason_hash: Option<String>,
) -> Result<(), MutationError> {
    append_event(
        audit,
        AuditEvent::OperatorActionRequested {
            action: action.to_string(),
            run_id: target.run_id.clone(),
            target_id: target.target_id.clone(),
            target_ref: target.target_ref.clone(),
            reason_hash,
        },
    )
    .map(|_| ())
    .map_err(|e| MutationError::with_detail("operator_audit_failed", e.to_string()))
}

pub(crate) fn emit_completed(
    audit: &mut AuditAppender,
    action: &str,
    target: &OperatorActionTarget,
    artifact_ref: Option<String>,
    artifact_hash: Option<String>,
) -> Result<(), MutationError> {
    append_event(
        audit,
        AuditEvent::OperatorActionCompleted {
            action: action.to_string(),
            run_id: target.run_id.clone(),
            target_id: target.target_id.clone(),
            target_ref: target.target_ref.clone(),
            artifact_ref,
            artifact_hash,
        },
    )
    .map(|_| ())
    .map_err(|e| MutationError::with_detail("operator_audit_failed", e.to_string()))
}

pub(crate) fn emit_refused_and_error(
    audit: &mut AuditAppender,
    audit_path: &Path,
    action: &str,
    target: &OperatorActionTarget,
    reason: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    if append_event(
        audit,
        AuditEvent::OperatorActionRefused {
            action: action.to_string(),
            reason: reason.to_string(),
            run_id: target.run_id.clone(),
            target_id: target.target_id.clone(),
            target_ref: target.target_ref.clone(),
        },
    )
    .is_err()
    {
        return emit_error("operator_audit_failed");
    }
    let mut payload = serde_json::Map::new();
    payload.insert("ok".to_string(), serde_json::Value::Bool(false));
    payload.insert(
        "action".to_string(),
        serde_json::Value::String(action.to_string()),
    );
    payload.insert(
        "error".to_string(),
        serde_json::Value::String(reason.to_string()),
    );
    payload.insert(
        "audit_hash".to_string(),
        serde_json::Value::String(audit.last_hash().to_string()),
    );
    if let Some(run_id) = target.run_id.as_ref() {
        payload.insert(
            "run_id".to_string(),
            serde_json::Value::String(run_id.clone()),
        );
    }
    if let Some(target_id) = target.target_id.as_ref() {
        payload.insert(
            "target_id".to_string(),
            serde_json::Value::String(target_id.clone()),
        );
    }
    if let Some(target_ref) = target.target_ref.as_ref() {
        payload.insert(
            "target_ref".to_string(),
            serde_json::Value::String(target_ref.clone()),
        );
    }
    let _ = succeed_run(audit, audit_path, serde_json::Value::Object(payload), false);
    Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, reason).into())
}

pub(crate) fn emit_error(reason: &'static str) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "ok": false,
            "error": reason
        }))?
    );
    Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, reason).into())
}

fn normalize_reason(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut prev_was_cr = false;
    for ch in value.chars() {
        if ch == '\r' {
            out.push('\n');
            prev_was_cr = true;
            continue;
        }
        if prev_was_cr {
            prev_was_cr = false;
            if ch == '\n' {
                continue;
            }
        }
        out.push(ch);
    }
    out.trim().to_string()
}
