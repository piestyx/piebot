use crate::runtime::artifacts::artifact_filename;
use crate::audit::{
    append_event, filter_events_for_run as filter_events_for_run_raw,
    read_audit_events as read_audit_events_raw, AuditEvent,
};
use crate::runtime::explain_args::{ExplainArgs, ExplainTarget};
use crate::capsule::run_capsule::{RunCapsule, RUN_CAPSULE_SCHEMA};
use pie_audit_log::AuditAppender;
use pie_common::{canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

pub const EXPLAIN_SCHEMA: &str = "serverd.explain.v1";

#[derive(Debug)]
pub struct ExplainError {
    reason: &'static str,
    detail: Option<String>,
}

impl ExplainError {
    pub fn new(reason: &'static str) -> Self {
        Self {
            reason,
            detail: None,
        }
    }

    pub fn with_detail(reason: &'static str, detail: String) -> Self {
        Self {
            reason,
            detail: Some(detail),
        }
    }

    pub fn reason(&self) -> &'static str {
        self.reason
    }

    #[allow(dead_code)]
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl std::fmt::Display for ExplainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for ExplainError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExplainArtifact {
    pub schema: String,
    pub capsule_ref: String,
    pub audit_head_hash: String,
    pub run_id: String,
    pub mode: String,
    pub summary: Vec<String>,
    pub findings: Vec<ExplainFinding>,
    pub actions: Vec<ExplainAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExplainFinding {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExplainAction {
    pub code: String,
    pub message: String,
    pub required: bool,
}

pub(crate) fn run_explain(args: ExplainArgs) -> Result<(), Box<dyn std::error::Error>> {
    let ExplainArgs {
        runtime_root,
        target,
    } = args;
    let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
    let capsule_ref_for_failure = match &target {
        ExplainTarget::CapsuleRef(capsule_ref) => Some(capsule_ref.clone()),
        ExplainTarget::RunId(_) => None,
    };
    let context = match resolve_explain_context(&runtime_root, &audit_path, &target) {
        Ok(context) => context,
        Err(err) => {
            if let Some(capsule_ref) = capsule_ref_for_failure {
                if let Ok(mut audit) = AuditAppender::open(&audit_path) {
                    let _ = append_event(
                        &mut audit,
                        AuditEvent::ExplainFailed {
                            capsule_ref,
                            reason: err.reason().to_string(),
                        },
                    );
                }
            }
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "ok": false,
                    "error": err.reason()
                }))?
            );
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, err.reason()).into());
        }
    };
    match run_explain_inner(&runtime_root, &context) {
        Ok((artifact, explain_ref)) => {
            let mut audit = AuditAppender::open(&audit_path).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "explain_write_failed")
            })?;
            append_event(
                &mut audit,
                AuditEvent::ExplainWritten {
                    explain_ref,
                    capsule_ref: artifact.capsule_ref.clone(),
                },
            )
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "explain_write_failed")
            })?;
            for line in &artifact.summary {
                println!("{}", line);
            }
            Ok(())
        }
        Err(err) => {
            if let Ok(mut audit) = AuditAppender::open(&audit_path) {
                let _ = append_event(
                    &mut audit,
                    AuditEvent::ExplainFailed {
                        capsule_ref: context.capsule_ref.clone(),
                        reason: err.reason().to_string(),
                    },
                );
            }
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "ok": false,
                    "error": err.reason()
                }))?
            );
            Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, err.reason()).into())
        }
    }
}

fn run_explain_inner(
    runtime_root: &Path,
    context: &ExplainContext,
) -> Result<(ExplainArtifact, String), ExplainError> {
    let artifact = build_explain(&context.capsule_ref, &context.capsule, &context.run_events)?;
    let explain_ref = write_explain(runtime_root, &artifact)?;
    Ok((artifact, explain_ref))
}

fn read_capsule(runtime_root: &Path, capsule_ref: &str) -> Result<RunCapsule, ExplainError> {
    if !capsule_ref.starts_with("sha256:") {
        return Err(ExplainError::new("explain_input_invalid"));
    }
    let path = runtime_root
        .join("artifacts")
        .join("run_capsules")
        .join(artifact_filename(capsule_ref));
    let bytes = fs::read(&path)
        .map_err(|e| ExplainError::with_detail("explain_input_invalid", e.to_string()))?;
    let capsule: RunCapsule =
        serde_json::from_slice(&bytes).map_err(|_| ExplainError::new("explain_input_invalid"))?;
    if capsule.schema != RUN_CAPSULE_SCHEMA {
        return Err(ExplainError::new("explain_input_invalid"));
    }
    Ok(capsule)
}

fn read_audit_events(audit_path: &Path) -> Result<Vec<serde_json::Value>, ExplainError> {
    if !audit_path.exists() {
        return Err(ExplainError::new("explain_input_invalid"));
    }
    read_audit_events_raw(audit_path).map_err(|_| ExplainError::new("explain_input_invalid"))
}

fn filter_events_for_run(
    events: &[serde_json::Value],
    run_id: &str,
) -> Result<Vec<serde_json::Value>, ExplainError> {
    filter_events_for_run_raw(events, run_id)
        .map_err(|_| ExplainError::new("explain_input_invalid"))
}

struct ExplainContext {
    capsule_ref: String,
    capsule: RunCapsule,
    run_events: Vec<serde_json::Value>,
}

fn resolve_explain_context(
    runtime_root: &Path,
    audit_path: &Path,
    target: &ExplainTarget,
) -> Result<ExplainContext, ExplainError> {
    let events = read_audit_events(audit_path)?;
    match target {
        ExplainTarget::CapsuleRef(capsule_ref) => {
            let capsule = read_capsule(runtime_root, capsule_ref)?;
            let run_events = filter_events_for_run(&events, &capsule.run.run_id)?;
            Ok(ExplainContext {
                capsule_ref: capsule_ref.clone(),
                capsule,
                run_events,
            })
        }
        ExplainTarget::RunId(run_id) => {
            let run_events = filter_events_for_run(&events, run_id)?;
            let capsule_ref = resolve_capsule_ref_from_run_events(&run_events)?;
            let capsule = read_capsule(runtime_root, &capsule_ref)?;
            if capsule.run.run_id != *run_id {
                return Err(ExplainError::new("explain_input_invalid"));
            }
            Ok(ExplainContext {
                capsule_ref,
                capsule,
                run_events,
            })
        }
    }
}

fn resolve_capsule_ref_from_run_events(
    run_events: &[serde_json::Value],
) -> Result<String, ExplainError> {
    let mut found: Option<String> = None;
    for event in run_events {
        let event_type = event
            .get("event_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ExplainError::new("explain_input_invalid"))?;
        if event_type != "run_capsule_written" {
            continue;
        }
        let capsule_ref = get_str(event, "capsule_ref")?;
        if found.is_some() {
            return Err(ExplainError::new("explain_input_invalid"));
        }
        found = Some(capsule_ref);
    }
    found.ok_or_else(|| ExplainError::new("explain_input_invalid"))
}

fn build_explain(
    capsule_ref: &str,
    capsule: &RunCapsule,
    audit_events: &[serde_json::Value],
) -> Result<ExplainArtifact, ExplainError> {
    let mut request_refs: BTreeMap<String, String> = BTreeMap::new();
    let mut response_refs: BTreeMap<String, String> = BTreeMap::new();

    let mut route_selected = Vec::new();
    let mut tool_executed = Vec::new();
    let mut tool_denied = Vec::new();
    let mut tool_approval = Vec::new();
    let mut output_rejected = Vec::new();

    for event in audit_events {
        let event_type = event
            .get("event_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ExplainError::new("explain_input_invalid"))?;
        match event_type {
            "route_selected" => {
                let provider_id = get_str(event, "provider_id")?;
                let reason = get_str(event, "reason")?;
                let request_hash = get_str(event, "request_hash")?;
                route_selected.push((provider_id, reason, request_hash));
            }
            "provider_request_written" => {
                let request_hash = get_str(event, "request_hash")?;
                let artifact_ref = get_str(event, "artifact_ref")?;
                request_refs.insert(request_hash, artifact_ref);
            }
            "provider_response_written" => {
                let request_hash = get_str(event, "request_hash")?;
                let artifact_ref = get_str(event, "artifact_ref")?;
                response_refs.insert(request_hash, artifact_ref);
            }
            "tool_executed" => {
                let tool_id = get_str(event, "tool_id")?;
                let input_ref = get_str(event, "input_ref")?;
                let output_ref = get_str(event, "output_ref")?;
                let request_hash = get_str(event, "request_hash")?;
                tool_executed.push((tool_id, input_ref, output_ref, request_hash));
            }
            "tool_execution_denied" => {
                let tool_id = get_str(event, "tool_id")?;
                let reason = get_str(event, "reason")?;
                let request_hash = get_str(event, "request_hash")?;
                tool_denied.push((tool_id, reason, request_hash));
            }
            "tool_approval_required" => {
                let tool_id = get_str(event, "tool_id")?;
                let approval_ref = get_str(event, "approval_ref")?;
                let request_hash = get_str(event, "request_hash")?;
                tool_approval.push((tool_id, approval_ref, request_hash));
            }
            "provider_output_rejected" => {
                let reason = get_str(event, "reason")?;
                let request_hash = get_str(event, "request_hash")?;
                output_rejected.push((reason, request_hash));
            }
            _ => {}
        }
    }

    let mut findings = Vec::new();
    let mut actions = Vec::new();

    for (provider_id, reason, request_hash) in route_selected {
        let mut related_refs = vec![capsule_ref.to_string()];
        let mut related_hashes = vec![request_hash.clone()];
        if let Some(req) = request_refs.get(&request_hash) {
            related_refs.push(req.clone());
        }
        if let Some(resp) = response_refs.get(&request_hash) {
            related_refs.push(resp.clone());
        }
        normalize_refs(&mut related_refs);
        normalize_refs(&mut related_hashes);
        findings.push(ExplainFinding {
            code: "provider_selected".to_string(),
            message: format!("provider selected: {} ({})", provider_id, reason),
            related_refs,
            related_hashes,
        });
    }

    for (tool_id, input_ref, output_ref, request_hash) in tool_executed {
        let mut related_refs = vec![input_ref, output_ref, capsule_ref.to_string()];
        let mut related_hashes = vec![request_hash];
        normalize_refs(&mut related_refs);
        normalize_refs(&mut related_hashes);
        findings.push(ExplainFinding {
            code: "tool_executed".to_string(),
            message: format!("tool executed: {}", tool_id),
            related_refs,
            related_hashes,
        });
    }

    for (tool_id, reason, request_hash) in tool_denied {
        let mut related_refs = vec![capsule_ref.to_string()];
        let mut related_hashes = vec![request_hash];
        normalize_refs(&mut related_refs);
        normalize_refs(&mut related_hashes);
        findings.push(ExplainFinding {
            code: "tool_denied".to_string(),
            message: format!("tool denied: {} ({})", tool_id, reason),
            related_refs,
            related_hashes,
        });
        match reason.as_str() {
            "tools_disabled" => actions.push(ExplainAction {
                code: "enable_tools".to_string(),
                message: "set TOOLS_ENABLE=1".to_string(),
                required: true,
            }),
            "tool_requires_arming" => actions.push(ExplainAction {
                code: "arm_tools".to_string(),
                message: "set TOOLS_ARM=1".to_string(),
                required: true,
            }),
            "tool_not_allowed" => actions.push(ExplainAction {
                code: "update_tool_policy".to_string(),
                message: "allow tool in policy".to_string(),
                required: true,
            }),
            "skill_tool_not_allowed" => actions.push(ExplainAction {
                code: "update_skill_allowed_tools".to_string(),
                message: "allow tool in skill manifest".to_string(),
                required: true,
            }),
            _ => {}
        }
    }

    for (tool_id, approval_ref, request_hash) in tool_approval {
        let mut related_refs = vec![approval_ref, capsule_ref.to_string()];
        let mut related_hashes = vec![request_hash];
        normalize_refs(&mut related_refs);
        normalize_refs(&mut related_hashes);
        findings.push(ExplainFinding {
            code: "tool_approval_required".to_string(),
            message: format!("tool approval required: {}", tool_id),
            related_refs,
            related_hashes,
        });
        actions.push(ExplainAction {
            code: "add_tool_approval".to_string(),
            message: "add tool approval artifact".to_string(),
            required: true,
        });
    }

    if !output_rejected.is_empty() {
        for (reason, request_hash) in output_rejected {
            let mut related_refs = vec![capsule_ref.to_string()];
            let mut related_hashes = vec![request_hash];
            normalize_refs(&mut related_refs);
            normalize_refs(&mut related_hashes);
            findings.push(ExplainFinding {
                code: "provider_output_rejected".to_string(),
                message: format!("provider output rejected: {}", reason),
                related_refs,
                related_hashes,
            });
        }
        actions.push(ExplainAction {
            code: "fix_output_contract".to_string(),
            message: "fix output contract to accept provider output".to_string(),
            required: true,
        });
        actions.push(ExplainAction {
            code: "update_skill_output_contract".to_string(),
            message: "update skill output_contract reference".to_string(),
            required: true,
        });
    }

    let mut summary = Vec::new();
    summary.push(format!("capsule_ref: {}", capsule_ref));
    summary.push(format!("run_id: {}", capsule.run.run_id));
    summary.push(format!("mode: {}", capsule.run.mode));

    sort_findings(&mut findings);
    sort_actions(&mut actions);

    Ok(ExplainArtifact {
        schema: EXPLAIN_SCHEMA.to_string(),
        capsule_ref: capsule_ref.to_string(),
        audit_head_hash: capsule.audit.audit_head_hash.clone(),
        run_id: capsule.run.run_id.clone(),
        mode: capsule.run.mode.clone(),
        summary,
        findings,
        actions,
    })
}

fn sort_findings(findings: &mut Vec<ExplainFinding>) {
    for finding in findings.iter_mut() {
        normalize_refs(&mut finding.related_refs);
        normalize_refs(&mut finding.related_hashes);
    }
    findings.sort_by(|a, b| {
        (
            a.code.as_str(),
            a.message.as_str(),
            &a.related_refs,
            &a.related_hashes,
        )
            .cmp(&(
                b.code.as_str(),
                b.message.as_str(),
                &b.related_refs,
                &b.related_hashes,
            ))
    });
    findings.dedup();
}

fn sort_actions(actions: &mut Vec<ExplainAction>) {
    actions.sort_by(|a, b| {
        (a.code.as_str(), a.message.as_str(), a.required).cmp(&(
            b.code.as_str(),
            b.message.as_str(),
            b.required,
        ))
    });
    actions.dedup();
}

fn normalize_refs(refs: &mut Vec<String>) {
    refs.sort();
    refs.dedup();
}

fn get_str(event: &serde_json::Value, field: &str) -> Result<String, ExplainError> {
    event
        .get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| ExplainError::new("explain_input_invalid"))
}

fn write_explain(runtime_root: &Path, explain: &ExplainArtifact) -> Result<String, ExplainError> {
    let value =
        serde_json::to_value(explain).map_err(|_| ExplainError::new("explain_build_failed"))?;
    let bytes =
        canonical_json_bytes(&value).map_err(|_| ExplainError::new("explain_build_failed"))?;
    let explain_ref = sha256_bytes(&bytes);
    let dir = runtime_root.join("artifacts").join("explains");
    fs::create_dir_all(&dir)
        .map_err(|e| ExplainError::with_detail("explain_write_failed", e.to_string()))?;
    let filename = artifact_filename(&explain_ref);
    let path = dir.join(&filename);
    if path.exists() {
        let existing = fs::read(&path)
            .map_err(|e| ExplainError::with_detail("explain_write_failed", e.to_string()))?;
        if existing != bytes {
            return Err(ExplainError::new("explain_write_failed"));
        }
        return Ok(explain_ref);
    }
    let tmp_path = dir.join(format!("{}.tmp", filename));
    let mut file = fs::File::create(&tmp_path)
        .map_err(|e| ExplainError::with_detail("explain_write_failed", e.to_string()))?;
    file.write_all(&bytes)
        .map_err(|e| ExplainError::with_detail("explain_write_failed", e.to_string()))?;
    file.sync_all()
        .map_err(|e| ExplainError::with_detail("explain_write_failed", e.to_string()))?;
    if let Err(e) = fs::rename(&tmp_path, &path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(ExplainError::with_detail(
            "explain_write_failed",
            e.to_string(),
        ));
    }
    Ok(explain_ref)
}
