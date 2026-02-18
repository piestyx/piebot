use crate::audit::{
    append_event, filter_events_for_run, read_audit_events as read_audit_events_raw, succeed_run,
    AuditEvent, AuditReadError,
};
use crate::command::{ApproveArgs, CapsuleExportArgs, LearnArgs};
use crate::runtime::artifacts::{artifact_filename, is_sha256_ref};
use crate::tools::policy::{TOOL_APPROVAL_REQUEST_SCHEMA, TOOL_APPROVAL_SCHEMA};
use crate::tools::ToolId;
use pie_audit_log::AuditAppender;
use pie_common::{canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const LEARNING_ENTRY_SCHEMA: &str = "serverd.learning_entry.v1";
pub(crate) const MAX_LEARNING_BYTES: usize = 4096;

#[derive(Debug)]
pub(crate) struct MutationError {
    reason: &'static str,
    detail: Option<String>,
}

impl MutationError {
    pub(crate) fn new(reason: &'static str) -> Self {
        Self {
            reason,
            detail: None,
        }
    }

    pub(crate) fn with_detail(reason: &'static str, detail: String) -> Self {
        Self {
            reason,
            detail: Some(detail),
        }
    }

    pub(crate) fn reason(&self) -> &'static str {
        self.reason
    }
}

impl std::fmt::Display for MutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.detail.as_ref() {
            Some(detail) => write!(f, "{}: {}", self.reason, detail),
            None => write!(f, "{}", self.reason),
        }
    }
}

impl std::error::Error for MutationError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct ToolApprovalRequest {
    pub(crate) schema: String,
    pub(crate) tool_id: String,
    pub(crate) request_hash: String,
    pub(crate) input_ref: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct ToolApproval {
    schema: String,
    approval_ref: String,
    tool_id: String,
    request_hash: String,
    input_ref: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct LearningEntry {
    schema: String,
    text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
}

#[derive(Debug)]
pub(crate) struct ApprovalMatch {
    pub(crate) approval_ref: String,
    pub(crate) request_hash: String,
}

pub(crate) fn run_approve(args: ApproveArgs) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(err) = ensure_runtime_root(&args.runtime_root) {
        return emit_error(err.reason());
    }
    let tool_id = match ToolId::parse(&args.tool_id) {
        Ok(id) => id,
        Err(_) => return emit_error("tool_id_invalid"),
    };
    if !is_sha256_ref(&args.input_ref) {
        return emit_error("input_ref_invalid");
    }
    let approval_match = match find_approval_request(&args.runtime_root, &tool_id, &args.input_ref)
    {
        Ok(value) => value,
        Err(err) => return emit_error(err.reason()),
    };
    if !is_sha256_ref(&approval_match.request_hash) {
        return emit_error("approval_request_invalid");
    }
    if let Err(err) = write_approval_file(
        &args.runtime_root,
        &approval_match.approval_ref,
        &tool_id,
        &approval_match.request_hash,
        &args.input_ref,
    ) {
        return emit_error(err.reason());
    }
    let (mut audit, audit_path) = match open_audit(&args.runtime_root) {
        Ok(value) => value,
        Err(err) => return emit_error(err.reason()),
    };
    if append_event(
        &mut audit,
        AuditEvent::ApprovalCreated {
            tool_id: tool_id.as_str().to_string(),
            approval_ref: approval_match.approval_ref.clone(),
            input_ref: args.input_ref.clone(),
            request_hash: approval_match.request_hash.clone(),
            run_id: args.run_id.clone(),
        },
    )
    .is_err()
    {
        return emit_error("approval_audit_failed");
    }
    let audit_hash = audit.last_hash().to_string();
    let mut payload = serde_json::Map::new();
    payload.insert("ok".to_string(), serde_json::Value::Bool(true));
    payload.insert(
        "approval_ref".to_string(),
        serde_json::Value::String(approval_match.approval_ref),
    );
    if let Some(run_id) = args.run_id {
        payload.insert("run_id".to_string(), serde_json::Value::String(run_id));
    }
    payload.insert(
        "audit_hash".to_string(),
        serde_json::Value::String(audit_hash),
    );
    succeed_run(
        &mut audit,
        &audit_path,
        serde_json::Value::Object(payload),
        false,
    )
}

pub(crate) fn run_learn(args: LearnArgs) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(err) = ensure_runtime_root(&args.runtime_root) {
        return emit_error(err.reason());
    }
    let text = normalize_line_endings(&args.text);
    if text.trim().is_empty() {
        return emit_error("learning_text_empty");
    }
    if text.as_bytes().len() > MAX_LEARNING_BYTES {
        return emit_error("learning_text_too_large");
    }
    let tags = match parse_tags(args.tags.as_deref()) {
        Ok(tags) => tags,
        Err(err) => return emit_error(err.reason()),
    };
    let source = args
        .source
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let entry = LearningEntry {
        schema: LEARNING_ENTRY_SCHEMA.to_string(),
        text,
        tags,
        source,
    };
    let value = match serde_json::to_value(&entry) {
        Ok(value) => value,
        Err(_) => return emit_error("learning_entry_invalid"),
    };
    let bytes = match canonical_json_bytes(&value) {
        Ok(bytes) => bytes,
        Err(_) => return emit_error("learning_entry_invalid"),
    };
    let entry_hash = sha256_bytes(&bytes);
    let bytes_written = bytes.len() as u64 + 1;
    if let Err(err) = append_learning(&args.runtime_root, &bytes) {
        return emit_error(err.reason());
    }
    let (mut audit, audit_path) = match open_audit(&args.runtime_root) {
        Ok(value) => value,
        Err(err) => return emit_error(err.reason()),
    };
    if append_event(
        &mut audit,
        AuditEvent::LearningAppended {
            entry_hash: entry_hash.clone(),
            bytes_written,
        },
    )
    .is_err()
    {
        return emit_error("learning_audit_failed");
    }
    let audit_hash = audit.last_hash().to_string();
    let mut payload = serde_json::Map::new();
    payload.insert("ok".to_string(), serde_json::Value::Bool(true));
    payload.insert(
        "entry_hash".to_string(),
        serde_json::Value::String(entry_hash),
    );
    payload.insert(
        "bytes_written".to_string(),
        serde_json::Value::Number(serde_json::Number::from(bytes_written)),
    );
    payload.insert(
        "audit_hash".to_string(),
        serde_json::Value::String(audit_hash),
    );
    succeed_run(
        &mut audit,
        &audit_path,
        serde_json::Value::Object(payload),
        false,
    )
}

pub(crate) fn run_capsule_export(
    args: CapsuleExportArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(err) = ensure_runtime_root(&args.runtime_root) {
        return emit_error(err.reason());
    }
    if !is_sha256_ref(&args.run_id) {
        return emit_error("run_id_invalid");
    }
    let audit_path = args.runtime_root.join("logs").join("audit_rust.jsonl");
    let events = match read_audit_events_checked(&audit_path) {
        Ok(events) => events,
        Err(err) => return emit_error(err.reason()),
    };
    let run_events = match filter_events_for_run(&events, &args.run_id) {
        Ok(events) => events,
        Err(err) => return emit_error(map_audit_read_error(err).reason()),
    };
    let capsule_ref = match resolve_capsule_ref(&run_events) {
        Ok(value) => value,
        Err(err) => return emit_error(err.reason()),
    };
    let capsule_bytes = match read_capsule_bytes(&args.runtime_root, &capsule_ref) {
        Ok(bytes) => bytes,
        Err(err) => return emit_error(err.reason()),
    };
    let (export_path, export_rel) =
        match resolve_export_path(&args.runtime_root, &capsule_ref, args.out.as_ref()) {
            Ok(value) => value,
            Err(err) => return emit_error(err.reason()),
        };
    if let Err(err) = write_export_file(&export_path, &capsule_bytes) {
        return emit_error(err.reason());
    }
    let export_hash = sha256_bytes(&capsule_bytes);
    let (mut audit, audit_path) = match open_audit(&args.runtime_root) {
        Ok(value) => value,
        Err(err) => return emit_error(err.reason()),
    };
    let export_rel_for_event = export_rel.clone();
    if append_event(
        &mut audit,
        AuditEvent::CapsuleExported {
            capsule_ref: capsule_ref.clone(),
            export_hash: export_hash.clone(),
            export_path: export_rel_for_event,
        },
    )
    .is_err()
    {
        return emit_error("capsule_export_audit_failed");
    }
    let audit_hash = audit.last_hash().to_string();
    let mut payload = serde_json::Map::new();
    payload.insert("ok".to_string(), serde_json::Value::Bool(true));
    payload.insert(
        "capsule_ref".to_string(),
        serde_json::Value::String(capsule_ref),
    );
    payload.insert(
        "export_hash".to_string(),
        serde_json::Value::String(export_hash),
    );
    payload.insert(
        "export_path".to_string(),
        serde_json::Value::String(export_rel),
    );
    payload.insert(
        "audit_hash".to_string(),
        serde_json::Value::String(audit_hash),
    );
    succeed_run(
        &mut audit,
        &audit_path,
        serde_json::Value::Object(payload),
        false,
    )
}

pub(crate) fn ensure_runtime_root(path: &Path) -> Result<(), MutationError> {
    if !path.exists() {
        return Err(MutationError::new("runtime_root_missing"));
    }
    if !path.is_dir() {
        return Err(MutationError::new("runtime_root_invalid"));
    }
    Ok(())
}

pub(crate) fn open_audit(runtime_root: &Path) -> Result<(AuditAppender, PathBuf), MutationError> {
    let dir = runtime_root.join("logs");
    fs::create_dir_all(&dir)
        .map_err(|e| MutationError::with_detail("audit_open_failed", e.to_string()))?;
    let path = dir.join("audit_rust.jsonl");
    let audit = AuditAppender::open(&path)
        .map_err(|e| MutationError::with_detail("audit_open_failed", e.to_string()))?;
    Ok((audit, path))
}

fn emit_error(reason: &'static str) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({ "ok": false, "error": reason }))?
    );
    Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, reason).into())
}

pub(crate) fn find_approval_request(
    runtime_root: &Path,
    tool_id: &ToolId,
    input_ref: &str,
) -> Result<ApprovalMatch, MutationError> {
    let dir = runtime_root.join("artifacts").join("approvals");
    if !dir.is_dir() {
        return Err(MutationError::new("approval_request_missing"));
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(&dir)
        .map_err(|e| MutationError::with_detail("approval_request_invalid", e.to_string()))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    entries.sort_by(|a, b| path_name(a).cmp(&path_name(b)));
    let mut matches = Vec::new();
    for path in entries {
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(&path)
            .map_err(|e| MutationError::with_detail("approval_request_invalid", e.to_string()))?;
        let request: ToolApprovalRequest = serde_json::from_slice(&bytes)
            .map_err(|_| MutationError::new("approval_request_invalid"))?;
        if request.schema != TOOL_APPROVAL_REQUEST_SCHEMA {
            return Err(MutationError::new("approval_request_invalid"));
        }
        if request.tool_id != tool_id.as_str() || request.input_ref != input_ref {
            continue;
        }
        if !is_sha256_ref(&request.request_hash) {
            return Err(MutationError::new("approval_request_invalid"));
        }
        let value = serde_json::to_value(&request)
            .map_err(|_| MutationError::new("approval_request_invalid"))?;
        let canon = canonical_json_bytes(&value)
            .map_err(|_| MutationError::new("approval_request_invalid"))?;
        let approval_ref = sha256_bytes(&canon);
        if !path_matches_ref(&path, &approval_ref) {
            return Err(MutationError::new("approval_request_invalid"));
        }
        matches.push(ApprovalMatch {
            approval_ref,
            request_hash: request.request_hash.clone(),
        });
    }
    match matches.len().cmp(&1) {
        Ordering::Equal => Ok(matches.remove(0)),
        Ordering::Less => Err(MutationError::new("approval_request_missing")),
        Ordering::Greater => Err(MutationError::new("approval_request_ambiguous")),
    }
}

pub(crate) fn write_approval_file(
    runtime_root: &Path,
    approval_ref: &str,
    tool_id: &ToolId,
    request_hash: &str,
    input_ref: &str,
) -> Result<(), MutationError> {
    let approval = ToolApproval {
        schema: TOOL_APPROVAL_SCHEMA.to_string(),
        approval_ref: approval_ref.to_string(),
        tool_id: tool_id.as_str().to_string(),
        request_hash: request_hash.to_string(),
        input_ref: input_ref.to_string(),
    };
    let value =
        serde_json::to_value(&approval).map_err(|_| MutationError::new("approval_write_failed"))?;
    let bytes =
        canonical_json_bytes(&value).map_err(|_| MutationError::new("approval_write_failed"))?;
    let dir = runtime_root.join("approvals");
    fs::create_dir_all(&dir)
        .map_err(|e| MutationError::with_detail("approval_write_failed", e.to_string()))?;
    let filename = approval_filename(approval_ref);
    let path = dir.join(&filename);
    if path.exists() {
        let existing = fs::read(&path)
            .map_err(|e| MutationError::with_detail("approval_write_failed", e.to_string()))?;
        if existing != bytes {
            return Err(MutationError::new("approval_write_conflict"));
        }
        return Ok(());
    }
    let tmp_path = dir.join(format!("{}.tmp", filename));
    let mut file = fs::File::create(&tmp_path)
        .map_err(|e| MutationError::with_detail("approval_write_failed", e.to_string()))?;
    file.write_all(&bytes)
        .map_err(|e| MutationError::with_detail("approval_write_failed", e.to_string()))?;
    file.sync_all()
        .map_err(|e| MutationError::with_detail("approval_write_failed", e.to_string()))?;
    if let Err(e) = fs::rename(&tmp_path, &path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(MutationError::with_detail(
            "approval_write_failed",
            e.to_string(),
        ));
    }
    Ok(())
}

fn approval_filename(approval_ref: &str) -> String {
    let trimmed = approval_ref.strip_prefix("sha256:").unwrap_or(approval_ref);
    format!("{}.approved.json", trimmed)
}

pub(crate) fn append_learning(runtime_root: &Path, bytes: &[u8]) -> Result<(), MutationError> {
    let dir = runtime_root.join("learnings");
    fs::create_dir_all(&dir)
        .map_err(|e| MutationError::with_detail("learning_write_failed", e.to_string()))?;
    let path = dir.join("learnings.jsonl");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| MutationError::with_detail("learning_write_failed", e.to_string()))?;
    file.write_all(bytes)
        .map_err(|e| MutationError::with_detail("learning_write_failed", e.to_string()))?;
    file.write_all(b"\n")
        .map_err(|e| MutationError::with_detail("learning_write_failed", e.to_string()))?;
    Ok(())
}

pub(crate) fn map_audit_read_error(err: AuditReadError) -> MutationError {
    match err.detail() {
        Some(detail) => MutationError::with_detail(err.reason(), detail.to_string()),
        None => MutationError::new(err.reason()),
    }
}

pub(crate) fn normalize_line_endings(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_was_cr = false;
    for ch in input.chars() {
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
    out
}

pub(crate) fn parse_tags(raw: Option<&str>) -> Result<Vec<String>, MutationError> {
    let raw = match raw {
        Some(value) => value,
        None => return Ok(Vec::new()),
    };
    let mut tags = Vec::new();
    for tag in raw.split(',') {
        let trimmed = tag.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !is_safe_tag_token(trimmed) {
            return Err(MutationError::new("learning_tags_invalid"));
        }
        tags.push(trimmed.to_string());
    }
    tags.sort();
    tags.dedup();
    Ok(tags)
}

pub(crate) fn is_safe_tag_token(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

pub(crate) fn read_audit_events_checked(
    audit_path: &Path,
) -> Result<Vec<serde_json::Value>, MutationError> {
    if !audit_path.exists() {
        return Err(MutationError::new("audit_log_missing"));
    }
    read_audit_events_raw(audit_path).map_err(map_audit_read_error)
}

pub(crate) fn resolve_capsule_ref(
    run_events: &[serde_json::Value],
) -> Result<String, MutationError> {
    let mut found: Option<String> = None;
    for event in run_events {
        let event_type = event
            .get("event_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MutationError::new("audit_log_invalid"))?;
        if event_type != "run_capsule_written" {
            continue;
        }
        let capsule_ref = get_str(event, "capsule_ref")?;
        if found.is_some() {
            return Err(MutationError::new("audit_log_invalid"));
        }
        found = Some(capsule_ref);
    }
    found.ok_or_else(|| MutationError::new("audit_log_invalid"))
}

pub(crate) fn read_capsule_bytes(
    runtime_root: &Path,
    capsule_ref: &str,
) -> Result<Vec<u8>, MutationError> {
    if !is_sha256_ref(capsule_ref) {
        return Err(MutationError::new("capsule_ref_invalid"));
    }
    let path = runtime_root
        .join("artifacts")
        .join("run_capsules")
        .join(artifact_filename(capsule_ref));
    fs::read(&path).map_err(|e| MutationError::with_detail("capsule_read_failed", e.to_string()))
}

pub(crate) fn resolve_export_path(
    runtime_root: &Path,
    capsule_ref: &str,
    out: Option<&PathBuf>,
) -> Result<(PathBuf, String), MutationError> {
    let base = runtime_root.join("exports");
    fs::create_dir_all(&base)
        .map_err(|e| MutationError::with_detail("export_path_invalid", e.to_string()))?;
    let trimmed = capsule_ref.strip_prefix("sha256:").unwrap_or(capsule_ref);
    let default_name = PathBuf::from(format!("capsule_{}.json", trimmed));
    let requested = out.cloned().unwrap_or(default_name);
    if requested.as_os_str().is_empty() {
        return Err(MutationError::new("export_path_invalid"));
    }
    let candidate = if requested.is_absolute() {
        if !requested.starts_with(&base) {
            return Err(MutationError::new("export_path_invalid"));
        }
        requested.clone()
    } else {
        if requested
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(MutationError::new("export_path_invalid"));
        }
        base.join(&requested)
    };
    if let Some(parent) = candidate.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| MutationError::with_detail("export_path_invalid", e.to_string()))?;
        let base_canon = fs::canonicalize(&base)
            .map_err(|e| MutationError::with_detail("export_path_invalid", e.to_string()))?;
        let parent_canon = fs::canonicalize(parent)
            .map_err(|e| MutationError::with_detail("export_path_invalid", e.to_string()))?;
        if !parent_canon.starts_with(&base_canon) {
            return Err(MutationError::new("export_path_invalid"));
        }
    }
    let rel_path = candidate
        .strip_prefix(runtime_root)
        .unwrap_or(&candidate)
        .to_string_lossy()
        .to_string();
    Ok((candidate, rel_path))
}

pub(crate) fn write_export_file(path: &Path, bytes: &[u8]) -> Result<(), MutationError> {
    if path.exists() {
        let existing = fs::read(path)
            .map_err(|e| MutationError::with_detail("capsule_export_failed", e.to_string()))?;
        if existing != bytes {
            return Err(MutationError::new("capsule_export_conflict"));
        }
        return Ok(());
    }
    let dir = path
        .parent()
        .ok_or_else(|| MutationError::new("capsule_export_failed"))?;
    let filename = path
        .file_name()
        .ok_or_else(|| MutationError::new("capsule_export_failed"))?
        .to_string_lossy()
        .to_string();
    let tmp_path = dir.join(format!("{}.tmp", filename));
    let mut file = fs::File::create(&tmp_path)
        .map_err(|e| MutationError::with_detail("capsule_export_failed", e.to_string()))?;
    file.write_all(bytes)
        .map_err(|e| MutationError::with_detail("capsule_export_failed", e.to_string()))?;
    file.sync_all()
        .map_err(|e| MutationError::with_detail("capsule_export_failed", e.to_string()))?;
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(MutationError::with_detail(
            "capsule_export_failed",
            e.to_string(),
        ));
    }
    Ok(())
}

fn path_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string()
}

fn path_matches_ref(path: &Path, artifact_ref: &str) -> bool {
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    filename == format!("{}.json", trimmed)
}

fn get_str(event: &serde_json::Value, field: &str) -> Result<String, MutationError> {
    event
        .get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| MutationError::new("audit_log_invalid"))
}
