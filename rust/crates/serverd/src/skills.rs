use crate::audit::{append_event, AuditEvent};
use crate::tools::execute::{read_tool_input, ToolCall};
use crate::tools::{ToolError, ToolId};
use pie_audit_log::AuditAppender;
use pie_common::{canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const SKILL_MANIFEST_SCHEMA: &str = "serverd.skill_manifest.v1";

#[derive(Debug)]
pub struct SkillError {
    reason: &'static str,
    detail: Option<String>,
}

impl SkillError {
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

impl std::fmt::Display for SkillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for SkillError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SkillToolConstraint {
    pub tool_id: String,
    pub require: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SkillManifest {
    pub schema: String,
    pub skill_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub tool_constraints: Vec<SkillToolConstraint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_contract: Option<String>,
    #[serde(default)]
    pub prompt_template_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_context_namespaces: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_context_items: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_context_bytes: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct SkillContext {
    pub manifest: SkillManifest,
    pub manifest_hash: String,
    allowed_tools: BTreeSet<ToolId>,
    constraints: BTreeMap<ToolId, Vec<SkillToolConstraint>>,
}

#[derive(Debug, Clone)]
pub struct SkillRegistry {
    skills: BTreeMap<String, SkillManifest>,
}

impl SkillRegistry {
    pub fn load(runtime_root: &Path) -> Result<Self, SkillError> {
        let dir = runtime_root.join("skills");
        if !dir.exists() {
            return Ok(Self {
                skills: BTreeMap::new(),
            });
        }

        let mut entries: Vec<(String, PathBuf)> = Vec::new();
        for entry in fs::read_dir(&dir)
            .map_err(|e| SkillError::with_detail("skill_registry_read_failed", e.to_string()))?
        {
            let entry = entry.map_err(|e| {
                SkillError::with_detail("skill_registry_read_failed", e.to_string())
            })?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let dir_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| SkillError::new("skill_manifest_invalid"))?;
            entries.push((dir_name.to_string(), path));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut skills = BTreeMap::new();
        for (dir_name, path) in entries {
            let manifest_path = path.join("skill.json");
            if !manifest_path.is_file() {
                return Err(SkillError::with_detail(
                    "skill_manifest_missing",
                    dir_name.clone(),
                ));
            }
            let bytes = fs::read(&manifest_path).map_err(|e| {
                SkillError::with_detail("skill_manifest_read_failed", e.to_string())
            })?;
            let manifest: SkillManifest = serde_json::from_slice(&bytes)
                .map_err(|_| SkillError::new("skill_manifest_invalid"))?;
            validate_manifest(&manifest, &dir_name)?;
            if skills.insert(manifest.skill_id.clone(), manifest).is_some() {
                return Err(SkillError::new("skill_manifest_invalid"));
            }
        }

        Ok(Self { skills })
    }

    pub fn get(&self, skill_id: &str) -> Option<&SkillManifest> {
        self.skills.get(skill_id)
    }

    #[allow(dead_code)]
    pub fn skill_ids(&self) -> Vec<String> {
        self.skills.keys().cloned().collect()
    }
}

pub fn load_skill_context(runtime_root: &Path, skill_id: &str) -> Result<SkillContext, SkillError> {
    let registry = SkillRegistry::load(runtime_root)?;
    let manifest = registry
        .get(skill_id)
        .ok_or_else(|| SkillError::new("skill_not_found"))?;
    let manifest_hash = skill_manifest_hash(manifest)?;
    let mut allowed_tools = BTreeSet::new();
    for tool_id in &manifest.allowed_tools {
        let parsed =
            ToolId::parse(tool_id).map_err(|_| SkillError::new("skill_manifest_invalid"))?;
        allowed_tools.insert(parsed);
    }
    let mut constraints: BTreeMap<ToolId, Vec<SkillToolConstraint>> = BTreeMap::new();
    for constraint in &manifest.tool_constraints {
        let parsed = ToolId::parse(&constraint.tool_id)
            .map_err(|_| SkillError::new("skill_manifest_invalid"))?;
        constraints
            .entry(parsed)
            .or_default()
            .push(constraint.clone());
    }
    Ok(SkillContext {
        manifest: manifest.clone(),
        manifest_hash,
        allowed_tools,
        constraints,
    })
}

pub fn skill_manifest_hash(manifest: &SkillManifest) -> Result<String, SkillError> {
    let value = serde_json::to_value(manifest)
        .map_err(|_| SkillError::new("skill_manifest_hash_failed"))?;
    let bytes =
        canonical_json_bytes(&value).map_err(|_| SkillError::new("skill_manifest_hash_failed"))?;
    Ok(sha256_bytes(&bytes))
}

pub fn enforce_tool_call(
    runtime_root: &Path,
    ctx: &SkillContext,
    call: &ToolCall,
    audit: &mut AuditAppender,
) -> Result<(), SkillError> {
    if !ctx.allowed_tools.contains(&call.tool_id) {
        emit_tool_denied(
            audit,
            &call.tool_id,
            "skill_tool_not_allowed",
            &call.request_hash,
        )?;
        return Err(SkillError::new("skill_tool_not_allowed"));
    }
    let constraints = match ctx.constraints.get(&call.tool_id) {
        Some(values) => values,
        None => return Ok(()),
    };
    if constraints.is_empty() {
        return Ok(());
    }

    let input_ref = match call.input_ref.as_deref() {
        Some(value) => value,
        None => return Err(SkillError::new("tool_call_invalid")),
    };
    let input_value = match read_tool_input(runtime_root, input_ref) {
        Ok(value) => value,
        Err(e) => {
            let reason = map_tool_input_error(&e);
            emit_tool_denied(audit, &call.tool_id, reason, &call.request_hash)?;
            return Err(SkillError::new(reason));
        }
    };

    for constraint in constraints {
        for (key, expected) in constraint.require.iter() {
            match input_value.get(key) {
                Some(actual) if actual == expected => {}
                _ => {
                    emit_tool_denied(
                        audit,
                        &call.tool_id,
                        "skill_tool_constraint_failed",
                        &call.request_hash,
                    )?;
                    return Err(SkillError::new("skill_tool_constraint_failed"));
                }
            }
        }
    }

    Ok(())
}

#[allow(dead_code)]
pub fn append_learning(
    runtime_root: &Path,
    skill_id: &str,
    entry_value: serde_json::Value,
    audit: &mut AuditAppender,
) -> Result<String, SkillError> {
    if !is_safe_skill_id_token(skill_id) {
        return Err(SkillError::new("skill_learning_invalid"));
    }
    let dir = runtime_root.join("skills").join(skill_id);
    fs::create_dir_all(&dir)
        .map_err(|e| SkillError::with_detail("skill_learning_write_failed", e.to_string()))?;
    let bytes = canonical_json_bytes(&entry_value)
        .map_err(|_| SkillError::new("skill_learning_invalid"))?;
    let entry_hash = sha256_bytes(&bytes);
    let path = dir.join("learnings.jsonl");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| SkillError::with_detail("skill_learning_write_failed", e.to_string()))?;
    file.write_all(&bytes)
        .map_err(|e| SkillError::with_detail("skill_learning_write_failed", e.to_string()))?;
    file.write_all(b"\n")
        .map_err(|e| SkillError::with_detail("skill_learning_write_failed", e.to_string()))?;
    append_event(
        audit,
        AuditEvent::SkillLearningAppended {
            skill_id: skill_id.to_string(),
            entry_hash: entry_hash.clone(),
        },
    )
    .map(|_| ())
    .map_err(|e| SkillError::with_detail("skill_audit_failed", e.to_string()))?;
    Ok(entry_hash)
}
fn map_tool_input_error(err: &ToolError) -> &'static str {
    match err.reason() {
        "tool_input_read_failed" => "skill_tool_input_unreadable",
        "tool_input_invalid" => "skill_tool_input_invalid",
        _ => "skill_tool_input_invalid",
    }
}

fn emit_tool_denied(
    audit: &mut AuditAppender,
    tool_id: &ToolId,
    reason: &'static str,
    request_hash: &str,
) -> Result<(), SkillError> {
    append_event(
        audit,
        AuditEvent::ToolExecutionDenied {
            tool_id: tool_id.as_str().to_string(),
            reason: reason.to_string(),
            request_hash: request_hash.to_string(),
        },
    )
    .map(|_| ())
    .map_err(|e| SkillError::with_detail("skill_audit_failed", e.to_string()))
}

fn validate_manifest(manifest: &SkillManifest, dir_name: &str) -> Result<(), SkillError> {
    if manifest.schema != SKILL_MANIFEST_SCHEMA {
        return Err(SkillError::new("skill_manifest_invalid"));
    }
    if !is_safe_skill_id_token(&manifest.skill_id) {
        return Err(SkillError::new("skill_manifest_invalid"));
    }
    if manifest.skill_id != dir_name {
        return Err(SkillError::new("skill_manifest_invalid"));
    }
    for tool_id in &manifest.allowed_tools {
        if ToolId::parse(tool_id).is_err() {
            return Err(SkillError::new("skill_manifest_invalid"));
        }
    }
    for constraint in &manifest.tool_constraints {
        if ToolId::parse(&constraint.tool_id).is_err() {
            return Err(SkillError::new("skill_manifest_invalid"));
        }
    }
    if let Some(namespaces) = &manifest.allowed_context_namespaces {
        for ns in namespaces {
            if !is_safe_skill_id_token(ns) {
                return Err(SkillError::new("skill_manifest_invalid"));
            }
        }
    }
    if let Some(items) = manifest.max_context_items {
        if items == 0 {
            return Err(SkillError::new("skill_manifest_invalid"));
        }
    }
    if let Some(bytes) = manifest.max_context_bytes {
        if bytes == 0 {
            return Err(SkillError::new("skill_manifest_invalid"));
        }
    }
    if let Some(contract) = &manifest.output_contract {
        if !is_safe_skill_id_token(contract) {
            return Err(SkillError::new("skill_manifest_invalid"));
        }
    }
    Ok(())
}

fn is_safe_skill_id_token(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}
