use crate::context::ContextSelection;
use crate::skills::SkillContext;
use pie_common::canonical_json_bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const CONTEXT_POLICY_SCHEMA: &str = "serverd.context_policy.v1";

#[derive(Debug)]
pub struct ContextPolicyError {
    reason: &'static str,
    detail: Option<String>,
}

impl ContextPolicyError {
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

impl std::fmt::Display for ContextPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for ContextPolicyError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ContextPolicy {
    pub schema: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub max_items: u64,
    #[serde(default)]
    pub max_bytes: u64,
    #[serde(default)]
    pub allowed_namespaces: Vec<String>,
    #[serde(default = "default_ordering")]
    pub ordering: String,
    #[serde(default)]
    pub allow_skill_overrides: bool,
}

impl Default for ContextPolicy {
    fn default() -> Self {
        Self {
            schema: CONTEXT_POLICY_SCHEMA.to_string(),
            enabled: false,
            max_items: 0,
            max_bytes: 0,
            allowed_namespaces: Vec::new(),
            ordering: default_ordering(),
            allow_skill_overrides: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextOrdering {
    Lexicographic,
    StableManifestOrder,
}

pub fn load_context_policy(runtime_root: &Path) -> Result<ContextPolicy, ContextPolicyError> {
    let path = context_policy_path(runtime_root);
    if !path.exists() {
        return Ok(ContextPolicy::default());
    }
    let bytes = std::fs::read(&path).map_err(|e| {
        ContextPolicyError::with_detail("context_policy_read_failed", e.to_string())
    })?;
    let mut config: ContextPolicy = serde_json::from_slice(&bytes)
        .map_err(|e| ContextPolicyError::with_detail("context_policy_invalid", e.to_string()))?;
    if config.schema != CONTEXT_POLICY_SCHEMA {
        return Err(ContextPolicyError::new("context_policy_invalid"));
    }
    normalize_context_policy(&mut config)?;
    Ok(config)
}

pub fn enforce_context_policy(
    selection: ContextSelection,
    policy: &ContextPolicy,
    skill_ctx: Option<&SkillContext>,
) -> Result<ContextSelection, ContextPolicyError> {
    if !policy.enabled {
        return Ok(selection);
    }
    let mut refs = selection.context_refs.clone();
    let mut allowed_namespaces = policy.allowed_namespaces.clone();
    let mut max_items = policy.max_items;
    let mut max_bytes = policy.max_bytes;

    if policy.allow_skill_overrides {
        if let Some(skill_ctx) = skill_ctx {
            if let Some(list) = &skill_ctx.manifest.allowed_context_namespaces {
                let override_set: BTreeSet<String> = list.iter().cloned().collect();
                let policy_set: BTreeSet<String> = allowed_namespaces.iter().cloned().collect();
                if !override_set.is_subset(&policy_set) {
                    return Err(ContextPolicyError::new("context_policy_override_invalid"));
                }
                allowed_namespaces = override_set.into_iter().collect();
                allowed_namespaces.sort();
                allowed_namespaces.dedup();
            }
            if let Some(items) = skill_ctx.manifest.max_context_items {
                if items > max_items {
                    return Err(ContextPolicyError::new("context_policy_override_invalid"));
                }
                max_items = items;
            }
            if let Some(bytes) = skill_ctx.manifest.max_context_bytes {
                if bytes > max_bytes {
                    return Err(ContextPolicyError::new("context_policy_override_invalid"));
                }
                max_bytes = bytes;
            }
        }
    }

    for entry in &refs {
        let namespace = namespace_from_ref(entry);
        if !allowed_namespaces.iter().any(|n| n == namespace) {
            return Err(ContextPolicyError::new("context_namespace_denied"));
        }
    }

    refs = match parse_ordering(&policy.ordering) {
        Some(ContextOrdering::Lexicographic) => {
            let mut ordered = refs;
            ordered.sort();
            ordered
        }
        Some(ContextOrdering::StableManifestOrder) => refs,
        None => return Err(ContextPolicyError::new("context_policy_invalid")),
    };

    if max_items > 0 && refs.len() as u64 > max_items {
        return Err(ContextPolicyError::new(
            "context_selection_exceeds_max_items",
        ));
    }

    let mut output = ContextSelection {
        schema: selection.schema,
        context_refs: refs,
        ordering: Some(policy.ordering.clone()),
        total_items: None,
        total_bytes: None,
    };
    let (total_items, total_bytes) = compute_selection_metrics(&output)?;
    if max_bytes > 0 && total_bytes > max_bytes {
        return Err(ContextPolicyError::new(
            "context_selection_exceeds_max_bytes",
        ));
    }
    output.total_items = Some(total_items);
    output.total_bytes = Some(total_bytes);
    Ok(output)
}

pub fn compute_selection_metrics(
    selection: &ContextSelection,
) -> Result<(u64, u64), ContextPolicyError> {
    let total_items = selection.context_refs.len() as u64;
    let mut current_bytes = 0u64;
    for _ in 0..5 {
        let mut working = selection.clone();
        working.total_items = Some(total_items);
        working.total_bytes = Some(current_bytes);
        let value = serde_json::to_value(&working)
            .map_err(|_| ContextPolicyError::new("context_selection_failed"))?;
        let bytes = canonical_json_bytes(&value)
            .map_err(|_| ContextPolicyError::new("context_selection_failed"))?;
        let next = bytes.len() as u64;
        if next == current_bytes {
            return Ok((total_items, next));
        }
        current_bytes = next;
    }
    Err(ContextPolicyError::new("context_selection_failed"))
}

pub fn context_policy_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join("context").join("policy.json")
}

fn normalize_context_policy(config: &mut ContextPolicy) -> Result<(), ContextPolicyError> {
    if config.enabled {
        if config.max_items == 0 || config.max_bytes == 0 {
            return Err(ContextPolicyError::new("context_policy_invalid"));
        }
        if config.allowed_namespaces.is_empty() {
            return Err(ContextPolicyError::new("context_policy_invalid"));
        }
    }
    for ns in &config.allowed_namespaces {
        if ns.trim().is_empty() || !is_safe_namespace(ns) {
            return Err(ContextPolicyError::new("context_policy_invalid"));
        }
    }
    config.allowed_namespaces.sort();
    config.allowed_namespaces.dedup();
    if parse_ordering(&config.ordering).is_none() {
        return Err(ContextPolicyError::new("context_policy_invalid"));
    }
    Ok(())
}

fn parse_ordering(value: &str) -> Option<ContextOrdering> {
    match value {
        "lexicographic" => Some(ContextOrdering::Lexicographic),
        "stable_manifest_order" => Some(ContextOrdering::StableManifestOrder),
        _ => None,
    }
}

fn namespace_from_ref(value: &str) -> &str {
    let mut parts = value.splitn(2, '/');
    let prefix = parts.next().unwrap_or("");
    let rest = parts.next();
    if rest.is_some() && !prefix.is_empty() {
        return prefix;
    }
    "contexts"
}

fn is_safe_namespace(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn default_ordering() -> String {
    "stable_manifest_order".to_string()
}
