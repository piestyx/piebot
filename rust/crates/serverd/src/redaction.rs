use pie_common::canonical_json_bytes;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const REDACTION_CONFIG_SCHEMA: &str = "serverd.redaction_config.v1";

const DEFAULT_MAX_PROVIDER_INPUT_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
pub struct RedactionError {
    reason: &'static str,
    detail: Option<String>,
}

impl RedactionError {
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

impl std::fmt::Display for RedactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for RedactionError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RedactionConfig {
    pub schema: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_provider_input_bytes")]
    pub max_provider_input_bytes: u64,
    #[serde(default)]
    pub strategies: RedactionStrategies,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            schema: REDACTION_CONFIG_SCHEMA.to_string(),
            enabled: false,
            max_provider_input_bytes: DEFAULT_MAX_PROVIDER_INPUT_BYTES,
            strategies: RedactionStrategies::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RedactionStrategies {
    #[serde(default)]
    pub drop_fields: Vec<String>,
    #[serde(default)]
    pub redact_fields: Vec<String>,
    #[serde(default)]
    pub regex_redactions: Vec<RegexRedaction>,
    #[serde(default)]
    pub allow_raw_artifacts: bool,
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RegexRedaction {
    pub name: String,
    pub pattern: String,
    pub replace: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FieldPath {
    Top(String),
    Nested(String, String),
}

pub fn load_redaction_config(runtime_root: &Path) -> Result<RedactionConfig, RedactionError> {
    let path = redaction_config_path(runtime_root);
    if !path.exists() {
        return Ok(RedactionConfig::default());
    }
    let bytes = std::fs::read(&path)
        .map_err(|e| RedactionError::with_detail("redaction_config_read_failed", e.to_string()))?;
    let mut config: RedactionConfig = serde_json::from_slice(&bytes)
        .map_err(|e| RedactionError::with_detail("redaction_config_invalid", e.to_string()))?;
    if config.schema != REDACTION_CONFIG_SCHEMA {
        return Err(RedactionError::new("redaction_config_invalid"));
    }
    normalize_config(&mut config)?;
    Ok(config)
}

#[allow(dead_code)]
pub fn apply_redaction(
    value: &serde_json::Value,
    cfg: &RedactionConfig,
) -> Result<serde_json::Value, RedactionError> {
    let compiled = compile_regex_redactions(cfg)?;
    apply_redaction_with_compiled(value, cfg, &compiled)
}

#[allow(dead_code)]
pub fn minimize_provider_input(
    value: &serde_json::Value,
    cfg: &RedactionConfig,
) -> Result<serde_json::Value, RedactionError> {
    let redacted = apply_redaction(value, cfg)?;
    let bytes =
        canonical_json_bytes(&redacted).map_err(|_| RedactionError::new("redaction_failed"))?;
    if cfg.max_provider_input_bytes == 0 {
        return Err(RedactionError::new("redaction_config_invalid"));
    }
    if bytes.len() as u64 > cfg.max_provider_input_bytes {
        return Err(RedactionError::new("redaction_limit_exceeded"));
    }
    Ok(redacted)
}

#[derive(Debug, Clone)]
pub struct CompiledRegexRedaction {
    regex: Regex,
    replace: String,
}

pub fn compile_regex_redactions(
    cfg: &RedactionConfig,
) -> Result<Vec<CompiledRegexRedaction>, RedactionError> {
    let mut compiled = Vec::with_capacity(cfg.strategies.regex_redactions.len());
    for rule in &cfg.strategies.regex_redactions {
        let regex = Regex::new(rule.pattern.as_str())
            .map_err(|_| RedactionError::new("redaction_config_invalid"))?;
        compiled.push(CompiledRegexRedaction {
            regex,
            replace: rule.replace.clone(),
        });
    }
    Ok(compiled)
}

pub fn apply_redaction_with_compiled(
    value: &serde_json::Value,
    cfg: &RedactionConfig,
    compiled: &[CompiledRegexRedaction],
) -> Result<serde_json::Value, RedactionError> {
    let mut output = value.clone();
    let mut drop_paths = Vec::with_capacity(cfg.strategies.drop_fields.len());
    for path in &cfg.strategies.drop_fields {
        drop_paths.push(parse_field_path(path)?);
    }
    let mut redact_paths = Vec::with_capacity(cfg.strategies.redact_fields.len());
    for path in &cfg.strategies.redact_fields {
        redact_paths.push(parse_field_path(path)?);
    }
    for path in &drop_paths {
        drop_field(&mut output, path);
    }
    for path in &redact_paths {
        redact_field(&mut output, path);
    }
    for rule in compiled {
        apply_regex(&mut output, &rule.regex, &rule.replace);
    }
    Ok(output)
}

pub fn minimize_provider_input_with_compiled(
    value: &serde_json::Value,
    cfg: &RedactionConfig,
    compiled: &[CompiledRegexRedaction],
) -> Result<serde_json::Value, RedactionError> {
    let redacted = apply_redaction_with_compiled(value, cfg, compiled)?;
    let bytes =
        canonical_json_bytes(&redacted).map_err(|_| RedactionError::new("redaction_failed"))?;
    if cfg.max_provider_input_bytes == 0 {
        return Err(RedactionError::new("redaction_config_invalid"));
    }
    if bytes.len() as u64 > cfg.max_provider_input_bytes {
        return Err(RedactionError::new("redaction_limit_exceeded"));
    }
    Ok(redacted)
}

fn redaction_config_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join("redaction").join("config.json")
}

fn normalize_config(config: &mut RedactionConfig) -> Result<(), RedactionError> {
    if config.max_provider_input_bytes == 0 && config.enabled {
        return Err(RedactionError::new("redaction_config_invalid"));
    }
    config.strategies.drop_fields.sort();
    config.strategies.redact_fields.sort();
    config.strategies.regex_redactions.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then(a.pattern.cmp(&b.pattern))
            .then(a.replace.cmp(&b.replace))
    });
    for path in config
        .strategies
        .drop_fields
        .iter()
        .chain(config.strategies.redact_fields.iter())
    {
        let _ = parse_field_path(path)?;
    }
    for rule in &config.strategies.regex_redactions {
        if rule.name.trim().is_empty() || rule.pattern.is_empty() {
            return Err(RedactionError::new("redaction_config_invalid"));
        }
        Regex::new(rule.pattern.as_str())
            .map_err(|_| RedactionError::new("redaction_config_invalid"))?;
    }
    Ok(())
}

fn parse_field_path(path: &str) -> Result<FieldPath, RedactionError> {
    if path.trim().is_empty() {
        return Err(RedactionError::new("redaction_config_invalid"));
    }
    let parts: Vec<&str> = path.split('.').collect();
    match parts.len() {
        1 => {
            let key = parts[0].trim();
            if key.is_empty() {
                Err(RedactionError::new("redaction_config_invalid"))
            } else {
                Ok(FieldPath::Top(key.to_string()))
            }
        }
        2 => {
            let parent = parts[0].trim();
            let child = parts[1].trim();
            if parent.is_empty() || child.is_empty() {
                Err(RedactionError::new("redaction_config_invalid"))
            } else {
                Ok(FieldPath::Nested(parent.to_string(), child.to_string()))
            }
        }
        _ => Err(RedactionError::new("redaction_config_invalid")),
    }
}

fn drop_field(value: &mut serde_json::Value, path: &FieldPath) {
    let obj = match value.as_object_mut() {
        Some(obj) => obj,
        None => return,
    };
    match path {
        FieldPath::Top(key) => {
            obj.remove(key);
        }
        FieldPath::Nested(parent, child) => {
            if let Some(parent_val) = obj.get_mut(parent) {
                if let Some(map) = parent_val.as_object_mut() {
                    map.remove(child);
                }
            }
        }
    }
}

fn redact_field(value: &mut serde_json::Value, path: &FieldPath) {
    let obj = match value.as_object_mut() {
        Some(obj) => obj,
        None => return,
    };
    match path {
        FieldPath::Top(key) => {
            if obj.contains_key(key) {
                obj.insert(
                    key.clone(),
                    serde_json::Value::String("__REDACTED__".to_string()),
                );
            }
        }
        FieldPath::Nested(parent, child) => {
            if let Some(parent_val) = obj.get_mut(parent) {
                if let Some(map) = parent_val.as_object_mut() {
                    if map.contains_key(child) {
                        map.insert(
                            child.clone(),
                            serde_json::Value::String("__REDACTED__".to_string()),
                        );
                    }
                }
            }
        }
    }
}

fn apply_regex(value: &mut serde_json::Value, regex: &Regex, replace: &str) {
    match value {
        serde_json::Value::String(s) => {
            let updated = regex.replace_all(s, replace);
            if updated != *s {
                *s = updated.to_string();
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                apply_regex(item, regex, replace);
            }
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();
            for key in keys {
                if let Some(next) = map.get_mut(&key) {
                    apply_regex(next, regex, replace);
                }
            }
        }
        _ => {}
    }
}

fn default_max_provider_input_bytes() -> u64 {
    DEFAULT_MAX_PROVIDER_INPUT_BYTES
}
