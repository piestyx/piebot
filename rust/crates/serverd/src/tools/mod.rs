use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const TOOL_SPEC_SCHEMA: &str = "serverd.tool_spec.v1";
#[allow(dead_code)]
pub const TOOL_REGISTRY_SCHEMA: &str = "serverd.tool_registry.v1";
pub mod execute;
pub mod policy;

#[derive(Debug)]
pub struct ToolError {
    reason: &'static str,
    source: Option<std::io::Error>,
}

impl ToolError {
    pub fn new(reason: &'static str) -> Self {
        Self {
            reason,
            source: None,
        }
    }

    pub fn with_source(reason: &'static str, source: std::io::Error) -> Self {
        Self {
            reason,
            source: Some(source),
        }
    }

    pub fn reason(&self) -> &'static str {
        self.reason
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for ToolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e as _)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ToolId(String);

impl ToolId {
    pub fn parse(value: &str) -> Result<Self, ToolError> {
        if is_safe_tool_id_token(value) {
            Ok(Self(value.to_string()))
        } else {
            Err(ToolError::new("tool_id_invalid"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ToolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for ToolId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ToolId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        ToolId::parse(&value).map_err(serde::de::Error::custom)
    }
}

fn is_safe_tool_id_token(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}
fn is_safe_schema_ident(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ToolSpec {
    pub schema: String,
    pub id: ToolId,
    pub input_schema: String,
    pub output_schema: String,
    pub deterministic: bool,
    pub risk_level: RiskLevel,
    pub requires_approval: bool,
    pub requires_arming: bool,
    #[serde(default)]
    pub filesystem: bool,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct ToolRegistry {
    tools: BTreeMap<ToolId, ToolSpec>,
}

impl ToolRegistry {
    pub fn load_tools(runtime_root: &Path) -> Result<Self, ToolError> {
        let dir = runtime_root.join("tools");
        if !dir.exists() {
            return Ok(Self {
                tools: BTreeMap::new(),
            });
        }

        let mut entries: Vec<(String, PathBuf)> = Vec::new();
        for entry in fs::read_dir(&dir)
            .map_err(|e| ToolError::with_source("tool_registry_read_failed", e))?
        {
            let entry =
                entry.map_err(|e| ToolError::with_source("tool_registry_read_failed", e))?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| ToolError::new("tool_spec_invalid"))?;
            if !file_name.ends_with(".json") {
                continue;
            }
            if file_name == "policy.json" {
                continue;
            }
            entries.push((file_name.to_string(), path));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut tools = BTreeMap::new();
        for (_file_name, path) in entries {
            let bytes =
                fs::read(&path).map_err(|e| ToolError::with_source("tool_spec_read_failed", e))?;
            let spec: ToolSpec =
                serde_json::from_slice(&bytes).map_err(|_| ToolError::new("tool_spec_invalid"))?;
            validate_spec(&spec)?;
            if tools.insert(spec.id.clone(), spec).is_some() {
                // Duplicate IDs are considered invalid tool specs.
                return Err(ToolError::new("tool_spec_invalid"));
            }
        }

        Ok(Self { tools })
    }

    #[allow(dead_code)]
    pub fn tool_ids(&self) -> Vec<String> {
        self.tool_ids_iter()
            .map(|id| id.as_str().to_string())
            .collect()
    }
    #[allow(dead_code)]
    pub fn tool_ids_iter(&self) -> impl Iterator<Item = &ToolId> {
        self.tools.keys()
    }

    pub fn get(&self, tool_id: &ToolId) -> Option<&ToolSpec> {
        self.tools.get(tool_id)
    }

    /// Diagnostic-only helper for registry hashing/tests. Not a stable API.
    #[allow(dead_code)]
    pub fn as_registry_value(&self) -> serde_json::Value {
        let tools: Vec<ToolSpec> = self.tools.values().cloned().collect();
        serde_json::json!({
            "schema": TOOL_REGISTRY_SCHEMA,
            "tools": tools
        })
    }
}

fn validate_spec(spec: &ToolSpec) -> Result<(), ToolError> {
    if spec.schema != TOOL_SPEC_SCHEMA {
        return Err(ToolError::new("tool_spec_invalid"));
    }
    if !is_safe_schema_ident(&spec.input_schema)
        || !is_safe_schema_ident(&spec.output_schema)
        || !is_safe_schema_ident(&spec.version)
    {
        return Err(ToolError::new("tool_spec_invalid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_id_parse_accepts_safe_tokens() {
        assert!(ToolId::parse("foo").is_ok());
        assert!(ToolId::parse("foo-bar").is_ok());
        assert!(ToolId::parse("foo_bar").is_ok());
        assert!(ToolId::parse("foo.bar").is_ok());
    }

    #[test]
    fn tool_id_parse_rejects_unsafe_chars() {
        assert!(ToolId::parse("").is_err());
        assert!(ToolId::parse("foo/bar").is_err());
        assert!(ToolId::parse("foo bar").is_err());
        assert!(ToolId::parse("foo:bar").is_err());
    }

    #[test]
    fn tool_spec_invalid_schema_fails() {
        let spec = ToolSpec {
            schema: "wrong.schema".to_string(),
            id: ToolId::parse("tool.noop").expect("tool id"),
            input_schema: "serverd.tool_input.noop.v1".to_string(),
            output_schema: "serverd.tool_output.noop.v1".to_string(),
            deterministic: true,
            risk_level: RiskLevel::Low,
            requires_approval: false,
            requires_arming: false,
            filesystem: false,
            version: "v1".to_string(),
        };
        let err = validate_spec(&spec).expect_err("should fail");
        assert_eq!(err.reason(), "tool_spec_invalid");
    }

    #[test]
    fn tool_spec_deny_unknown_fields_enforced() {
        let value = serde_json::json!({
            "schema": TOOL_SPEC_SCHEMA,
            "id": "tool.noop",
            "input_schema": "serverd.tool_input.noop.v1",
            "output_schema": "serverd.tool_output.noop.v1",
            "deterministic": true,
            "risk_level": "low",
            "requires_approval": false,
            "requires_arming": false,
            "version": "v1",
            "extra": true
        });
        let bytes = serde_json::to_vec(&value).expect("serialize");
        let parsed: Result<ToolSpec, _> = serde_json::from_slice(&bytes);
        assert!(parsed.is_err());
    }
}
