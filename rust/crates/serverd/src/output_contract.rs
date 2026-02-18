use crate::ref_utils::is_safe_token;
use pie_common::{canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const OUTPUT_CONTRACT_SCHEMA: &str = "serverd.output_contract.v1";

#[derive(Debug)]
pub struct OutputContractError {
    reason: &'static str,
    detail: Option<String>,
}

impl OutputContractError {
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

impl std::fmt::Display for OutputContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for OutputContractError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct OutputContract {
    pub schema: String,
    pub contract_id: String,
    #[serde(default)]
    pub allowed_tool_calls: Vec<String>,
    #[serde(default)]
    pub required_fields: Vec<String>,
    #[serde(default)]
    pub allowed_fields: Vec<String>,
    #[serde(default)]
    pub field_constraints: BTreeMap<String, FieldConstraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FieldConstraint {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub min: Option<f64>,
    #[serde(default)]
    pub max: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct OutputContractEntry {
    pub contract: OutputContract,
    pub contract_hash: String,
}

#[derive(Debug, Clone)]
pub struct OutputContractRegistry {
    contracts: BTreeMap<String, OutputContractEntry>,
}

impl OutputContractRegistry {
    pub fn get(&self, contract_id: &str) -> Option<&OutputContractEntry> {
        self.contracts.get(contract_id)
    }

    #[allow(dead_code)]
    pub fn contract_ids(&self) -> Vec<String> {
        self.contracts.keys().cloned().collect()
    }
}

pub fn load_output_contracts(
    runtime_root: &Path,
) -> Result<OutputContractRegistry, OutputContractError> {
    let dir = output_contracts_path(runtime_root);
    if !dir.exists() {
        return Ok(OutputContractRegistry {
            contracts: BTreeMap::new(),
        });
    }
    let mut entries: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .map_err(|e| OutputContractError::with_detail("output_contract_invalid", e.to_string()))?
    {
        let entry = entry.map_err(|e| {
            OutputContractError::with_detail("output_contract_invalid", e.to_string())
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }
        entries.push(path);
    }
    entries.sort();

    let mut contracts = BTreeMap::new();
    for path in entries {
        let bytes = std::fs::read(&path).map_err(|e| {
            OutputContractError::with_detail("output_contract_invalid", e.to_string())
        })?;
        let mut contract: OutputContract = serde_json::from_slice(&bytes).map_err(|e| {
            OutputContractError::with_detail("output_contract_invalid", e.to_string())
        })?;
        normalize_contract(&mut contract)?;
        let contract_id = contract.contract_id.clone();
        if contracts.contains_key(&contract_id) {
            return Err(OutputContractError::new("output_contract_invalid"));
        }
        let value = serde_json::to_value(&contract)
            .map_err(|_| OutputContractError::new("output_contract_invalid"))?;
        let bytes = canonical_json_bytes(&value)
            .map_err(|_| OutputContractError::new("output_contract_invalid"))?;
        let contract_hash = sha256_bytes(&bytes);
        contracts.insert(
            contract_id,
            OutputContractEntry {
                contract,
                contract_hash,
            },
        );
    }

    Ok(OutputContractRegistry { contracts })
}

pub fn read_output_from_response(
    runtime_root: &Path,
    response_ref: &str,
) -> Result<serde_json::Value, OutputContractError> {
    let response_path = artifact_path(runtime_root, "responses", response_ref);
    let response_bytes = std::fs::read(&response_path)
        .map_err(|_| OutputContractError::new("provider_output_validation_failed"))?;
    let response_value: serde_json::Value = serde_json::from_slice(&response_bytes)
        .map_err(|_| OutputContractError::new("provider_output_validation_failed"))?;
    let output_ref = response_value
        .get("output_ref")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OutputContractError::new("provider_output_validation_failed"))?;
    let output_path = artifact_path(runtime_root, "outputs", output_ref);
    let output_bytes = std::fs::read(&output_path)
        .map_err(|_| OutputContractError::new("provider_output_validation_failed"))?;
    let output_value: serde_json::Value = serde_json::from_slice(&output_bytes)
        .map_err(|_| OutputContractError::new("provider_output_validation_failed"))?;
    Ok(output_value)
}

pub fn validate_provider_output(
    output: &serde_json::Value,
    contract: &OutputContract,
) -> Result<(), OutputContractError> {
    let obj = output
        .as_object()
        .ok_or_else(|| OutputContractError::new("provider_output_invalid"))?;

    let tool_call_obj = match obj.get("tool_call") {
        Some(value) => Some(
            value
                .as_object()
                .ok_or_else(|| OutputContractError::new("provider_output_contract_violation"))?,
        ),
        None => None,
    };
    let tool_input_kind = if let Some(tool_call_obj) = tool_call_obj.as_ref() {
        let input_ref = tool_call_obj.get("input_ref");
        let input = tool_call_obj.get("input");
        let has_ref = input_ref.is_some();
        let has_input = input.is_some();
        if has_ref == has_input {
            return Err(OutputContractError::new(
                "provider_output_contract_violation",
            ));
        }
        if let Some(value) = input_ref {
            if !value.is_string() || value.as_str().unwrap_or("").is_empty() {
                return Err(OutputContractError::new(
                    "provider_output_contract_violation",
                ));
            }
        }
        if let Some(value) = input {
            if !value.is_object() {
                return Err(OutputContractError::new(
                    "provider_output_contract_violation",
                ));
            }
        }
        Some(if has_ref {
            ToolCallInputKind::Ref
        } else {
            ToolCallInputKind::Inline
        })
    } else {
        None
    };

    let allowed_fields: BTreeSet<String> = contract.allowed_fields.iter().cloned().collect();
    for key in obj.keys() {
        if !allowed_fields.contains(key) {
            return Err(OutputContractError::new(
                "provider_output_contract_violation",
            ));
        }
    }
    for required in &contract.required_fields {
        if !obj.contains_key(required) {
            return Err(OutputContractError::new(
                "provider_output_contract_violation",
            ));
        }
    }

    for (path, constraint) in &contract.field_constraints {
        if let Some(tool_input_kind) = tool_input_kind {
            if path == "tool_call.input_ref" && tool_input_kind == ToolCallInputKind::Inline {
                continue;
            }
            if path == "tool_call.input" && tool_input_kind == ToolCallInputKind::Ref {
                continue;
            }
        }
        let value = match parse_field_path(path) {
            Ok(FieldPath::Top(key)) => obj
                .get(&key)
                .ok_or_else(|| OutputContractError::new("provider_output_contract_violation"))?,
            Ok(FieldPath::Nested(parent, child)) => {
                let parent_value = obj.get(&parent).ok_or_else(|| {
                    OutputContractError::new("provider_output_contract_violation")
                })?;
                let parent_obj = parent_value.as_object().ok_or_else(|| {
                    OutputContractError::new("provider_output_contract_violation")
                })?;
                parent_obj
                    .get(&child)
                    .ok_or_else(|| OutputContractError::new("provider_output_contract_violation"))?
            }
            Err(e) => return Err(e),
        };
        validate_value_against_constraint(value, constraint)?;
    }
    if let Some(tool_call_obj) = tool_call_obj {
        if contract.allowed_tool_calls.is_empty() {
            return Err(OutputContractError::new(
                "provider_output_contract_violation",
            ));
        }
        let tool_id = tool_call_obj
            .get("tool_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OutputContractError::new("provider_output_contract_violation"))?;
        if !contract.allowed_tool_calls.iter().any(|id| id == tool_id) {
            return Err(OutputContractError::new(
                "provider_output_contract_violation",
            ));
        }
    }

    Ok(())
}

fn validate_value_against_constraint(
    value: &serde_json::Value,
    constraint: &FieldConstraint,
) -> Result<(), OutputContractError> {
    match constraint.kind.as_str() {
        "string" => {
            if !value.is_string() {
                return Err(OutputContractError::new(
                    "provider_output_contract_violation",
                ));
            }
        }
        "number" => {
            let num = value
                .as_f64()
                .ok_or_else(|| OutputContractError::new("provider_output_contract_violation"))?;
            if let Some(min) = constraint.min {
                if num < min {
                    return Err(OutputContractError::new(
                        "provider_output_contract_violation",
                    ));
                }
            }
            if let Some(max) = constraint.max {
                if num > max {
                    return Err(OutputContractError::new(
                        "provider_output_contract_violation",
                    ));
                }
            }
        }
        "boolean" => {
            if !value.is_boolean() {
                return Err(OutputContractError::new(
                    "provider_output_contract_violation",
                ));
            }
        }
        "object" => {
            if !value.is_object() {
                return Err(OutputContractError::new(
                    "provider_output_contract_violation",
                ));
            }
        }
        "array" => {
            if !value.is_array() {
                return Err(OutputContractError::new(
                    "provider_output_contract_violation",
                ));
            }
        }
        _ => return Err(OutputContractError::new("output_contract_invalid")),
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FieldPath {
    Top(String),
    Nested(String, String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolCallInputKind {
    Ref,
    Inline,
}

fn normalize_contract(contract: &mut OutputContract) -> Result<(), OutputContractError> {
    if contract.schema != OUTPUT_CONTRACT_SCHEMA {
        return Err(OutputContractError::new("output_contract_invalid"));
    }
    if !is_safe_token(&contract.contract_id) {
        return Err(OutputContractError::new("output_contract_invalid"));
    }

    contract.allowed_tool_calls.sort();
    contract.allowed_tool_calls.dedup();
    for tool_id in &contract.allowed_tool_calls {
        if !is_safe_token(tool_id) {
            return Err(OutputContractError::new("output_contract_invalid"));
        }
    }

    contract.allowed_fields.sort();
    contract.allowed_fields.dedup();
    if contract.allowed_fields.is_empty() {
        return Err(OutputContractError::new("output_contract_invalid"));
    }
    for field in &contract.allowed_fields {
        if !is_safe_token(field) {
            return Err(OutputContractError::new("output_contract_invalid"));
        }
    }

    contract.required_fields.sort();
    contract.required_fields.dedup();
    for field in &contract.required_fields {
        if !is_safe_token(field) {
            return Err(OutputContractError::new("output_contract_invalid"));
        }
        if !contract.allowed_fields.contains(field) {
            return Err(OutputContractError::new("output_contract_invalid"));
        }
    }

    for (path, constraint) in &contract.field_constraints {
        let parsed = parse_field_path(path)?;
        let top_level = match parsed {
            FieldPath::Top(ref key) => key.as_str(),
            FieldPath::Nested(ref key, _) => key.as_str(),
        };
        if !contract.allowed_fields.iter().any(|k| k == top_level) {
            return Err(OutputContractError::new("output_contract_invalid"));
        }
        if constraint.kind == "number" {
            if let (Some(min), Some(max)) = (constraint.min, constraint.max) {
                if min > max {
                    return Err(OutputContractError::new("output_contract_invalid"));
                }
            }
        } else if constraint.min.is_some() || constraint.max.is_some() {
            return Err(OutputContractError::new("output_contract_invalid"));
        }
        match constraint.kind.as_str() {
            "string" | "number" | "boolean" | "object" | "array" => {}
            _ => return Err(OutputContractError::new("output_contract_invalid")),
        }
    }

    Ok(())
}

fn parse_field_path(path: &str) -> Result<FieldPath, OutputContractError> {
    if path.trim().is_empty() {
        return Err(OutputContractError::new("output_contract_invalid"));
    }
    let parts: Vec<&str> = path.split('.').collect();
    match parts.len() {
        1 => {
            let key = parts[0].trim();
            if key.is_empty() || !is_safe_token(key) {
                Err(OutputContractError::new("output_contract_invalid"))
            } else {
                Ok(FieldPath::Top(key.to_string()))
            }
        }
        2 => {
            let parent = parts[0].trim();
            let child = parts[1].trim();
            if parent.is_empty()
                || child.is_empty()
                || !is_safe_token(parent)
                || !is_safe_token(child)
            {
                Err(OutputContractError::new("output_contract_invalid"))
            } else {
                Ok(FieldPath::Nested(parent.to_string(), child.to_string()))
            }
        }
        _ => Err(OutputContractError::new("output_contract_invalid")),
    }
}

fn output_contracts_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join("contracts")
}

fn artifact_path(runtime_root: &Path, subdir: &str, artifact_ref: &str) -> PathBuf {
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    runtime_root
        .join("artifacts")
        .join(subdir)
        .join(format!("{}.json", trimmed))
}
