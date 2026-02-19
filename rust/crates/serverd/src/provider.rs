use crate::ref_utils::is_safe_token;
use crate::tools::execute::{TOOL_CALL_SCHEMA, TOOL_INPUT_NOOP_SCHEMA};
use pie_common::{canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};

pub const PROVIDER_REQUEST_SCHEMA: &str = "serverd.provider_request.v1";
pub const PROVIDER_RESPONSE_SCHEMA: &str = "serverd.provider_response.v1";
pub const PROVIDER_OUTPUT_SCHEMA: &str = "serverd.provider_output.v1";
pub const PROVIDER_INPUT_SCHEMA: &str = "serverd.provider_input.v1";
pub const PROVIDER_CONSTRAINTS_SCHEMA: &str = "serverd.provider_constraints.v1";
pub const PROVIDER_RESPONSE_ARTIFACT_SCHEMA: &str = "serverd.provider_response_artifact.v1";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProviderId(String);

impl ProviderId {
    pub fn parse(value: &str) -> Result<Self, ProviderError> {
        if is_safe_token(value) {
            Ok(Self(value.to_string()))
        } else {
            Err(ProviderError::new("provider_id_invalid"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn panic_if_provider_called() {
    let should_panic = std::env::var("MOCK_PROVIDER_PANIC_IF_CALLED")
        .map(|v| v == "1")
        .unwrap_or(false);
    assert!(!should_panic, "provider infer called unexpectedly");
}
fn mock_tool_input_path() -> String {
    std::env::var("MOCK_TOOL_INPUT_PATH").unwrap_or_else(|_| "allowed.txt".to_string())
}

fn mock_tool_tool_id() -> String {
    std::env::var("MOCK_TOOL_TOOL_ID").unwrap_or_else(|_| "tools.noop".to_string())
}

fn mock_tool_input_json() -> Option<serde_json::Value> {
    let raw = std::env::var("MOCK_TOOL_INPUT_JSON").ok()?;
    serde_json::from_str(&raw).ok()
}

fn mock_tool_emit_both_inputs() -> bool {
    std::env::var("MOCK_TOOL_BOTH_INPUTS")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn mock_port_plan_invalid_mode() -> Option<String> {
    std::env::var("MOCK_PORT_PLAN_INVALID_MODE").ok()
}

fn tool_input_ref_from_value(value: &serde_json::Value) -> Result<String, ProviderError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|_| ProviderError::new("provider_tool_input_hash_failed"))?;
    Ok(sha256_bytes(&bytes))
}

impl std::fmt::Display for ProviderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProviderRequest {
    pub schema: String,
    pub request_hash: String,
    pub purpose: String,
    pub input_ref: String,
    pub constraints_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
}

impl ProviderRequest {
    pub fn new(
        request_hash: String,
        purpose: String,
        input_ref: String,
        constraints_ref: String,
    ) -> Self {
        Self {
            schema: PROVIDER_REQUEST_SCHEMA.to_string(),
            request_hash,
            purpose,
            input_ref,
            constraints_ref,
            context_ref: None,
            prompt_ref: None,
            max_tokens: None,
            temperature: None,
        }
    }

    pub fn with_context_ref(mut self, context_ref: String) -> Self {
        self.context_ref = Some(context_ref);
        self
    }

    pub fn with_prompt_ref(mut self, prompt_ref: String) -> Self {
        self.prompt_ref = Some(prompt_ref);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProviderTokenCounts {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProviderResponse {
    pub schema: String,
    pub request_hash: String,
    pub output_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_counts: Option<ProviderTokenCounts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip)]
    pub output: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProviderResponseArtifact {
    pub schema: String,
    pub request_hash: String,
    pub provider_id: String,
    pub response: serde_json::Value,
    pub response_hash: String,
    pub created_from_run_id: String,
    pub created_from_tick_index: u64,
}

impl ProviderResponse {
    pub fn with_output(
        request_hash: String,
        output: serde_json::Value,
        model: Option<String>,
    ) -> Self {
        Self {
            schema: PROVIDER_RESPONSE_SCHEMA.to_string(),
            request_hash,
            output_ref: None,
            token_counts: None,
            model,
            output: Some(output),
        }
    }

    pub fn set_output_ref(&mut self, output_ref: String) {
        self.output_ref = Some(output_ref);
    }

    pub fn to_artifact_value(&self) -> Result<serde_json::Value, ProviderError> {
        if self.output_ref.as_deref().unwrap_or("").is_empty() {
            return Err(ProviderError::new("provider_output_ref_missing"));
        }
        serde_json::to_value(self).map_err(|_| ProviderError::new("provider_response_invalid"))
    }
}

#[derive(Debug)]
pub struct ProviderError {
    reason: &'static str,
    source: Option<std::io::Error>,
}

impl ProviderError {
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

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for ProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e as _)
    }
}

pub trait ModelProvider {
    fn id(&self) -> &str;
    fn is_available(&self) -> bool;
    fn infer(&self, req: &ProviderRequest) -> Result<ProviderResponse, ProviderError>;
}

#[derive(Debug)]
pub struct MockProvider {
    id: ProviderId,
}

impl MockProvider {
    pub fn new() -> Result<Self, ProviderError> {
        Ok(Self {
            id: ProviderId::parse("mock")?,
        })
    }
}

impl ModelProvider for MockProvider {
    fn id(&self) -> &str {
        self.id.as_str()
    }

    fn is_available(&self) -> bool {
        true
    }

    fn infer(&self, req: &ProviderRequest) -> Result<ProviderResponse, ProviderError> {
        panic_if_provider_called();
        let output = serde_json::json!({
            "schema": PROVIDER_OUTPUT_SCHEMA,
            "output": format!("mock:{}", req.request_hash),
        });
        Ok(ProviderResponse::with_output(
            req.request_hash.clone(),
            output,
            Some(self.id.as_str().to_string()),
        ))
    }
}

#[derive(Debug)]
pub struct MockPortPlanProvider {
    id: ProviderId,
}

impl MockPortPlanProvider {
    pub fn new() -> Result<Self, ProviderError> {
        Ok(Self {
            id: ProviderId::parse("mock_port_plan")?,
        })
    }
}

impl ModelProvider for MockPortPlanProvider {
    fn id(&self) -> &str {
        self.id.as_str()
    }

    fn is_available(&self) -> bool {
        true
    }

    fn infer(&self, req: &ProviderRequest) -> Result<ProviderResponse, ProviderError> {
        panic_if_provider_called();
        let output = match mock_port_plan_invalid_mode().as_deref() {
            Some("unknown_field") => serde_json::json!({
                "schema": "serverd.port_plan_provider_output.v1",
                "candidate_nodes": [],
                "candidate_invariants": [],
                "candidate_work_units": [],
                "unexpected": true
            }),
            Some("wrong_schema") => serde_json::json!({
                "schema": "serverd.port_plan_provider_output.v0",
                "candidate_nodes": [],
                "candidate_invariants": [],
                "candidate_work_units": []
            }),
            Some("non_object") => serde_json::json!("not_an_object"),
            _ => serde_json::json!({
                "schema": "serverd.port_plan_provider_output.v1",
                "candidate_nodes": [
                    {
                        "kind": "tests",
                        "target_paths": ["tests/port_repo_plan.rs"],
                        "dependencies": [{"kind": "module_map", "target_path": "src/lib.rs"}],
                        "invariant_statements": [" behavior must remain equivalent "]
                    },
                    {
                        "kind": "module_map",
                        "target_paths": ["src\\lib.rs"],
                        "dependencies": [],
                        "invariant_statements": []
                    }
                ],
                "candidate_invariants": [
                    {
                        "statement": "No workspace writes during ingest planning",
                        "scope": "repo"
                    }
                ],
                "candidate_work_units": [
                    {
                        "node": {"kind": "module_map", "target_path": "src/lib.rs"},
                        "target_path": "src\\lib.rs",
                        "acceptance_criteria": ["Capture module boundaries"]
                    },
                    {
                        "node": {"kind": "tests", "target_path": "tests/port_repo_plan.rs"},
                        "target_path": "tests/port_repo_plan.rs",
                        "acceptance_criteria": ["Assert replay-stable plan ids"]
                    }
                ]
            }),
        };
        Ok(ProviderResponse::with_output(
            req.request_hash.clone(),
            output,
            Some(self.id.as_str().to_string()),
        ))
    }
}
#[derive(Debug)]
pub struct MockToolProvider {
    id: ProviderId,
}

impl MockToolProvider {
    pub fn new() -> Result<Self, ProviderError> {
        Ok(Self {
            id: ProviderId::parse("mock_tool")?,
        })
    }
}

impl ModelProvider for MockToolProvider {
    fn id(&self) -> &str {
        self.id.as_str()
    }

    fn is_available(&self) -> bool {
        true
    }

    fn infer(&self, req: &ProviderRequest) -> Result<ProviderResponse, ProviderError> {
        panic_if_provider_called();
        let tool_id = mock_tool_tool_id();
        let input_value = mock_tool_input_json().unwrap_or_else(|| {
            serde_json::json!({
                "schema": TOOL_INPUT_NOOP_SCHEMA,
                "path": mock_tool_input_path()
            })
        });
        let input_ref = if mock_tool_emit_both_inputs() {
            Some(tool_input_ref_from_value(&input_value)?)
        } else {
            None
        };
        let output = serde_json::json!({
            "schema": PROVIDER_OUTPUT_SCHEMA,
            "output": format!("mock_tool:{}", req.request_hash),
            "tool_call": {
                "schema": TOOL_CALL_SCHEMA,
                "tool_id": tool_id,
                "input": input_value,
                "request_hash": req.request_hash
            }
        });
        let mut output = output;
        if let Some(input_ref) = input_ref {
            if let Some(tool_call) = output.get_mut("tool_call") {
                if let Some(tool_call_obj) = tool_call.as_object_mut() {
                    tool_call_obj.insert("input_ref".to_string(), serde_json::json!(input_ref));
                }
            }
        }
        Ok(ProviderResponse::with_output(
            req.request_hash.clone(),
            output,
            Some(self.id.as_str().to_string()),
        ))
    }
}

#[derive(Debug)]
pub struct NullProvider {
    id: ProviderId,
}

impl NullProvider {
    pub fn new() -> Result<Self, ProviderError> {
        Ok(Self {
            id: ProviderId::parse("null")?,
        })
    }
}

impl ModelProvider for NullProvider {
    fn id(&self) -> &str {
        self.id.as_str()
    }

    fn is_available(&self) -> bool {
        true
    }

    fn infer(&self, req: &ProviderRequest) -> Result<ProviderResponse, ProviderError> {
        panic_if_provider_called();
        let output = serde_json::json!({
            "schema": PROVIDER_OUTPUT_SCHEMA,
            "output": "null",
        });
        Ok(ProviderResponse::with_output(
            req.request_hash.clone(),
            output,
            Some(self.id.as_str().to_string()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pie_common::{canonical_json_bytes, sha256_bytes};

    #[test]
    fn provider_request_hash_is_deterministic() {
        let req = ProviderRequest::new(
            "sha256:request".to_string(),
            "tick".to_string(),
            "sha256:input".to_string(),
            "sha256:constraints".to_string(),
        );
        let value = serde_json::to_value(&req).expect("to value");
        let bytes = canonical_json_bytes(&value).expect("canonical bytes");
        let hash_one = sha256_bytes(&bytes);
        let bytes_two = canonical_json_bytes(&value).expect("canonical bytes two");
        let hash_two = sha256_bytes(&bytes_two);
        assert_eq!(hash_one, hash_two);
    }
}
