use super::{ToolError, ToolId, ToolSpec};
use crate::audit::{append_event, AuditEvent};
use pie_audit_log::AuditAppender;
use pie_common::{canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const TOOL_POLICY_SCHEMA: &str = "serverd.tool_policy.v1";
pub const TOOL_APPROVAL_REQUEST_SCHEMA: &str = "serverd.tool_approval_request.v1";
pub const TOOL_APPROVAL_SCHEMA: &str = "serverd.tool_approval.v1";

#[derive(Debug, Clone)]
pub struct ToolPolicyInput<'a> {
    pub tool_id: &'a ToolId,
    pub spec: &'a ToolSpec,
    #[allow(dead_code)]
    pub mode: &'a str,
    pub request_hash: &'a str,
    pub input_ref: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PolicyConfig {
    pub schema: String,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub default_allow: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            schema: TOOL_POLICY_SCHEMA.to_string(),
            allowed_tools: Vec::new(),
            default_allow: false,
        }
    }
}

#[derive(Debug, Clone)]
pub enum PolicyOutcome {
    Allowed,
    Denied { reason: &'static str },
    NeedsApproval { approval_ref: String },
    NeedsArming { reason: &'static str },
}

pub struct ToolPolicy;

impl ToolPolicy {
    pub fn check(
        input: &ToolPolicyInput,
        config: &PolicyConfig,
        runtime_root: &Path,
        audit: &mut AuditAppender,
    ) -> Result<PolicyOutcome, ToolError> {
        let gates = PolicyGates::from_env();
        Self::check_with_gates(input, config, runtime_root, audit, &gates)
    }

    fn check_with_gates(
        input: &ToolPolicyInput,
        config: &PolicyConfig,
        runtime_root: &Path,
        audit: &mut AuditAppender,
        gates: &PolicyGates,
    ) -> Result<PolicyOutcome, ToolError> {
        if !gates.tools_enabled {
            emit_tool_denied(audit, input.tool_id, "tools_disabled", input.request_hash)?;
            return Ok(PolicyOutcome::Denied {
                reason: "tools_disabled",
            });
        }

        if !is_tool_allowed(config, input.tool_id) {
            emit_tool_denied(audit, input.tool_id, "tool_not_allowed", input.request_hash)?;
            return Ok(PolicyOutcome::Denied {
                reason: "tool_not_allowed",
            });
        }

        if is_tool_arm_required(input.spec) && !gates.tools_armed {
            return Ok(PolicyOutcome::NeedsArming {
                reason: "tool_requires_arming",
            });
        }

        if input.spec.requires_approval {
            let request = approval_request_value(input)?;
            let approval_ref = approval_ref_from_request(&request)?;
            if approval_file_exists(runtime_root, &approval_ref) {
                validate_approval(runtime_root, &approval_ref, input)?;
                return Ok(PolicyOutcome::Allowed);
            }
            write_approval_request(runtime_root, &approval_ref, &request)?;
            emit_tool_approval_required(audit, input.tool_id, &approval_ref, input.request_hash)?;
            return Ok(PolicyOutcome::NeedsApproval { approval_ref });
        }

        Ok(PolicyOutcome::Allowed)
    }
}

pub fn load_policy_config(runtime_root: &Path) -> Result<PolicyConfig, ToolError> {
    let path = policy_config_path(runtime_root);
    if !path.exists() {
        return Ok(PolicyConfig::default());
    }
    let bytes =
        fs::read(&path).map_err(|e| ToolError::with_source("tool_policy_read_failed", e))?;
    let config: PolicyConfig =
        serde_json::from_slice(&bytes).map_err(|_| ToolError::new("tool_policy_invalid"))?;
    if config.schema != TOOL_POLICY_SCHEMA {
        return Err(ToolError::new("tool_policy_invalid"));
    }
    validate_policy_config(&config)?;
    Ok(config)
}

fn policy_config_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join("tools").join("policy.json")
}

fn validate_policy_config(config: &PolicyConfig) -> Result<(), ToolError> {
    validate_tool_list(&config.allowed_tools)?;
    Ok(())
}

fn validate_tool_list(entries: &[String]) -> Result<(), ToolError> {
    for entry in entries {
        if entry == "*" {
            continue;
        }
        if ToolId::parse(entry).is_err() {
            return Err(ToolError::new("tool_policy_invalid"));
        }
    }
    Ok(())
}

fn is_tool_allowed(config: &PolicyConfig, tool_id: &ToolId) -> bool {
    if config.allowed_tools.iter().any(|t| t == "*") {
        return true;
    }
    if config.allowed_tools.iter().any(|t| t == tool_id.as_str()) {
        return true;
    }
    config.default_allow
}

fn is_tool_arm_required(spec: &ToolSpec) -> bool {
    spec.requires_arming || matches!(spec.risk_level, super::RiskLevel::High)
}
fn emit_tool_denied(
    audit: &mut AuditAppender,
    tool_id: &ToolId,
    reason: &'static str,
    request_hash: &str,
) -> Result<(), ToolError> {
    emit_audit_event(
        audit,
        AuditEvent::ToolExecutionDenied {
            tool_id: tool_id.as_str().to_string(),
            reason: reason.to_string(),
            request_hash: request_hash.to_string(),
        },
    )
}

fn emit_tool_approval_required(
    audit: &mut AuditAppender,
    tool_id: &ToolId,
    approval_ref: &str,
    request_hash: &str,
) -> Result<(), ToolError> {
    emit_audit_event(
        audit,
        AuditEvent::ToolApprovalRequired {
            tool_id: tool_id.as_str().to_string(),
            approval_ref: approval_ref.to_string(),
            request_hash: request_hash.to_string(),
        },
    )
}

fn emit_audit_event(audit: &mut AuditAppender, event: AuditEvent) -> Result<(), ToolError> {
    append_event(audit, event).map(|_| ()).map_err(|e| {
        ToolError::with_source(
            "tool_policy_audit_failed",
            std::io::Error::other(e.to_string()),
        )
    })
}

#[derive(Debug, Clone)]
struct PolicyGates {
    tools_enabled: bool,
    tools_armed: bool,
}

impl PolicyGates {
    fn from_env() -> Self {
        Self {
            tools_enabled: std::env::var("TOOLS_ENABLE")
                .map(|v| v == "1")
                .unwrap_or(false),
            tools_armed: std::env::var("TOOLS_ARM")
                .map(|v| v == "1")
                .unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct ToolApprovalRequest {
    schema: String,
    tool_id: String,
    request_hash: String,
    input_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct ToolApproval {
    schema: String,
    approval_ref: String,
    tool_id: String,
    request_hash: String,
    input_ref: String,
}

fn approval_request_value(input: &ToolPolicyInput) -> Result<serde_json::Value, ToolError> {
    let request = ToolApprovalRequest {
        schema: TOOL_APPROVAL_REQUEST_SCHEMA.to_string(),
        tool_id: input.tool_id.as_str().to_string(),
        request_hash: input.request_hash.to_string(),
        input_ref: input.input_ref.to_string(),
    };
    serde_json::to_value(&request).map_err(|_| ToolError::new("tool_approval_request_failed"))
}

fn approval_ref_from_request(value: &serde_json::Value) -> Result<String, ToolError> {
    let bytes =
        canonical_json_bytes(value).map_err(|_| ToolError::new("tool_approval_request_failed"))?;
    Ok(sha256_bytes(&bytes))
}

fn approval_file_exists(runtime_root: &Path, approval_ref: &str) -> bool {
    let path = approval_path(runtime_root, approval_ref);
    path.exists()
}

fn approval_path(runtime_root: &Path, approval_ref: &str) -> PathBuf {
    runtime_root
        .join("approvals")
        .join(format!("{}.approved.json", artifact_basename(approval_ref)))
}

fn approval_request_path(runtime_root: &Path, approval_ref: &str) -> PathBuf {
    runtime_root
        .join("artifacts")
        .join("approvals")
        .join(format!("{}.json", artifact_basename(approval_ref)))
}

fn artifact_basename(artifact_ref: &str) -> String {
    artifact_ref
        .strip_prefix("sha256:")
        .unwrap_or(artifact_ref)
        .to_string()
}

fn write_approval_request(
    runtime_root: &Path,
    approval_ref: &str,
    request: &serde_json::Value,
) -> Result<(), ToolError> {
    let bytes = canonical_json_bytes(request)
        .map_err(|_| ToolError::new("tool_approval_request_failed"))?;
    let dir = runtime_root.join("artifacts").join("approvals");
    fs::create_dir_all(&dir)
        .map_err(|e| ToolError::with_source("tool_approval_request_failed", e))?;
    let path = approval_request_path(runtime_root, approval_ref);
    if path.exists() {
        let existing = fs::read(&path)
            .map_err(|e| ToolError::with_source("tool_approval_request_failed", e))?;
        if existing != bytes {
            return Err(ToolError::new("tool_approval_request_failed"));
        }
        return Ok(());
    }
    let tmp_path = dir.join(format!("{}.tmp", artifact_basename(approval_ref)));
    let mut file = fs::File::create(&tmp_path)
        .map_err(|e| ToolError::with_source("tool_approval_request_failed", e))?;
    file.write_all(&bytes)
        .map_err(|e| ToolError::with_source("tool_approval_request_failed", e))?;
    file.sync_all()
        .map_err(|e| ToolError::with_source("tool_approval_request_failed", e))?;
    if let Err(e) = fs::rename(&tmp_path, &path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(ToolError::with_source("tool_approval_request_failed", e));
    }
    Ok(())
}

fn validate_approval(
    runtime_root: &Path,
    approval_ref: &str,
    input: &ToolPolicyInput,
) -> Result<(), ToolError> {
    let path = approval_path(runtime_root, approval_ref);
    let bytes = fs::read(&path).map_err(|e| ToolError::with_source("tool_approval_invalid", e))?;
    let approval: ToolApproval =
        serde_json::from_slice(&bytes).map_err(|_| ToolError::new("tool_approval_invalid"))?;
    if approval.schema != TOOL_APPROVAL_SCHEMA {
        return Err(ToolError::new("tool_approval_invalid"));
    }
    if approval.approval_ref != approval_ref
        || approval.tool_id != input.tool_id.as_str()
        || approval.request_hash != input.request_hash
        || approval.input_ref != input.input_ref
    {
        return Err(ToolError::new("tool_approval_invalid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::RiskLevel;
    use pie_audit_log::AuditAppender;
    use uuid::Uuid;

    fn sample_spec() -> ToolSpec {
        ToolSpec {
            schema: "serverd.tool_spec.v1".to_string(),
            id: ToolId::parse("tool.noop").expect("tool id"),
            input_schema: "serverd.tool_input.noop.v1".to_string(),
            output_schema: "serverd.tool_output.noop.v1".to_string(),
            deterministic: true,
            risk_level: RiskLevel::Low,
            requires_approval: false,
            requires_arming: false,
            filesystem: false,
            version: "v1".to_string(),
        }
    }

    fn policy_input<'a>(spec: &'a ToolSpec) -> ToolPolicyInput<'a> {
        ToolPolicyInput {
            tool_id: &spec.id,
            spec,
            mode: "route",
            request_hash: "sha256:request",
            input_ref: "sha256:input",
        }
    }
    fn audit_appender(runtime_root: &Path) -> AuditAppender {
        let path = runtime_root.join("logs").join("audit_rust.jsonl");
        AuditAppender::open(path).expect("open audit log")
    }

    fn gates(enabled: bool, armed: bool) -> PolicyGates {
        PolicyGates {
            tools_enabled: enabled,
            tools_armed: armed,
        }
    }

    #[test]
    fn policy_check_denies_when_tools_enable_missing() {
        let runtime_root = std::env::temp_dir().join(format!("pie_policy_env_{}", Uuid::new_v4()));
        let mut audit = audit_appender(&runtime_root);
        let spec = sample_spec();
        let input = policy_input(&spec);
        let config = PolicyConfig {
            schema: TOOL_POLICY_SCHEMA.to_string(),
            allowed_tools: vec![spec.id.as_str().to_string()],
            default_allow: false,
        };
        let outcome = ToolPolicy::check_with_gates(
            &input,
            &config,
            &runtime_root,
            &mut audit,
            &gates(false, false),
        )
        .expect("check");
        assert!(matches!(
            outcome,
            PolicyOutcome::Denied {
                reason: "tools_disabled"
            }
        ));
    }

    #[test]
    fn policy_check_denies_when_tool_not_allowed() {
        let runtime_root = std::env::temp_dir().join(format!("pie_policy_deny_{}", Uuid::new_v4()));
        let mut audit = audit_appender(&runtime_root);
        let spec = sample_spec();
        let input = policy_input(&spec);
        let config = PolicyConfig {
            schema: TOOL_POLICY_SCHEMA.to_string(),
            allowed_tools: Vec::new(),
            default_allow: false,
        };
        let outcome = ToolPolicy::check_with_gates(
            &input,
            &config,
            &runtime_root,
            &mut audit,
            &gates(true, false),
        )
        .expect("check");
        assert!(matches!(
            outcome,
            PolicyOutcome::Denied {
                reason: "tool_not_allowed"
            }
        ));
    }

    #[test]
    fn policy_check_needs_arming_when_required() {
        let runtime_root = std::env::temp_dir().join(format!("pie_policy_arm_{}", Uuid::new_v4()));
        let mut audit = audit_appender(&runtime_root);
        let mut spec = sample_spec();
        spec.requires_arming = true;
        let input = policy_input(&spec);
        let config = PolicyConfig {
            schema: TOOL_POLICY_SCHEMA.to_string(),
            allowed_tools: vec![spec.id.as_str().to_string()],
            default_allow: false,
        };
        let outcome = ToolPolicy::check_with_gates(
            &input,
            &config,
            &runtime_root,
            &mut audit,
            &gates(true, false),
        )
        .expect("check");
        assert!(matches!(
            outcome,
            PolicyOutcome::NeedsArming {
                reason: "tool_requires_arming"
            }
        ));
    }

    #[test]
    fn policy_check_needs_approval_when_required_and_missing() {
        let runtime_root =
            std::env::temp_dir().join(format!("pie_policy_approval_{}", Uuid::new_v4()));
        let mut audit = audit_appender(&runtime_root);
        let mut spec = sample_spec();
        spec.requires_approval = true;
        let input = policy_input(&spec);
        let config = PolicyConfig {
            schema: TOOL_POLICY_SCHEMA.to_string(),
            allowed_tools: vec![spec.id.as_str().to_string()],
            default_allow: false,
        };
        let outcome = ToolPolicy::check_with_gates(
            &input,
            &config,
            &runtime_root,
            &mut audit,
            &gates(true, true),
        )
        .expect("check");
        let approval_ref = match outcome {
            PolicyOutcome::NeedsApproval { approval_ref } => approval_ref,
            _ => panic!("expected approval required"),
        };
        let request_path = approval_request_path(&runtime_root, &approval_ref);
        assert!(request_path.exists());
    }

    #[test]
    fn policy_check_allows_when_approval_present() {
        let runtime_root =
            std::env::temp_dir().join(format!("pie_policy_approved_{}", Uuid::new_v4()));
        let mut audit = audit_appender(&runtime_root);
        let mut spec = sample_spec();
        spec.requires_approval = true;
        let input = policy_input(&spec);
        let config = PolicyConfig {
            schema: TOOL_POLICY_SCHEMA.to_string(),
            allowed_tools: vec![spec.id.as_str().to_string()],
            default_allow: false,
        };
        let outcome = ToolPolicy::check_with_gates(
            &input,
            &config,
            &runtime_root,
            &mut audit,
            &gates(true, true),
        )
        .expect("check");
        let approval_ref = match outcome {
            PolicyOutcome::NeedsApproval { approval_ref } => approval_ref,
            _ => panic!("expected approval required"),
        };
        write_approval_file(&runtime_root, &approval_ref, &input).expect("write approval");
        let outcome = ToolPolicy::check_with_gates(
            &input,
            &config,
            &runtime_root,
            &mut audit,
            &gates(true, true),
        )
        .expect("check");
        assert!(matches!(outcome, PolicyOutcome::Allowed));
    }

    fn write_approval_file(
        runtime_root: &Path,
        approval_ref: &str,
        input: &ToolPolicyInput<'_>,
    ) -> Result<(), ToolError> {
        let approval = ToolApproval {
            schema: TOOL_APPROVAL_SCHEMA.to_string(),
            approval_ref: approval_ref.to_string(),
            tool_id: input.tool_id.as_str().to_string(),
            request_hash: input.request_hash.to_string(),
            input_ref: input.input_ref.to_string(),
        };
        let value =
            serde_json::to_value(&approval).map_err(|_| ToolError::new("tool_approval_invalid"))?;
        let bytes =
            canonical_json_bytes(&value).map_err(|_| ToolError::new("tool_approval_invalid"))?;
        let dir = runtime_root.join("approvals");
        fs::create_dir_all(&dir).map_err(|e| ToolError::with_source("tool_approval_invalid", e))?;
        let path = approval_path(runtime_root, approval_ref);
        fs::write(path, bytes).map_err(|e| ToolError::with_source("tool_approval_invalid", e))?;
        Ok(())
    }
}
