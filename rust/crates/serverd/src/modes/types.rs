use crate::runtime::artifacts::artifact_filename;
use crate::lenses::LensConfig;
use crate::prompt::{PromptTemplateArtifact, PROMPT_TEMPLATE_SCHEMA};
use crate::ref_utils::{is_safe_token, split_ref_parts_with_default};
use crate::retrieval::RetrievalConfig;
use crate::tools::{ToolId, ToolRegistry};
use pie_common::{canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub const MODE_CONFIG_SCHEMA: &str = "serverd.mode_config.v1";
pub const MODE_PROFILE_SCHEMA: &str = "serverd.mode_profile.v1";
pub const MODE_APPLIED_SCHEMA: &str = "serverd.mode_applied.v1";
pub const MODE_ROUTE_SCHEMA: &str = "serverd.mode_route.v1";

const DEFAULT_MODE_ID: &str = "default";
const DEFAULT_LENS_RECENCY_TICKS: u64 = 8;
const DEFAULT_LENS_TOP_PER_GROUP: u64 = 3;

#[derive(Debug)]
pub struct ModeError {
    reason: &'static str,
    detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ModeRetrievalPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_namespaces: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_items: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ModeLensPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_lenses: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forbid_lenses: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_candidates: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<u64>,
}

impl ModeError {
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

impl std::fmt::Display for ModeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for ModeError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ModeConfig {
    pub schema: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_mode_id")]
    pub default_mode: String,
    #[serde(default)]
    pub allowed_modes: Vec<String>,
    #[serde(default)]
    pub max_profile_bytes: u64,
}

impl Default for ModeConfig {
    fn default() -> Self {
        Self {
            schema: MODE_CONFIG_SCHEMA.to_string(),
            enabled: false,
            default_mode: DEFAULT_MODE_ID.to_string(),
            allowed_modes: Vec::new(),
            max_profile_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ModeRouteConfig {
    pub schema: String,
    #[serde(default)]
    pub by_skill: BTreeMap<String, String>,
}

impl Default for ModeRouteConfig {
    fn default() -> Self {
        Self {
            schema: MODE_ROUTE_SCHEMA.to_string(),
            by_skill: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoadedModeRouteConfig {
    pub config: ModeRouteConfig,
    pub loaded_from_file: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ModeProfile {
    pub schema: String,
    pub mode_id: String,
    #[serde(default)]
    pub bias: ModeBias,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieval_policy: Option<ModeRetrievalPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lens_policy: Option<ModeLensPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ModeBias {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieval: Option<ModeRetrievalBias>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lenses: Option<ModeLensesBias>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<ModePromptBias>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<ModeToolsBias>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ModeRetrievalBias {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces_allowlist: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_recency_ticks: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ModeLensesBias {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_lenses: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recency_ticks: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_per_group: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_candidates: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ModePromptBias {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ModeToolsBias {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_tools: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_approval_tools: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_arming_tools: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ModeToolConstraints {
    #[serde(default)]
    pub deny_tools: Vec<String>,
    #[serde(default)]
    pub require_approval_tools: Vec<String>,
    #[serde(default)]
    pub require_arming_tools: Vec<String>,
}

impl ModeToolConstraints {
    pub fn is_denied(&self, tool_id: &str) -> bool {
        self.deny_tools.iter().any(|value| value == tool_id)
    }

    pub fn requires_approval(&self, tool_id: &str) -> bool {
        self.require_approval_tools
            .iter()
            .any(|value| value == tool_id)
    }

    pub fn requires_arming(&self, tool_id: &str) -> bool {
        self.require_arming_tools
            .iter()
            .any(|value| value == tool_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ModeAppliedArtifact {
    pub schema: String,
    pub mode_id: String,
    pub retrieval_config: RetrievalConfig,
    pub lens_config: LensConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieval_policy: Option<ModeRetrievalPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lens_policy: Option<ModeLensPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode_policy_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_template_ref: Option<String>,
    pub tool_constraints: ModeToolConstraints,
    pub mode_hash: String,
}

#[derive(Debug, Clone)]
pub struct EffectiveMode {
    pub mode_id: String,
    pub retrieval_config: RetrievalConfig,
    pub lens_config: LensConfig,
    pub mode_policy_hash: Option<String>,
    pub prompt_template_ref: Option<String>,
    pub tool_constraints: ModeToolConstraints,
    pub mode_hash: String,
    pub applied_artifact: ModeAppliedArtifact,
}

#[derive(Debug, Clone)]
pub struct ModeApplyInput<'a> {
    pub runtime_root: &'a Path,
    pub base_retrieval: &'a RetrievalConfig,
    pub base_lenses: &'a LensConfig,
    pub base_prompt_template_refs: &'a [String],
}

