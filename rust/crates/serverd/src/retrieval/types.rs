use crate::runtime::artifacts::{artifact_filename, write_json_artifact_atomic};
use crate::command::ProviderMode;
use crate::memory::{
    list_episode_chain, load_memory_config, load_working_memory, open_memory_enabled, read_episode,
};
use crate::ref_utils::{
    is_safe_token, normalize_ref, split_explicit_ref, split_ref_parts_with_default,
};
use gsama_encoder::{
    DynamicalInput, EncoderError, HashEmbedder, MultiViewEncoder, SalienceInput,
    SemanticVectorArtifact, TextEmbedder, NON_SEMANTIC_DIM, SEMANTIC_VECTOR_SCHEMA,
};
use pie_common::{canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const RETRIEVAL_CONFIG_SCHEMA: &str = "serverd.retrieval_config.v1";
pub const RETRIEVAL_QUERY_SCHEMA: &str = "serverd.retrieval_query.v1";
pub const RETRIEVAL_RESULTS_SCHEMA: &str = "serverd.retrieval_results.v1";
pub const CONTEXT_POINTER_SCHEMA: &str = "serverd.context_pointer.v1";
pub const CONTEXT_POINTER_WRITE_FAILED: &str = "context_pointer_write_failed";
pub const GSAMA_WRITE_INPUT_INVALID: &str = "gsama_write_input_invalid";
const GSAMA_WRITE_MAX_EXTRA_TAGS: usize = 64;
pub const GSAMA_VECTOR_SOURCE_HASH_FALLBACK_ONLY: &str = "hash_fallback_only";
pub const GSAMA_VECTOR_SOURCE_EXTERNAL_ONLY: &str = "external_only";
pub const GSAMA_VECTOR_SOURCE_EXTERNAL_OR_HASH_FALLBACK: &str = "external_or_hash_fallback";

#[derive(Debug)]
pub struct RetrievalError {
    reason: &'static str,
    detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct ContextPointerArtifact {
    pub schema: String,
    pub run_id: String,
    pub episode_ref: String,
    pub episode_hash: String,
    pub created_tick: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GsamaFeatureProfile {
    pub turn_index: f32,
    pub time_since_last: f32,
    pub write_frequency: f32,
    pub entropy: f32,
    pub self_state_shift_cosine: f32,
    pub importance: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GsamaVectorSourceMode {
    HashFallbackOnly,
    ExternalOnly,
    ExternalOrHashFallback,
}

impl GsamaVectorSourceMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::HashFallbackOnly => GSAMA_VECTOR_SOURCE_HASH_FALLBACK_ONLY,
            Self::ExternalOnly => GSAMA_VECTOR_SOURCE_EXTERNAL_ONLY,
            Self::ExternalOrHashFallback => GSAMA_VECTOR_SOURCE_EXTERNAL_OR_HASH_FALLBACK,
        }
    }

    fn allows_external(self) -> bool {
        matches!(self, Self::ExternalOnly | Self::ExternalOrHashFallback)
    }

    fn allows_hash_fallback(self) -> bool {
        matches!(self, Self::HashFallbackOnly | Self::ExternalOrHashFallback)
    }
}

#[derive(Debug, Clone, Copy)]
struct ExternalOnlyEmbedder {
    dim: usize,
}

impl TextEmbedder for ExternalOnlyEmbedder {
    fn embed(&self, _text: &str) -> Result<Vec<f32>, EncoderError> {
        Err(EncoderError::InvalidValue(
            "external_only_embedder_disabled",
        ))
    }

    fn dim(&self) -> usize {
        self.dim
    }
}

impl RetrievalError {
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

pub(crate) struct GsamaEpisodeWriteInput<'a> {
    pub text: &'a str,
    pub tick_index: u64,
    pub episode_ref: &'a str,
    pub context_ref: &'a str,
    pub intent_kind: &'a str,
    pub semantic_vector: Option<Vec<f32>>,
    pub entropy: f32,
    pub feature_profile: GsamaFeatureProfile,
    pub extra_tags: Vec<(String, String)>,
}

fn gsama_semantic_dim(config: &RetrievalConfig) -> Result<usize, RetrievalError> {
    config
        .gsama_vector_dim
        .checked_sub(NON_SEMANTIC_DIM)
        .filter(|dim| *dim > 0)
        .ok_or_else(|| RetrievalError::new("retrieval_config_invalid"))
}

fn validate_gsama_write_input(input: &GsamaEpisodeWriteInput<'_>) -> Result<(), RetrievalError> {
    let (context_ns, context_id) = split_explicit_ref(input.context_ref)
        .ok_or_else(|| RetrievalError::new(GSAMA_WRITE_INPUT_INVALID))?;
    let _context_ref = normalize_ref(context_ns, context_id)
        .ok_or_else(|| RetrievalError::new(GSAMA_WRITE_INPUT_INVALID))?;

    let (episode_ns, episode_id) = split_explicit_ref(input.episode_ref)
        .ok_or_else(|| RetrievalError::new(GSAMA_WRITE_INPUT_INVALID))?;
    let _episode_ref = normalize_ref(episode_ns, episode_id)
        .ok_or_else(|| RetrievalError::new(GSAMA_WRITE_INPUT_INVALID))?;
    if input.extra_tags.len() > GSAMA_WRITE_MAX_EXTRA_TAGS {
        return Err(RetrievalError::new(GSAMA_WRITE_INPUT_INVALID));
    }
    for (key, value) in &input.extra_tags {
        if !is_safe_token(key) || value.trim().is_empty() || value.contains('\n') {
            return Err(RetrievalError::new(GSAMA_WRITE_INPUT_INVALID));
        }
    }

    Ok(())
}

pub(crate) fn append_episode_to_gsama_store(
    runtime_root: &Path,
    config: &RetrievalConfig,
    input: &GsamaEpisodeWriteInput<'_>,
    provider_mode: ProviderMode,
) -> Result<(), RetrievalError> {
    validate_gsama_write_input(input)?;
    if config.gsama_store_capacity == 0 || config.gsama_vector_dim == 0 {
        return Err(RetrievalError::new("retrieval_config_invalid"));
    }
    let mut store = match load_gsama_store(runtime_root) {
        Ok(store) => {
            if store.dim() != config.gsama_vector_dim {
                return Err(RetrievalError::new("gsama_store_dim_mismatch"));
            }
            if store.capacity() != config.gsama_store_capacity {
                return Err(RetrievalError::new("gsama_store_capacity_mismatch"));
            }
            store
        }
        Err(err) if err.reason() == "gsama_store_not_found" => {
            if matches!(provider_mode, ProviderMode::Replay) {
                return Err(RetrievalError::new("replay_requires_existing_gsama_store"));
            }
            gsama_core::Store::new(config.gsama_vector_dim, config.gsama_store_capacity)
        }
        Err(err) => return Err(err),
    };
    if matches!(provider_mode, ProviderMode::Replay) {
        return Ok(());
    }
    let _semantic_dim = gsama_semantic_dim(config)?;
    let vector_mode = parse_gsama_vector_source_mode(config)?;
    let vector = build_gsama_combined_vector(
        config,
        vector_mode,
        input.text,
        input.semantic_vector.clone(),
        input.feature_profile,
        "gsama_write_vector_missing",
    )?;
    if store.dim() != vector.len() {
        return Err(RetrievalError::new("gsama_store_dim_mismatch"));
    }

    let mut tags = vec![
        ("context_ref".to_string(), input.context_ref.to_string()),
        ("episode_ref".to_string(), input.episode_ref.to_string()),
        ("intent".to_string(), input.intent_kind.to_string()),
    ];
    tags.extend(input.extra_tags.iter().cloned());
    tags.sort();
    tags.dedup();
    store
        .write(vector, tags, input.entropy, input.tick_index)
        .map_err(|e| RetrievalError::with_detail("gsama_store_write_failed", e.to_string()))?;
    save_gsama_store(runtime_root, &store)
}

impl std::fmt::Display for RetrievalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for RetrievalError {}

/// Retrieval kind: "refs" (default metadata-based) or "gsama" (vector-based)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalKind {
    #[default]
    Refs,
    Gsama,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RetrievalConfig {
    pub schema: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub kind: RetrievalKind,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub namespaces_allowlist: Vec<String>,
    #[serde(default)]
    pub max_items: u64,
    #[serde(default)]
    pub max_bytes: u64,
    #[serde(default)]
    pub default_recency_ticks: u64,
    #[serde(default)]
    pub default_tags: Vec<String>,
    #[serde(default)]
    pub gsama_vector_source_mode: String,
    #[serde(default)]
    pub gsama_allow_hash_embedder: bool,
    #[serde(default)]
    pub gsama_hash_embedder_dim: usize,
    #[serde(default)]
    pub gsama_store_capacity: usize,
    #[serde(default)]
    pub gsama_vector_dim: usize,
}

impl Default for RetrievalConfig {
    fn default() -> Self {
        Self {
            schema: RETRIEVAL_CONFIG_SCHEMA.to_string(),
            enabled: false,
            kind: RetrievalKind::Refs,
            sources: vec!["episodic".to_string(), "working".to_string()],
            namespaces_allowlist: vec!["contexts".to_string()],
            max_items: 16,
            max_bytes: 8 * 1024,
            default_recency_ticks: 16,
            default_tags: Vec::new(),
            gsama_vector_source_mode: GSAMA_VECTOR_SOURCE_HASH_FALLBACK_ONLY.to_string(),
            gsama_allow_hash_embedder: false,
            gsama_hash_embedder_dim: 64,
            gsama_store_capacity: 10_000,
            gsama_vector_dim: 74,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RetrievalQueryArtifact {
    pub schema: String,
    pub run_id: String,
    pub request_hash: String,
    pub query_kind: String,
    pub anchors: RetrievalAnchors,
    pub selectors: RetrievalSelectors,
    pub caps: RetrievalCaps,
    /// Query vector for GSAMA retrieval (required when kind=gsama)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_vector: Option<Vec<f32>>,
    /// Query semantic vector artifact reference for GSAMA retrieval
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_vector_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RetrievalAnchors {
    pub tick_index: u64,
    pub state_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RetrievalSelectors {
    #[serde(default)]
    pub namespaces: Vec<String>,
    #[serde(default)]
    pub tags_any: Vec<String>,
    pub recency_ticks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RetrievalCaps {
    pub max_items: u64,
    pub max_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RetrievalResultsArtifact {
    pub schema: String,
    pub run_id: String,
    pub request_hash: String,
    pub query_ref: String,
    pub result_set_hash: String,
    pub results: Vec<RetrievalResultEntry>,
    pub limits: RetrievalLimits,
    #[serde(default)]
    pub context_candidates: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RetrievalResultEntry {
    #[serde(rename = "ref")]
    pub ref_value: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tick_index: Option<u64>,
    pub namespace: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub score: u64,
    pub reason_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RetrievalLimits {
    pub items_returned: u64,
    pub bytes_written: u64,
}

pub(crate) struct RetrievalBuildInput<'a> {
    pub(crate) run_id: &'a str,
    pub(crate) request_hash: &'a str,
    pub(crate) query_kind: &'a str,
    pub(crate) tick_index: u64,
    pub(crate) state_hash: &'a str,
    pub(crate) task_id: Option<&'a str>,
    pub(crate) skill_id: Option<&'a str>,
    pub(crate) seed_context_refs: &'a [String],
    /// Query vector for GSAMA retrieval (optional, required when kind=gsama)
    pub(crate) query_vector: Option<Vec<f32>>,
    /// Query vector artifact reference (optional, used when query_vector is absent)
    pub(crate) query_vector_ref: Option<&'a str>,
    /// Query text used to build GSAMA query vectors when hash fallback is enabled
    pub(crate) query_text: Option<&'a str>,
    /// Optional injected semantic vector for kernel-pure external semantic input
    pub(crate) injected_semantic_vector: Option<Vec<f32>>,
    /// Dynamical features
    pub(crate) turn_index: f32,
    pub(crate) time_since_last: f32,
    pub(crate) write_frequency: f32,
    /// Salience features
    pub(crate) entropy: f32,
    pub(crate) self_state_shift_cosine: f32,
    pub(crate) importance: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SourceKind {
    Episodic,
    Working,
    OpenMemoryMirror,
}

impl SourceKind {
    fn parse(token: &str) -> Option<Self> {
        match token {
            "episodic" => Some(Self::Episodic),
            "working" => Some(Self::Working),
            "open_memory_mirror" => Some(Self::OpenMemoryMirror),
            _ => None,
        }
    }

    fn as_result_source(self) -> &'static str {
        match self {
            Self::Episodic => "episodic",
            Self::Working => "working",
            Self::OpenMemoryMirror => "open_memory",
        }
    }
}

#[derive(Debug, Clone)]
struct Candidate {
    ref_value: String,
    source: SourceKind,
    tick_index: Option<u64>,
    namespace: String,
    tags: Vec<String>,
    key_tokens: Vec<String>,
}

#[derive(Debug, Clone)]
struct RankedCandidate {
    entry: RetrievalResultEntry,
}

