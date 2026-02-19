use crate::retrieval::RetrievalResultsArtifact;
use pie_common::{canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub const LENS_CONFIG_SCHEMA: &str = "serverd.lens_config.v1";
pub const LENS_SET_SELECTED_SCHEMA: &str = "serverd.lens_set_selected.v1";
pub const LENS_OUTPUTS_SCHEMA: &str = "serverd.lens_outputs.v1";
pub const LENS_PLAN_SCHEMA: &str = "serverd.lens_plan.v1";

const DEFAULT_RECENCY_TICKS: u64 = 8;
const DEFAULT_TOP_PER_GROUP: u64 = 3;

#[derive(Debug)]
pub struct LensError {
    reason: &'static str,
    detail: Option<String>,
}

impl LensError {
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

impl std::fmt::Display for LensError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for LensError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LensConfig {
    pub schema: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_lenses: Vec<String>,
    #[serde(default)]
    pub max_output_bytes: u64,
    #[serde(default)]
    pub max_candidates: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recency_ticks: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_per_group: Option<u64>,
}

impl Default for LensConfig {
    fn default() -> Self {
        Self {
            schema: LENS_CONFIG_SCHEMA.to_string(),
            enabled: false,
            allowed_lenses: Vec::new(),
            max_output_bytes: 0,
            max_candidates: 0,
            recency_ticks: None,
            top_per_group: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LensSetSelectedArtifact {
    pub schema: String,
    pub run_id: String,
    pub request_hash: String,
    pub retrieval_results_ref: String,
    pub lens_ids: Vec<String>,
    pub params: LensParams,
    pub caps: LensCaps,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LensParams {
    pub recency_ticks: u64,
    pub top_per_group: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LensCaps {
    pub max_output_bytes: u64,
    pub max_candidates: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LensOutputsArtifact {
    pub schema: String,
    pub run_id: String,
    pub request_hash: String,
    pub retrieval_results_ref: String,
    pub lens_set_ref: String,
    pub refined_context_candidates: Vec<String>,
    pub summaries: BTreeMap<String, serde_json::Value>,
    pub limits: LensOutputLimits,
    pub output_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LensOutputLimits {
    pub bytes_written: u64,
    pub candidates_returned: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LensPlanArtifact {
    pub schema: String,
    pub built_at_tick: u64,
    pub mode_id: Option<String>,
    pub mode_policy_hash: Option<String>,
    pub lens_config_hash: String,
    pub retrieval_enabled: bool,
    pub skill_id: Option<String>,
    pub intent_kind: String,
    pub selected_lenses: Vec<String>,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LensPlanBuildOutput {
    pub artifact: LensPlanArtifact,
    pub plan_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LensId {
    DedupV1,
    RecencyV1,
    SalienceV1,
}

impl LensId {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "dedup_v1" => Some(Self::DedupV1),
            "recency_v1" => Some(Self::RecencyV1),
            "salience_v1" => Some(Self::SalienceV1),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::DedupV1 => "dedup_v1",
            Self::RecencyV1 => "recency_v1",
            Self::SalienceV1 => "salience_v1",
        }
    }
}

#[derive(Debug, Clone)]
struct CandidateMeta {
    tick_index: Option<u64>,
    namespace: String,
    reason_code: String,
    key_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GroupKey {
    namespace: String,
    reason_code: String,
    key_match: bool,
}

pub fn load_lens_config(runtime_root: &Path) -> Result<LensConfig, LensError> {
    let path = lens_config_path(runtime_root);
    if !path.exists() {
        return Ok(LensConfig::default());
    }
    let bytes = fs::read(&path)
        .map_err(|e| LensError::with_detail("lens_config_read_failed", e.to_string()))?;
    let mut config: LensConfig = serde_json::from_slice(&bytes)
        .map_err(|e| LensError::with_detail("lens_config_invalid", e.to_string()))?;
    if config.schema != LENS_CONFIG_SCHEMA {
        return Err(LensError::new("lens_config_invalid"));
    }
    normalize_lens_config(&mut config)?;
    Ok(config)
}

pub(crate) fn build_lens_set_selected(
    config: &LensConfig,
    selected_lenses: &[String],
    run_id: &str,
    request_hash: &str,
    retrieval_results_ref: &str,
) -> Result<LensSetSelectedArtifact, LensError> {
    let lens_ids = parse_lens_ids(selected_lenses)?;
    if config.enabled && lens_ids.is_empty() {
        return Err(LensError::new("lens_selection_invalid"));
    }
    Ok(LensSetSelectedArtifact {
        schema: LENS_SET_SELECTED_SCHEMA.to_string(),
        run_id: run_id.to_string(),
        request_hash: request_hash.to_string(),
        retrieval_results_ref: retrieval_results_ref.to_string(),
        lens_ids: lens_ids
            .into_iter()
            .map(|id| id.as_str().to_string())
            .collect(),
        params: LensParams {
            recency_ticks: resolved_recency_ticks(config)?,
            top_per_group: resolved_top_per_group(config)?,
        },
        caps: LensCaps {
            max_output_bytes: config.max_output_bytes,
            max_candidates: config.max_candidates,
        },
    })
}

pub(crate) fn build_lens_plan(
    tick_index: u64,
    intent_kind: &str,
    skill_id: Option<&str>,
    mode_id: Option<&str>,
    mode_policy_hash: Option<&str>,
    retrieval_enabled: bool,
    lens_config: &LensConfig,
) -> Result<Option<LensPlanBuildOutput>, LensError> {
    if intent_kind.trim().is_empty() {
        return Err(LensError::new("lens_plan_invalid"));
    }
    let lens_config_hash = hash_lens_config(lens_config)?;
    let mut reason_codes: Vec<String> = Vec::new();
    if lens_config.enabled {
        reason_codes.push("lenses_enabled".to_string());
    } else {
        reason_codes.push("lenses_disabled".to_string());
    }
    if mode_policy_hash.is_some() {
        reason_codes.push("mode_policy_applied".to_string());
    }
    if skill_id.is_some() {
        reason_codes.push("skill_selected".to_string());
    }
    reason_codes.push("intent_kind_present".to_string());

    let selected_lenses = if lens_config.enabled {
        if !retrieval_enabled {
            return Err(LensError::new("lens_requires_retrieval"));
        }
        reason_codes.push("retrieval_required_and_enabled".to_string());
        let selected = canonicalize_lens_ids(&lens_config.allowed_lenses, "lens_plan_invalid")?;
        reason_codes.push("allowed_lenses_canonicalized".to_string());
        if selected.is_empty() {
            return Err(LensError::new("lens_plan_empty_selection"));
        }
        selected
    } else {
        Vec::new()
    };
    let artifact = LensPlanArtifact {
        schema: LENS_PLAN_SCHEMA.to_string(),
        built_at_tick: tick_index,
        mode_id: mode_id.map(|value| value.to_string()),
        mode_policy_hash: mode_policy_hash.map(|value| value.to_string()),
        lens_config_hash,
        retrieval_enabled,
        skill_id: skill_id.map(|value| value.to_string()),
        intent_kind: intent_kind.to_string(),
        selected_lenses,
        reason_codes,
    };
    let value = serde_json::to_value(&artifact).map_err(|_| LensError::new("lens_plan_invalid"))?;
    let bytes = canonical_json_bytes(&value).map_err(|_| LensError::new("lens_plan_invalid"))?;
    let plan_hash = sha256_bytes(&bytes);
    Ok(Some(LensPlanBuildOutput {
        artifact,
        plan_hash,
    }))
}

pub(crate) fn execute_lens_pipeline(
    config: &LensConfig,
    lens_set_ref: &str,
    lens_set: &LensSetSelectedArtifact,
    retrieval_results: &RetrievalResultsArtifact,
    run_tick_index: u64,
    on_lens_executed: &mut dyn FnMut(&str) -> Result<(), LensError>,
) -> Result<LensOutputsArtifact, LensError> {
    if lens_set.schema != LENS_SET_SELECTED_SCHEMA {
        return Err(LensError::new("lens_selection_invalid"));
    }
    let lens_ids = parse_lens_ids(&lens_set.lens_ids)?;
    let mut candidates = retrieval_results.context_candidates.clone();
    let meta_by_ref = metadata_by_ref(retrieval_results);
    let mut summaries: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for lens_id in lens_ids {
        match lens_id {
            LensId::DedupV1 => {
                let before = candidates.len() as u64;
                candidates.sort();
                candidates.dedup();
                let after = candidates.len() as u64;
                summaries.insert(
                    lens_id.as_str().to_string(),
                    serde_json::json!({
                        "before_count": before,
                        "after_count": after,
                        "ordering": "lexicographic"
                    }),
                );
            }
            LensId::RecencyV1 => {
                let recency_ticks = lens_set.params.recency_ticks;
                let mut kept = Vec::new();
                let mut decisions = Vec::new();
                for candidate in &candidates {
                    let (keep, reason) = match meta_by_ref.get(candidate) {
                        Some(meta) => match meta.tick_index {
                            Some(tick_index) => {
                                let distance = run_tick_index.saturating_sub(tick_index);
                                if distance <= recency_ticks {
                                    (true, "within_window")
                                } else {
                                    (false, "outside_window")
                                }
                            }
                            None => (false, "tick_missing"),
                        },
                        None => (false, "meta_missing"),
                    };
                    decisions.push(serde_json::json!({
                        "ref": candidate,
                        "kept": keep,
                        "reason": reason
                    }));
                    if keep {
                        kept.push(candidate.clone());
                    }
                }
                candidates = kept;
                summaries.insert(
                    lens_id.as_str().to_string(),
                    serde_json::json!({
                        "recency_ticks": recency_ticks,
                        "kept_count": candidates.len() as u64,
                        "decisions": decisions
                    }),
                );
            }
            LensId::SalienceV1 => {
                let top_n = lens_set.params.top_per_group as usize;
                let mut counts_by_namespace: BTreeMap<String, u64> = BTreeMap::new();
                let mut groups: BTreeMap<GroupKey, Vec<String>> = BTreeMap::new();
                for candidate in &candidates {
                    let meta = meta_by_ref.get(candidate);
                    let namespace = meta
                        .map(|m| m.namespace.clone())
                        .unwrap_or_else(|| "unknown".to_string());
                    let reason_code = meta
                        .map(|m| m.reason_code.clone())
                        .unwrap_or_else(|| "unknown".to_string());
                    let key_match = meta.map(|m| m.key_match).unwrap_or(false);
                    *counts_by_namespace.entry(namespace.clone()).or_insert(0) += 1;
                    groups
                        .entry(GroupKey {
                            namespace,
                            reason_code,
                            key_match,
                        })
                        .or_default()
                        .push(candidate.clone());
                }
                let mut refined = Vec::new();
                let mut group_summaries = Vec::new();
                for (key, refs) in &mut groups {
                    let raw_count = refs.len() as u64;
                    refs.sort();
                    refs.dedup();
                    let top_refs: Vec<String> = refs.iter().take(top_n).cloned().collect();
                    group_summaries.push(serde_json::json!({
                        "namespace": key.namespace,
                        "reason_code": key.reason_code,
                        "key_match": key.key_match,
                        "count": raw_count,
                        "top_refs": top_refs
                    }));
                    refined.extend(top_refs);
                }
                candidates = refined;
                summaries.insert(
                    lens_id.as_str().to_string(),
                    serde_json::json!({
                        "top_per_group": lens_set.params.top_per_group,
                        "counts_by_namespace": counts_by_namespace,
                        "groups": group_summaries
                    }),
                );
            }
        }
        on_lens_executed(lens_id.as_str())?;
        if candidates.len() as u64 > config.max_candidates {
            return Err(LensError::new("lens_output_exceeds_max_candidates"));
        }
    }

    let mut outputs = LensOutputsArtifact {
        schema: LENS_OUTPUTS_SCHEMA.to_string(),
        run_id: lens_set.run_id.clone(),
        request_hash: lens_set.request_hash.clone(),
        retrieval_results_ref: lens_set.retrieval_results_ref.clone(),
        lens_set_ref: lens_set_ref.to_string(),
        refined_context_candidates: candidates,
        summaries,
        limits: LensOutputLimits {
            bytes_written: 0,
            candidates_returned: 0,
        },
        output_hash: String::new(),
    };
    outputs.output_hash = compute_output_hash(&outputs)?;
    let bytes = compute_output_bytes(&mut outputs)?;
    if bytes > config.max_output_bytes {
        return Err(LensError::new("lens_output_exceeds_max_bytes"));
    }
    Ok(outputs)
}

fn lens_config_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join("lenses").join("config.json")
}

fn normalize_lens_config(config: &mut LensConfig) -> Result<(), LensError> {
    let parsed_ids = canonicalize_lens_ids(&config.allowed_lenses, "lens_config_invalid")?;
    if config
        .recency_ticks
        .is_some_and(|recency_ticks| recency_ticks == 0)
    {
        return Err(LensError::new("lens_config_invalid"));
    }
    if config
        .top_per_group
        .is_some_and(|top_per_group| top_per_group == 0)
    {
        return Err(LensError::new("lens_config_invalid"));
    }
    if config.enabled
        && (config.allowed_lenses.is_empty()
            || config.max_output_bytes == 0
            || config.max_candidates == 0)
    {
        return Err(LensError::new("lens_config_invalid"));
    }
    config.allowed_lenses = parsed_ids;
    Ok(())
}

fn lens_order_key(id: LensId) -> u8 {
    match id {
        LensId::DedupV1 => 0,
        LensId::RecencyV1 => 1,
        LensId::SalienceV1 => 2,
    }
}

fn parse_lens_ids(values: &[String]) -> Result<Vec<LensId>, LensError> {
    let mut ids = Vec::new();
    for value in values {
        let id = LensId::parse(value).ok_or_else(|| LensError::new("lens_selection_invalid"))?;
        ids.push(id);
    }
    Ok(ids)
}

fn canonicalize_lens_ids(
    values: &[String],
    invalid_reason: &'static str,
) -> Result<Vec<String>, LensError> {
    let lens_ids = parse_lens_ids(values).map_err(|_| LensError::new(invalid_reason))?;
    let deduped: BTreeSet<String> = lens_ids
        .into_iter()
        .map(|id| id.as_str().to_string())
        .collect();
    let mut ordered: Vec<String> = deduped
        .iter()
        .filter_map(|id| LensId::parse(id))
        .map(|id| id.as_str().to_string())
        .collect();
    ordered.sort_by_key(|id| LensId::parse(id).map(lens_order_key).unwrap_or(255u8));
    Ok(ordered)
}

fn hash_lens_config(config: &LensConfig) -> Result<String, LensError> {
    let value = serde_json::to_value(config).map_err(|_| LensError::new("lens_plan_invalid"))?;
    let bytes = canonical_json_bytes(&value).map_err(|_| LensError::new("lens_plan_invalid"))?;
    Ok(sha256_bytes(&bytes))
}

fn resolved_recency_ticks(config: &LensConfig) -> Result<u64, LensError> {
    let value = config.recency_ticks.unwrap_or(DEFAULT_RECENCY_TICKS);
    if value == 0 {
        return Err(LensError::new("lens_selection_invalid"));
    }
    Ok(value)
}

fn resolved_top_per_group(config: &LensConfig) -> Result<u64, LensError> {
    let value = config.top_per_group.unwrap_or(DEFAULT_TOP_PER_GROUP);
    if value == 0 {
        return Err(LensError::new("lens_selection_invalid"));
    }
    Ok(value)
}

fn metadata_by_ref(results: &RetrievalResultsArtifact) -> BTreeMap<String, CandidateMeta> {
    let mut map = BTreeMap::new();
    for entry in &results.results {
        map.entry(entry.ref_value.clone())
            .or_insert_with(|| CandidateMeta {
                tick_index: entry.tick_index,
                namespace: entry.namespace.clone(),
                reason_code: entry.reason_code.clone(),
                key_match: entry.reason_code == "exact_key",
            });
    }
    map
}

fn compute_output_hash(outputs: &LensOutputsArtifact) -> Result<String, LensError> {
    let value = serde_json::json!({
        "run_id": outputs.run_id,
        "request_hash": outputs.request_hash,
        "retrieval_results_ref": outputs.retrieval_results_ref,
        "lens_set_ref": outputs.lens_set_ref,
        "refined_context_candidates": outputs.refined_context_candidates,
        "summaries": outputs.summaries
    });
    let bytes = canonical_json_bytes(&value).map_err(|_| LensError::new("lens_failed"))?;
    Ok(sha256_bytes(&bytes))
}

fn compute_output_bytes(outputs: &mut LensOutputsArtifact) -> Result<u64, LensError> {
    let candidates_returned = outputs.refined_context_candidates.len() as u64;
    let mut current_bytes = 0u64;
    for _ in 0..5 {
        outputs.limits.candidates_returned = candidates_returned;
        outputs.limits.bytes_written = current_bytes;
        let value = serde_json::to_value(&outputs).map_err(|_| LensError::new("lens_failed"))?;
        let bytes = canonical_json_bytes(&value).map_err(|_| LensError::new("lens_failed"))?;
        let next = bytes.len() as u64;
        if next == current_bytes {
            outputs.limits.bytes_written = next;
            return Ok(next);
        }
        current_bytes = next;
    }
    Err(LensError::new("lens_failed"))
}
