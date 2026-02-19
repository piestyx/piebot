mod schemas;
mod types;

use crate::audit::{append_event, read_audit_events, AuditEvent};
use crate::command::ProviderMode;
use crate::repo_index::{
    domain_separated_hash_ref as canonical_domain_separated_hash_ref,
    sha256_ref_to_hex as canonical_sha256_ref_to_hex, RepoIndexEvidence,
};
use crate::retrieval::{
    append_episode_to_gsama_store, GsamaEpisodeWriteInput, GsamaFeatureProfile, RetrievalConfig,
    RetrievalKind,
};
use crate::runtime::artifacts::{artifact_filename, write_json_artifact_atomic};
use crate::skills::SkillContext;
use pie_audit_log::AuditAppender;
use pie_common::canonical_json_bytes;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use self::schemas::{
    PORT_PLAN_PROVIDER_OUTPUT_SCHEMA, PORT_PLAN_REQUEST_SCHEMA, PORT_PLAN_SCHEMA,
    PORT_PLAN_SUMMARY_SCHEMA,
};
use self::types::{
    PortInvariant, PortPlanArtifact, PortPlanCandidateInvariant, PortPlanCandidateNode,
    PortPlanCandidateNodeRef, PortPlanCandidateWorkUnit, PortPlanNode, PortPlanNodeKind,
    PortPlanProviderOutput, PortPlanRequestArtifact, PortPlanRequestChunkSummary,
    PortPlanRequestFileSummary, PortPlanSummaryArtifact, RepoIdentityArtifactLite,
    RepoIndexSnapshotArtifactLite, WorkUnit,
};

const PORT_REPO_SKILL_ID: &str = "port_repo.v1";
pub(crate) const PORT_REPO_INGEST_INTENT: &str = "ingest_plan";
const REPO_IDENTITY_SCHEMA: &str = "serverd.repo_identity.v1";
const REPO_INDEX_SNAPSHOT_SCHEMA: &str = "serverd.repo_index_snapshot.v1";
const NODE_DOMAIN: &str = "port_plan_node.v1";
const INVARIANT_DOMAIN: &str = "port_invariant.v1";
const WORK_UNIT_DOMAIN: &str = "port_work_unit.v1";
const PLAN_DOMAIN: &str = "port_plan.v1";

#[derive(Debug)]
pub(crate) struct PortPlanError {
    reason: &'static str,
    detail: Option<String>,
}

impl PortPlanError {
    pub(crate) fn new(reason: &'static str) -> Self {
        Self {
            reason,
            detail: None,
        }
    }

    pub(crate) fn with_detail(reason: &'static str, detail: String) -> Self {
        Self {
            reason,
            detail: Some(detail),
        }
    }

    pub(crate) fn reason(&self) -> &'static str {
        self.reason
    }

    #[allow(dead_code)]
    pub(crate) fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl std::fmt::Display for PortPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.detail {
            Some(detail) => write!(f, "{}: {}", self.reason, detail),
            None => write!(f, "{}", self.reason),
        }
    }
}

impl std::error::Error for PortPlanError {}

#[derive(Debug, Clone)]
pub(crate) struct PortPlanGenerationResult {
    pub repo_identity_ref: String,
    pub repo_index_snapshot_ref: String,
    pub repo_identity_root_hash: String,
    pub repo_index_snapshot_root_hash: String,
    pub plan_ref: String,
    pub plan_root_hash: String,
    pub summary_ref: Option<String>,
    pub request_ref: String,
}

#[derive(Debug, Clone)]
pub(crate) struct LoadedRepoInputs {
    repo_identity_ref: String,
    repo_index_snapshot_ref: String,
    repo_identity: RepoIdentityArtifactLite,
    repo_index_snapshot: RepoIndexSnapshotArtifactLite,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
struct NodeRefKey {
    kind: PortPlanNodeKind,
    target_path: String,
}

#[derive(Debug, Clone)]
struct NormalizedNodeInput {
    kind: PortPlanNodeKind,
    targets: Vec<String>,
    dependencies: Vec<NodeRefKey>,
    invariant_statements: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct NodeHashPayload {
    repo_identity_root_hash_hex: String,
    repo_index_snapshot_root_hash_hex: String,
    kind: String,
    targets: Vec<String>,
    dependencies: Vec<NodeRefHashPayload>,
    invariant_statements: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct NodeRefHashPayload {
    kind: String,
    target_path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct InvariantHashPayload {
    repo_identity_root_hash_hex: String,
    repo_index_snapshot_root_hash_hex: String,
    scope: String,
    statement: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct WorkUnitHashPayload {
    repo_identity_root_hash_hex: String,
    repo_index_snapshot_root_hash_hex: String,
    node_id_hex: String,
    target_path: String,
    acceptance_criteria: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct PortPlanHashPayload {
    repo_identity_root_hash_hex: String,
    repo_index_snapshot_root_hash_hex: String,
    nodes: Vec<PortPlanNodeHashPayload>,
    invariants: Vec<PortInvariantHashPayload>,
    work_units: Vec<WorkUnitHashPayloadOut>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct PortPlanNodeHashPayload {
    id_hex: String,
    kind: String,
    targets: Vec<String>,
    dependencies: Vec<String>,
    invariant_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct PortInvariantHashPayload {
    id_hex: String,
    scope: String,
    statement: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct WorkUnitHashPayloadOut {
    id_hex: String,
    node_id_hex: String,
    target_path: String,
    acceptance_criteria: Vec<String>,
}

pub(crate) fn is_port_repo_ingest(skill_ctx: Option<&SkillContext>) -> bool {
    skill_ctx
        .map(|ctx| ctx.manifest.skill_id.as_str() == PORT_REPO_SKILL_ID)
        .unwrap_or(false)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn generate_port_plan_from_provider_output(
    runtime_root: &Path,
    repo_index_evidence: Option<&RepoIndexEvidence>,
    provider_output: &serde_json::Value,
    tick_index: u64,
    provider_mode: ProviderMode,
    retrieval_config: &RetrievalConfig,
    audit: &mut AuditAppender,
) -> Result<PortPlanGenerationResult, PortPlanError> {
    let inputs = load_repo_inputs(runtime_root, repo_index_evidence)?;
    let request_artifact = build_port_plan_request(&inputs);
    let request_value = serde_json::to_value(&request_artifact)
        .map_err(|_| PortPlanError::new("port_plan_build_failed"))?;
    let request_ref =
        write_json_artifact_atomic(runtime_root, "port_plan_requests", &request_value)
            .map_err(|_| PortPlanError::new("port_plan_write_failed"))?;

    let provider_payload = parse_provider_payload(provider_output)?;
    let (nodes, invariants, work_units, plan_root_hash) = canonicalize_port_plan(
        &inputs.repo_identity.root_hash,
        &inputs.repo_index_snapshot.root_hash,
        &provider_payload.candidate_nodes,
        &provider_payload.candidate_invariants,
        &provider_payload.candidate_work_units,
    )?;
    let plan_artifact = PortPlanArtifact {
        schema: PORT_PLAN_SCHEMA.to_string(),
        repo_identity_root_hash: inputs.repo_identity.root_hash.clone(),
        repo_index_snapshot_root_hash: inputs.repo_index_snapshot.root_hash.clone(),
        plan_root_hash: plan_root_hash.clone(),
        nodes: nodes.clone(),
        invariants: invariants.clone(),
        work_units: work_units.clone(),
        version: 1,
    };
    let plan_value = serde_json::to_value(&plan_artifact)
        .map_err(|_| PortPlanError::new("port_plan_build_failed"))?;
    let plan_ref = write_json_artifact_atomic(runtime_root, "port_plans", &plan_value)
        .map_err(|_| PortPlanError::new("port_plan_write_failed"))?;

    let mut node_kinds: Vec<String> = nodes
        .iter()
        .map(|node| node.kind.as_str().to_string())
        .collect();
    node_kinds.sort();
    node_kinds.dedup();
    let summary = PortPlanSummaryArtifact {
        schema: PORT_PLAN_SUMMARY_SCHEMA.to_string(),
        repo_identity_root_hash: inputs.repo_identity.root_hash.clone(),
        repo_index_snapshot_root_hash: inputs.repo_index_snapshot.root_hash.clone(),
        plan_root_hash: plan_root_hash.clone(),
        node_count: nodes.len() as u64,
        invariant_count: invariants.len() as u64,
        work_unit_count: work_units.len() as u64,
        node_kinds,
    };
    let summary_value =
        serde_json::to_value(&summary).map_err(|_| PortPlanError::new("port_plan_build_failed"))?;
    let summary_ref =
        write_json_artifact_atomic(runtime_root, "port_plan_summaries", &summary_value)
            .map_err(|_| PortPlanError::new("port_plan_write_failed"))?;

    append_event(
        audit,
        AuditEvent::PortPlanRequestWritten {
            artifact_ref: request_ref.clone(),
        },
    )
    .map_err(|e| PortPlanError::with_detail("port_plan_audit_failed", e.to_string()))?;
    append_event(
        audit,
        AuditEvent::PortPlanWritten {
            plan_root_hash: plan_root_hash.clone(),
            artifact_ref: plan_ref.clone(),
            request_ref: request_ref.clone(),
            repo_identity_root_hash: inputs.repo_identity.root_hash.clone(),
            repo_index_snapshot_root_hash: inputs.repo_index_snapshot.root_hash.clone(),
            node_count: nodes.len() as u64,
            invariant_count: invariants.len() as u64,
            work_unit_count: work_units.len() as u64,
        },
    )
    .map_err(|e| PortPlanError::with_detail("port_plan_audit_failed", e.to_string()))?;
    append_event(
        audit,
        AuditEvent::PortPlanSummaryWritten {
            artifact_ref: summary_ref.clone(),
        },
    )
    .map_err(|e| PortPlanError::with_detail("port_plan_audit_failed", e.to_string()))?;

    let gsama_context = PortPlanGsamaContext {
        runtime_root,
        tick_index,
        provider_mode,
        retrieval_config,
        repo_identity_root_hash: &inputs.repo_identity.root_hash,
        repo_index_snapshot_root_hash: &inputs.repo_index_snapshot.root_hash,
        plan_ref: &plan_ref,
    };
    append_port_plan_entries_to_gsama(&gsama_context, &nodes, &invariants, &work_units)?;

    Ok(PortPlanGenerationResult {
        repo_identity_ref: inputs.repo_identity_ref,
        repo_index_snapshot_ref: inputs.repo_index_snapshot_ref,
        repo_identity_root_hash: inputs.repo_identity.root_hash,
        repo_index_snapshot_root_hash: inputs.repo_index_snapshot.root_hash,
        plan_ref,
        plan_root_hash,
        summary_ref: Some(summary_ref),
        request_ref,
    })
}

fn parse_provider_payload(
    provider_output: &serde_json::Value,
) -> Result<PortPlanProviderOutput, PortPlanError> {
    let payload: PortPlanProviderOutput = serde_json::from_value(provider_output.clone())
        .map_err(|_| PortPlanError::new("port_plan_provider_invalid"))?;
    if payload.schema != PORT_PLAN_PROVIDER_OUTPUT_SCHEMA {
        return Err(PortPlanError::new("port_plan_provider_invalid"));
    }
    Ok(payload)
}

fn build_port_plan_request(inputs: &LoadedRepoInputs) -> PortPlanRequestArtifact {
    let mut files: Vec<PortPlanRequestFileSummary> = inputs
        .repo_identity
        .files
        .iter()
        .map(|entry| PortPlanRequestFileSummary {
            path: entry.path.clone(),
            sha256: entry.sha256.clone(),
            bytes: entry.bytes,
        })
        .collect();
    files.sort_by(|left, right| left.path.cmp(&right.path));

    let mut chunks_by_path: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for chunk in &inputs.repo_index_snapshot.chunks {
        let row = chunks_by_path.entry(chunk.path.clone()).or_insert((0, 0));
        row.0 = row.0.saturating_add(1);
        row.1 = row.1.saturating_add(chunk.len);
    }
    let chunks = chunks_by_path
        .into_iter()
        .map(
            |(path, (chunk_count, total_bytes))| PortPlanRequestChunkSummary {
                path,
                chunk_count,
                total_bytes,
            },
        )
        .collect();

    PortPlanRequestArtifact {
        schema: PORT_PLAN_REQUEST_SCHEMA.to_string(),
        intent: PORT_REPO_INGEST_INTENT.to_string(),
        repo_identity_ref: inputs.repo_identity_ref.clone(),
        repo_identity_root_hash: inputs.repo_identity.root_hash.clone(),
        repo_index_snapshot_ref: inputs.repo_index_snapshot_ref.clone(),
        repo_index_snapshot_root_hash: inputs.repo_index_snapshot.root_hash.clone(),
        files,
        chunks,
    }
}

#[allow(clippy::type_complexity)]
fn canonicalize_port_plan(
    repo_identity_root_hash: &str,
    repo_index_snapshot_root_hash: &str,
    candidate_nodes: &[PortPlanCandidateNode],
    candidate_invariants: &[PortPlanCandidateInvariant],
    candidate_work_units: &[PortPlanCandidateWorkUnit],
) -> Result<(Vec<PortPlanNode>, Vec<PortInvariant>, Vec<WorkUnit>, String), PortPlanError> {
    let repo_identity_root_hash_hex = hash_ref_to_hex(repo_identity_root_hash)?;
    let repo_index_snapshot_root_hash_hex = hash_ref_to_hex(repo_index_snapshot_root_hash)?;

    let normalized_nodes = normalize_nodes(candidate_nodes)?;
    let mut node_by_id: BTreeMap<String, NormalizedNodeInput> = BTreeMap::new();
    for node in normalized_nodes {
        let payload = NodeHashPayload {
            repo_identity_root_hash_hex: repo_identity_root_hash_hex.clone(),
            repo_index_snapshot_root_hash_hex: repo_index_snapshot_root_hash_hex.clone(),
            kind: node.kind.as_str().to_string(),
            targets: node.targets.clone(),
            dependencies: node
                .dependencies
                .iter()
                .map(|dep| NodeRefHashPayload {
                    kind: dep.kind.as_str().to_string(),
                    target_path: dep.target_path.clone(),
                })
                .collect(),
            invariant_statements: node.invariant_statements.clone(),
        };
        let node_id = hash_ref_from_payload(NODE_DOMAIN, &payload)?;
        node_by_id.entry(node_id).or_insert(node);
    }

    let mut node_ref_to_id: BTreeMap<NodeRefKey, String> = BTreeMap::new();
    for (node_id, node) in &node_by_id {
        let key = NodeRefKey {
            kind: node.kind.clone(),
            target_path: primary_target(node)?,
        };
        if node_ref_to_id.insert(key, node_id.clone()).is_some() {
            return Err(PortPlanError::new("port_plan_provider_invalid"));
        }
    }

    let mut invariant_by_id: BTreeMap<String, PortInvariant> = BTreeMap::new();
    for invariant in normalize_invariants(candidate_invariants)? {
        let invariant_id = hash_ref_from_payload(
            INVARIANT_DOMAIN,
            &InvariantHashPayload {
                repo_identity_root_hash_hex: repo_identity_root_hash_hex.clone(),
                repo_index_snapshot_root_hash_hex: repo_index_snapshot_root_hash_hex.clone(),
                scope: invariant.scope.clone(),
                statement: invariant.statement.clone(),
            },
        )?;
        invariant_by_id
            .entry(invariant_id.clone())
            .or_insert(PortInvariant {
                id: invariant_id,
                statement: invariant.statement,
                scope: invariant.scope,
            });
    }
    for node in node_by_id.values() {
        let scope = primary_target(node)?;
        for statement in &node.invariant_statements {
            let invariant_id = hash_ref_from_payload(
                INVARIANT_DOMAIN,
                &InvariantHashPayload {
                    repo_identity_root_hash_hex: repo_identity_root_hash_hex.clone(),
                    repo_index_snapshot_root_hash_hex: repo_index_snapshot_root_hash_hex.clone(),
                    scope: scope.clone(),
                    statement: statement.clone(),
                },
            )?;
            invariant_by_id
                .entry(invariant_id.clone())
                .or_insert(PortInvariant {
                    id: invariant_id,
                    statement: statement.clone(),
                    scope: scope.clone(),
                });
        }
    }
    let invariant_lookup: BTreeMap<(String, String), String> = invariant_by_id
        .values()
        .map(|inv| ((inv.scope.clone(), inv.statement.clone()), inv.id.clone()))
        .collect();

    let mut nodes: Vec<PortPlanNode> = Vec::new();
    for (node_id, node) in node_by_id {
        let mut dependencies: Vec<String> = Vec::new();
        for dep in &node.dependencies {
            let dep_id = node_ref_to_id
                .get(dep)
                .cloned()
                .ok_or_else(|| PortPlanError::new("port_plan_provider_invalid"))?;
            dependencies.push(dep_id);
        }
        dependencies.sort();
        dependencies.dedup();

        let scope = primary_target(&node)?;
        let mut invariant_ids = Vec::new();
        for statement in &node.invariant_statements {
            let key = (scope.clone(), statement.clone());
            let invariant_id = invariant_lookup
                .get(&key)
                .cloned()
                .ok_or_else(|| PortPlanError::new("port_plan_provider_invalid"))?;
            invariant_ids.push(invariant_id);
        }
        invariant_ids.sort();
        invariant_ids.dedup();

        nodes.push(PortPlanNode {
            id: node_id,
            kind: node.kind,
            targets: node.targets,
            dependencies,
            invariant_ids,
        });
    }
    nodes.sort_by(|left, right| {
        left.kind
            .as_str()
            .cmp(right.kind.as_str())
            .then(primary_target_from_node(left).cmp(&primary_target_from_node(right)))
            .then(left.id.cmp(&right.id))
    });

    let mut invariants: Vec<PortInvariant> = invariant_by_id.into_values().collect();
    invariants.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then(left.statement.cmp(&right.statement))
            .then(left.id.cmp(&right.id))
    });

    let mut work_units_by_id: BTreeMap<String, WorkUnit> = BTreeMap::new();
    for candidate in normalize_work_units(candidate_work_units)? {
        let node_key = NodeRefKey {
            kind: candidate.node.kind.clone(),
            target_path: candidate.node.target_path.clone(),
        };
        let node_id = node_ref_to_id
            .get(&node_key)
            .cloned()
            .ok_or_else(|| PortPlanError::new("port_plan_provider_invalid"))?;
        let id = hash_ref_from_payload(
            WORK_UNIT_DOMAIN,
            &WorkUnitHashPayload {
                repo_identity_root_hash_hex: repo_identity_root_hash_hex.clone(),
                repo_index_snapshot_root_hash_hex: repo_index_snapshot_root_hash_hex.clone(),
                node_id_hex: hash_ref_to_hex(&node_id)?,
                target_path: candidate.target_path.clone(),
                acceptance_criteria: candidate.acceptance_criteria.clone(),
            },
        )?;
        work_units_by_id.entry(id.clone()).or_insert(WorkUnit {
            id,
            node_id,
            target_path: candidate.target_path,
            acceptance_criteria: candidate.acceptance_criteria,
        });
    }
    let mut work_units: Vec<WorkUnit> = work_units_by_id.into_values().collect();
    work_units.sort_by(|left, right| {
        left.node_id
            .cmp(&right.node_id)
            .then(left.target_path.cmp(&right.target_path))
            .then(left.id.cmp(&right.id))
    });

    let plan_hash_payload = PortPlanHashPayload {
        repo_identity_root_hash_hex,
        repo_index_snapshot_root_hash_hex,
        nodes: nodes
            .iter()
            .map(|node| {
                Ok(PortPlanNodeHashPayload {
                    id_hex: hash_ref_to_hex(&node.id)?,
                    kind: node.kind.as_str().to_string(),
                    targets: node.targets.clone(),
                    dependencies: node
                        .dependencies
                        .iter()
                        .map(|dep| hash_ref_to_hex(dep))
                        .collect::<Result<Vec<_>, _>>()?,
                    invariant_ids: node
                        .invariant_ids
                        .iter()
                        .map(|id| hash_ref_to_hex(id))
                        .collect::<Result<Vec<_>, _>>()?,
                })
            })
            .collect::<Result<Vec<_>, PortPlanError>>()?,
        invariants: invariants
            .iter()
            .map(|inv| {
                Ok(PortInvariantHashPayload {
                    id_hex: hash_ref_to_hex(&inv.id)?,
                    scope: inv.scope.clone(),
                    statement: inv.statement.clone(),
                })
            })
            .collect::<Result<Vec<_>, PortPlanError>>()?,
        work_units: work_units
            .iter()
            .map(|wu| {
                Ok(WorkUnitHashPayloadOut {
                    id_hex: hash_ref_to_hex(&wu.id)?,
                    node_id_hex: hash_ref_to_hex(&wu.node_id)?,
                    target_path: wu.target_path.clone(),
                    acceptance_criteria: wu.acceptance_criteria.clone(),
                })
            })
            .collect::<Result<Vec<_>, PortPlanError>>()?,
    };
    let plan_root_hash = hash_ref_from_payload(PLAN_DOMAIN, &plan_hash_payload)?;
    Ok((nodes, invariants, work_units, plan_root_hash))
}

fn normalize_nodes(
    nodes: &[PortPlanCandidateNode],
) -> Result<Vec<NormalizedNodeInput>, PortPlanError> {
    let mut out = Vec::with_capacity(nodes.len());
    for candidate in nodes {
        let targets = normalize_paths(&candidate.target_paths)?;
        let dependencies = normalize_node_refs(&candidate.dependencies)?;
        let invariant_statements = normalize_string_list(&candidate.invariant_statements)?;
        out.push(NormalizedNodeInput {
            kind: candidate.kind.clone(),
            targets,
            dependencies,
            invariant_statements,
        });
    }
    Ok(out)
}

fn normalize_invariants(
    invariants: &[PortPlanCandidateInvariant],
) -> Result<Vec<PortPlanCandidateInvariant>, PortPlanError> {
    let mut dedup = BTreeSet::new();
    let mut out = Vec::new();
    for invariant in invariants {
        let statement = normalize_text(&invariant.statement)?;
        let scope = normalize_text(&invariant.scope)?;
        if dedup.insert((scope.clone(), statement.clone())) {
            out.push(PortPlanCandidateInvariant { statement, scope });
        }
    }
    Ok(out)
}

fn normalize_work_units(
    work_units: &[PortPlanCandidateWorkUnit],
) -> Result<Vec<PortPlanCandidateWorkUnit>, PortPlanError> {
    let mut out = Vec::with_capacity(work_units.len());
    for unit in work_units {
        let node = NodeRefKey {
            kind: unit.node.kind.clone(),
            target_path: normalize_rel_path(&unit.node.target_path)?,
        };
        let target_path = normalize_rel_path(&unit.target_path)?;
        let acceptance_criteria = normalize_string_list(&unit.acceptance_criteria)?;
        out.push(PortPlanCandidateWorkUnit {
            node: PortPlanCandidateNodeRef {
                kind: node.kind,
                target_path: node.target_path,
            },
            target_path,
            acceptance_criteria,
        });
    }
    Ok(out)
}

fn normalize_node_refs(
    refs: &[PortPlanCandidateNodeRef],
) -> Result<Vec<NodeRefKey>, PortPlanError> {
    let mut values = Vec::with_capacity(refs.len());
    for item in refs {
        values.push(NodeRefKey {
            kind: item.kind.clone(),
            target_path: normalize_rel_path(&item.target_path)?,
        });
    }
    values.sort();
    values.dedup();
    Ok(values)
}

fn normalize_paths(paths: &[String]) -> Result<Vec<String>, PortPlanError> {
    let mut out = Vec::new();
    for path in paths {
        out.push(normalize_rel_path(path)?);
    }
    out.sort();
    out.dedup();
    if out.is_empty() {
        return Err(PortPlanError::new("port_plan_provider_invalid"));
    }
    Ok(out)
}

fn normalize_string_list(values: &[String]) -> Result<Vec<String>, PortPlanError> {
    let mut out = Vec::new();
    for value in values {
        out.push(normalize_text(value)?);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn normalize_text(value: &str) -> Result<String, PortPlanError> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.trim().is_empty() {
        return Err(PortPlanError::new("port_plan_provider_invalid"));
    }
    Ok(normalized)
}

fn normalize_rel_path(value: &str) -> Result<String, PortPlanError> {
    let normalized = value.trim().replace('\\', "/");
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.starts_with("./")
        || normalized.contains(':')
    {
        return Err(PortPlanError::new("port_plan_provider_invalid"));
    }
    let mut parts = Vec::new();
    for part in normalized.split('/') {
        let segment = part.trim();
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(PortPlanError::new("port_plan_provider_invalid"));
        }
        parts.push(segment.to_string());
    }
    if parts.is_empty() {
        return Err(PortPlanError::new("port_plan_provider_invalid"));
    }
    Ok(parts.join("/"))
}

fn primary_target(node: &NormalizedNodeInput) -> Result<String, PortPlanError> {
    node.targets
        .first()
        .cloned()
        .ok_or_else(|| PortPlanError::new("port_plan_provider_invalid"))
}

fn primary_target_from_node(node: &PortPlanNode) -> String {
    node.targets.first().cloned().unwrap_or_default()
}

fn hash_ref_from_payload<T: Serialize>(domain: &str, payload: &T) -> Result<String, PortPlanError> {
    let value =
        serde_json::to_value(payload).map_err(|_| PortPlanError::new("port_plan_hash_failed"))?;
    let bytes =
        canonical_json_bytes(&value).map_err(|_| PortPlanError::new("port_plan_hash_failed"))?;
    canonical_domain_separated_hash_ref(domain, &bytes)
        .map_err(|_| PortPlanError::new("port_plan_hash_failed"))
}

fn hash_ref_to_hex(value: &str) -> Result<String, PortPlanError> {
    canonical_sha256_ref_to_hex(value).map_err(|_| PortPlanError::new("port_plan_hash_failed"))
}

struct PortPlanGsamaContext<'a> {
    runtime_root: &'a Path,
    tick_index: u64,
    provider_mode: ProviderMode,
    retrieval_config: &'a RetrievalConfig,
    repo_identity_root_hash: &'a str,
    repo_index_snapshot_root_hash: &'a str,
    plan_ref: &'a str,
}

fn append_port_plan_entries_to_gsama(
    context: &PortPlanGsamaContext<'_>,
    nodes: &[PortPlanNode],
    invariants: &[PortInvariant],
    work_units: &[WorkUnit],
) -> Result<(), PortPlanError> {
    if !context.retrieval_config.enabled || context.retrieval_config.kind != RetrievalKind::Gsama {
        return Ok(());
    }
    let port_plan_ref = format!("port_plans/{}", context.plan_ref);
    let base_extra_tags = vec![
        ("port_plan_ref".to_string(), port_plan_ref.clone()),
        (
            "repo_identity_root_hash".to_string(),
            context.repo_identity_root_hash.to_string(),
        ),
        (
            "repo_index_snapshot_root_hash".to_string(),
            context.repo_index_snapshot_root_hash.to_string(),
        ),
    ];

    for invariant in invariants {
        append_episode_to_gsama_store(
            context.runtime_root,
            context.retrieval_config,
            &GsamaEpisodeWriteInput {
                text: &format!(
                    "entry_type:invariant\nentry_id:{}\nscope:{}\nstatement:{}",
                    invariant.id, invariant.scope, invariant.statement
                ),
                tick_index: context.tick_index,
                episode_ref: &format!("port_invariants/{}", invariant.id),
                context_ref: &port_plan_ref,
                intent_kind: PORT_REPO_INGEST_INTENT,
                semantic_vector: None,
                entropy: 0.0,
                feature_profile: GsamaFeatureProfile {
                    turn_index: 0.0,
                    time_since_last: 0.0,
                    write_frequency: 0.0,
                    entropy: 0.0,
                    self_state_shift_cosine: 0.0,
                    importance: 1.0,
                },
                extra_tags: with_entry_tags(&base_extra_tags, "invariant", &invariant.id),
            },
            context.provider_mode,
        )
        .map_err(|e| PortPlanError::with_detail(e.reason(), e.to_string()))?;
    }
    for node in nodes {
        append_episode_to_gsama_store(
            context.runtime_root,
            context.retrieval_config,
            &GsamaEpisodeWriteInput {
                text: &format!(
                    "entry_type:node\nentry_id:{}\nkind:{}\nprimary_target:{}",
                    node.id,
                    node.kind.as_str(),
                    primary_target_from_node(node)
                ),
                tick_index: context.tick_index,
                episode_ref: &format!("port_nodes/{}", node.id),
                context_ref: &port_plan_ref,
                intent_kind: PORT_REPO_INGEST_INTENT,
                semantic_vector: None,
                entropy: 0.0,
                feature_profile: GsamaFeatureProfile {
                    turn_index: 0.0,
                    time_since_last: 0.0,
                    write_frequency: 0.0,
                    entropy: 0.0,
                    self_state_shift_cosine: 0.0,
                    importance: 1.0,
                },
                extra_tags: with_entry_tags(&base_extra_tags, "node", &node.id),
            },
            context.provider_mode,
        )
        .map_err(|e| PortPlanError::with_detail(e.reason(), e.to_string()))?;
    }
    for work_unit in work_units {
        append_episode_to_gsama_store(
            context.runtime_root,
            context.retrieval_config,
            &GsamaEpisodeWriteInput {
                text: &format!(
                    "entry_type:work_unit\nentry_id:{}\nnode_id:{}\ntarget_path:{}",
                    work_unit.id, work_unit.node_id, work_unit.target_path
                ),
                tick_index: context.tick_index,
                episode_ref: &format!("port_work_units/{}", work_unit.id),
                context_ref: &port_plan_ref,
                intent_kind: PORT_REPO_INGEST_INTENT,
                semantic_vector: None,
                entropy: 0.0,
                feature_profile: GsamaFeatureProfile {
                    turn_index: 0.0,
                    time_since_last: 0.0,
                    write_frequency: 0.0,
                    entropy: 0.0,
                    self_state_shift_cosine: 0.0,
                    importance: 1.0,
                },
                extra_tags: with_entry_tags(&base_extra_tags, "work_unit", &work_unit.id),
            },
            context.provider_mode,
        )
        .map_err(|e| PortPlanError::with_detail(e.reason(), e.to_string()))?;
    }
    Ok(())
}

fn with_entry_tags(
    base: &[(String, String)],
    entry_type: &str,
    entry_id: &str,
) -> Vec<(String, String)> {
    let mut tags = base.to_vec();
    tags.push(("entry_type".to_string(), entry_type.to_string()));
    tags.push(("entry_id".to_string(), entry_id.to_string()));
    tags
}

fn load_repo_inputs(
    runtime_root: &Path,
    repo_index_evidence: Option<&RepoIndexEvidence>,
) -> Result<LoadedRepoInputs, PortPlanError> {
    let (repo_identity_ref, repo_index_snapshot_ref) = if let Some(evidence) = repo_index_evidence {
        (
            evidence.repo_identity_ref.clone(),
            evidence.repo_index_snapshot_ref.clone(),
        )
    } else {
        load_latest_repo_index_refs_from_audit(runtime_root)?
    };
    let repo_identity: RepoIdentityArtifactLite =
        read_artifact_json(runtime_root, "repo_identity", &repo_identity_ref)?;
    if repo_identity.schema != REPO_IDENTITY_SCHEMA {
        return Err(PortPlanError::new("port_plan_repo_index_missing"));
    }
    let repo_index_snapshot: RepoIndexSnapshotArtifactLite = read_artifact_json(
        runtime_root,
        "repo_index_snapshot",
        &repo_index_snapshot_ref,
    )?;
    if repo_index_snapshot.schema != REPO_INDEX_SNAPSHOT_SCHEMA {
        return Err(PortPlanError::new("port_plan_repo_index_missing"));
    }
    if repo_index_snapshot.repo_identity_root_hash != repo_identity.root_hash {
        return Err(PortPlanError::new("port_plan_repo_index_missing"));
    }
    if let Some(evidence) = repo_index_evidence {
        if evidence.repo_identity_root_hash != repo_identity.root_hash
            || evidence.repo_index_snapshot_root_hash != repo_index_snapshot.root_hash
        {
            return Err(PortPlanError::new("port_plan_repo_index_missing"));
        }
    }
    Ok(LoadedRepoInputs {
        repo_identity_ref,
        repo_index_snapshot_ref,
        repo_identity,
        repo_index_snapshot,
    })
}

fn read_artifact_json<T: serde::de::DeserializeOwned>(
    runtime_root: &Path,
    subdir: &str,
    artifact_ref: &str,
) -> Result<T, PortPlanError> {
    let path = runtime_root
        .join("artifacts")
        .join(subdir)
        .join(artifact_filename(artifact_ref));
    let bytes = fs::read(path).map_err(|_| PortPlanError::new("port_plan_repo_index_missing"))?;
    serde_json::from_slice(&bytes).map_err(|_| PortPlanError::new("port_plan_repo_index_missing"))
}
fn load_latest_repo_index_refs_from_audit(
    runtime_root: &Path,
) -> Result<(String, String), PortPlanError> {
    let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
    let events = read_audit_events(&audit_path)
        .map_err(|_| PortPlanError::new("port_plan_repo_index_missing"))?;
    let mut latest_identity_ref: Option<String> = None;
    let mut latest_pair: Option<(String, String)> = None;
    for event in events {
        let event_type = event
            .get("event_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PortPlanError::new("port_plan_repo_index_missing"))?;
        match event_type {
            "repo_identity_written" => {
                let artifact_ref = event
                    .get("artifact_ref")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| PortPlanError::new("port_plan_repo_index_missing"))?;
                latest_identity_ref = Some(artifact_ref.to_string());
            }
            "repo_index_snapshot_written" => {
                let artifact_ref = event
                    .get("artifact_ref")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| PortPlanError::new("port_plan_repo_index_missing"))?;
                if let Some(identity_ref) = latest_identity_ref.as_ref() {
                    latest_pair = Some((identity_ref.clone(), artifact_ref.to_string()));
                }
            }
            _ => {}
        }
    }
    latest_pair.ok_or_else(|| PortPlanError::new("port_plan_repo_index_missing"))
}
