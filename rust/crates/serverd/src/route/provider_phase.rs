use crate::runtime::artifacts::{
    artifact_filename, write_json_artifact_at_ref_atomic, write_json_artifact_atomic,
};
use crate::audit::{append_event, fail_run, AuditEvent};
use crate::command::ProviderMode;
use crate::context::select_context;
use crate::policy::context_policy::{enforce_context_policy, ContextPolicy};
use crate::lenses::{
    build_lens_plan, build_lens_set_selected, execute_lens_pipeline, LensConfig, LensError,
    LensOutputsArtifact, LensSetSelectedArtifact,
};
use crate::repo_index::maybe_build_repo_index;
use crate::memory::{load_episode_head, WorkingMemory};
use crate::modes::ModeToolConstraints;
use crate::output_contract::{
    read_output_from_response, validate_provider_output, OutputContractRegistry,
};
use crate::prompt::{
    PromptArtifact, PromptContextSnippet, PromptTemplateArtifact, PROMPT_SCHEMA,
    PROMPT_TEMPLATE_SCHEMA,
};
use crate::provider::{
    ModelProvider, ProviderError, ProviderRequest, ProviderResponse, ProviderResponseArtifact,
    PROVIDER_CONSTRAINTS_SCHEMA, PROVIDER_INPUT_SCHEMA, PROVIDER_REQUEST_SCHEMA,
    PROVIDER_RESPONSE_ARTIFACT_SCHEMA, PROVIDER_RESPONSE_SCHEMA,
};
use crate::redaction::{
    minimize_provider_input_with_compiled, CompiledRegexRedaction, RedactionConfig,
};
use crate::ref_utils::{normalize_ref, split_ref_parts_with_default};
use crate::retrieval::{
    append_episode_to_gsama_store, build_retrieval_query, execute_retrieval, preflight_gsama_store,
    write_context_pointer_artifact, GsamaEpisodeWriteInput, GsamaFeatureProfile,
    RetrievalBuildInput, RetrievalConfig, RetrievalKind, RetrievalResultsArtifact,
};
use crate::router::{select_provider, RouteInput, RouterConfig};
use crate::capsule::run_capsule::{RunCapsuleProvider, RunCapsuleToolIo};
use crate::capsule::run_capsule_collector::RunCapsuleCollector;
use crate::skills::{
    enforce_tool_call,
    port_repo::{generate_port_plan_from_provider_output, is_port_repo_ingest},
    SkillContext,
};
use crate::task::task_store::Intent;
use crate::tick_core::{
    hash_canonical_value, hash_observation, intent_kind, observe, task_request_hash, tick_core,
};
use crate::tools::execute::{execute_tool, parse_tool_call_from_provider_output};
use crate::tools::policy::{PolicyConfig, ToolPolicyInput};
use crate::tools::ToolRegistry;
use crate::policy::workspace::WorkspaceContext;
use pie_audit_log::AuditAppender;
use pie_common::canonical_json_bytes;
use pie_kernel_state::{load_or_init, state_hash};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub(crate) struct RouteTickOutcome {
    pub(crate) state_hash: String,
    pub(crate) request_hash: String,
    pub(crate) observation_hash: String,
    pub(crate) state_hash_before: String,
}

fn effective_prompt_template_refs(
    skill_ctx: Option<&SkillContext>,
    template_override_ref: Option<&str>,
) -> Vec<String> {
    match template_override_ref {
        Some(value) => vec![value.to_string()],
        None => skill_ctx
            .map(|ctx| ctx.manifest.prompt_template_refs.clone())
            .unwrap_or_default(),
    }
}

pub(crate) struct RedactionContext {
    pub(crate) config: RedactionConfig,
    pub(crate) compiled_regex: Vec<CompiledRegexRedaction>,
}

pub(crate) struct ContextPolicyContext {
    pub(crate) policy: ContextPolicy,
    pub(crate) policy_ref: Option<String>,
}

pub(crate) struct OutputContractContext {
    pub(crate) registry: OutputContractRegistry,
    pub(crate) loaded: BTreeSet<String>,
}
pub(crate) struct RetrievalContext {
    pub(crate) config: RetrievalConfig,
    pub(crate) config_ref: Option<String>,
}
pub(crate) struct LensContext {
    pub(crate) config: LensConfig,
    pub(crate) config_ref: Option<String>,
    pub(crate) mode_id: Option<String>,
    pub(crate) mode_policy_hash: Option<String>,
}
pub(crate) struct PromptContext {
    pub(crate) template_override_ref: Option<String>,
}
pub(crate) struct ToolPolicyContext {
    pub(crate) config: PolicyConfig,
    pub(crate) mode_constraints: ModeToolConstraints,
}

fn split_artifact_ref(
    value: &str,
    default_namespace: &str,
) -> Result<(String, String), ProviderError> {
    split_ref_parts_with_default(value, default_namespace)
        .ok_or_else(|| ProviderError::new("prompt_build_failed"))
}

fn read_artifact_json(
    runtime_root: &Path,
    namespace: &str,
    artifact_ref: &str,
) -> Result<serde_json::Value, ProviderError> {
    let filename = artifact_filename(artifact_ref);
    let path = runtime_root
        .join("artifacts")
        .join(namespace)
        .join(filename);
    let bytes = std::fs::read(&path).map_err(|_| ProviderError::new("prompt_build_failed"))?;
    let value =
        serde_json::from_slice(&bytes).map_err(|_| ProviderError::new("prompt_build_failed"))?;
    Ok(value)
}

fn namespace_allowed(policy: &ContextPolicy, namespace: &str) -> bool {
    if !policy.enabled {
        return true;
    }
    policy.allowed_namespaces.iter().any(|n| n == namespace)
}

fn is_usable_context_candidate(runtime_root: &Path, value: &str) -> bool {
    let (namespace, artifact_ref) = match split_artifact_ref(value, "contexts") {
        Ok(parts) => parts,
        Err(_) => return false,
    };
    let filename = artifact_filename(&artifact_ref);
    runtime_root
        .join("artifacts")
        .join(namespace)
        .join(filename)
        .is_file()
}

fn resolve_prompt_template_text(
    runtime_root: &Path,
    template_ref: &str,
    policy: &ContextPolicy,
) -> Result<String, ProviderError> {
    let (namespace, artifact_ref) = split_artifact_ref(template_ref, "contexts")?;
    if !namespace_allowed(policy, &namespace) {
        return Err(ProviderError::new("context_namespace_denied"));
    }
    let value = read_artifact_json(runtime_root, &namespace, &artifact_ref)?;
    let template: PromptTemplateArtifact =
        serde_json::from_value(value).map_err(|_| ProviderError::new("prompt_build_failed"))?;
    if template.schema != PROMPT_TEMPLATE_SCHEMA {
        return Err(ProviderError::new("prompt_build_failed"));
    }
    Ok(template.template_text)
}

fn resolve_context_body(
    runtime_root: &Path,
    context_ref: &str,
    policy: &ContextPolicy,
) -> Result<String, ProviderError> {
    let (namespace, artifact_ref) = split_artifact_ref(context_ref, "contexts")?;
    if !namespace_allowed(policy, &namespace) {
        return Err(ProviderError::new("context_namespace_denied"));
    }
    let value = read_artifact_json(runtime_root, &namespace, &artifact_ref)?;
    if let Ok(template) = serde_json::from_value::<PromptTemplateArtifact>(value.clone()) {
        if template.schema == PROMPT_TEMPLATE_SCHEMA {
            return Ok(template.template_text);
        }
    }
    let bytes =
        canonical_json_bytes(&value).map_err(|_| ProviderError::new("prompt_build_failed"))?;
    let body = String::from_utf8(bytes).map_err(|_| ProviderError::new("prompt_build_failed"))?;
    Ok(body)
}

fn find_provider<'a>(
    providers: &'a [Box<dyn ModelProvider>],
    provider_id: &str,
) -> Option<&'a dyn ModelProvider> {
    providers
        .iter()
        .find(|p| p.id() == provider_id)
        .map(|p| p.as_ref())
}

struct ProviderExecutionResult {
    response: ProviderResponse,
    provider_response_artifact_ref: String,
    loaded_from_artifact: bool,
}

fn provider_response_artifact_path(runtime_root: &Path, request_hash: &str) -> PathBuf {
    runtime_root
        .join("artifacts")
        .join("provider_responses")
        .join(artifact_filename(request_hash))
}

fn provider_response_value_with_output(
    response: &ProviderResponse,
) -> Result<serde_json::Value, ProviderError> {
    let output = response
        .output
        .clone()
        .ok_or_else(|| ProviderError::new("provider_output_missing"))?;
    let mut map = serde_json::Map::new();
    map.insert(
        "schema".to_string(),
        serde_json::Value::String(response.schema.clone()),
    );
    map.insert(
        "request_hash".to_string(),
        serde_json::Value::String(response.request_hash.clone()),
    );
    if let Some(token_counts) = response.token_counts.as_ref() {
        let value = serde_json::to_value(token_counts)
            .map_err(|_| ProviderError::new("provider_response_invalid"))?;
        map.insert("token_counts".to_string(), value);
    }
    if let Some(model) = response.model.as_ref() {
        map.insert("model".to_string(), serde_json::Value::String(model.clone()));
    }
    map.insert("output".to_string(), output);
    Ok(serde_json::Value::Object(map))
}

fn provider_response_from_value(value: &serde_json::Value) -> Result<ProviderResponse, ProviderError> {
    let mut response: ProviderResponse = serde_json::from_value(value.clone())
        .map_err(|_| ProviderError::new("provider_response_invalid"))?;
    let output = value
        .get("output")
        .cloned()
        .ok_or_else(|| ProviderError::new("provider_output_missing"))?;
    response.output_ref = None;
    response.output = Some(output);
    Ok(response)
}

fn write_provider_response_artifact(
    runtime_root: &Path,
    provider_id: &str,
    request_hash: &str,
    response: &ProviderResponse,
    run_id: &str,
    tick_index: u64,
) -> Result<String, ProviderError> {
    let response_value = provider_response_value_with_output(response)?;
    let response_hash =
        hash_canonical_value(&response_value).map_err(|_| ProviderError::new("provider_response_invalid"))?;
    let artifact = ProviderResponseArtifact {
        schema: PROVIDER_RESPONSE_ARTIFACT_SCHEMA.to_string(),
        request_hash: request_hash.to_string(),
        provider_id: provider_id.to_string(),
        response: response_value,
        response_hash,
        created_from_run_id: run_id.to_string(),
        created_from_tick_index: tick_index,
    };
    let artifact_value =
        serde_json::to_value(&artifact).map_err(|_| ProviderError::new("provider_response_invalid"))?;
    write_json_artifact_at_ref_atomic(
        runtime_root,
        "provider_responses",
        request_hash,
        &artifact_value,
    )
    .map_err(ProviderError::from)
}

fn load_provider_response_artifact(
    runtime_root: &Path,
    request_hash: &str,
) -> Result<ProviderResponse, ProviderError> {
    let path = provider_response_artifact_path(runtime_root, request_hash);
    let bytes = std::fs::read(path).map_err(|_| ProviderError::new("provider_replay_missing_artifact"))?;
    let artifact: ProviderResponseArtifact =
        serde_json::from_slice(&bytes).map_err(|_| ProviderError::new("provider_response_invalid"))?;
    if artifact.schema != PROVIDER_RESPONSE_ARTIFACT_SCHEMA {
        return Err(ProviderError::new("provider_response_invalid"));
    }
    if artifact.request_hash != request_hash {
        return Err(ProviderError::new("provider_response_invalid"));
    }
    let computed_hash = hash_canonical_value(&artifact.response)
        .map_err(|_| ProviderError::new("provider_response_invalid"))?;
    if computed_hash != artifact.response_hash {
        return Err(ProviderError::new("provider_response_invalid"));
    }
    let response = provider_response_from_value(&artifact.response)?;
    if response.schema != PROVIDER_RESPONSE_SCHEMA || response.request_hash != request_hash {
        return Err(ProviderError::new("provider_response_invalid"));
    }
    Ok(response)
}

fn execute_provider_with_mode(
    runtime_root: &Path,
    provider_mode: ProviderMode,
    provider: &dyn ModelProvider,
    provider_id: &str,
    request: &ProviderRequest,
    run_id: &str,
    tick_index: u64,
) -> Result<ProviderExecutionResult, ProviderError> {
    let artifact_path = provider_response_artifact_path(runtime_root, &request.request_hash);
    match provider_mode {
        ProviderMode::Replay => {
            let response = load_provider_response_artifact(runtime_root, &request.request_hash)?;
            Ok(ProviderExecutionResult {
                response,
                provider_response_artifact_ref: request.request_hash.clone(),
                loaded_from_artifact: true,
            })
        }
        ProviderMode::Record => {
            if artifact_path.is_file() {
                return Err(ProviderError::new("provider_record_conflict"));
            }
            let response = provider.infer(request)?;
            if response.schema != PROVIDER_RESPONSE_SCHEMA
                || response.request_hash != request.request_hash
            {
                return Err(ProviderError::new("provider_response_invalid"));
            }
            let provider_response_artifact_ref = write_provider_response_artifact(
                runtime_root,
                provider_id,
                &request.request_hash,
                &response,
                run_id,
                tick_index,
            )?;
            Ok(ProviderExecutionResult {
                response,
                provider_response_artifact_ref,
                loaded_from_artifact: false,
            })
        }
        ProviderMode::Live => {
            let response = provider.infer(request)?;
            if response.schema != PROVIDER_RESPONSE_SCHEMA
                || response.request_hash != request.request_hash
            {
                return Err(ProviderError::new("provider_response_invalid"));
            }
            let provider_response_artifact_ref = write_provider_response_artifact(
                runtime_root,
                provider_id,
                &request.request_hash,
                &response,
                run_id,
                tick_index,
            )?;
            Ok(ProviderExecutionResult {
                response,
                provider_response_artifact_ref,
                loaded_from_artifact: false,
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_route_tick(
    runtime_root: &Path,
    audit: &mut AuditAppender,
    audit_path: &Path,
    state_path: &Path,
    run_id: &str,
    tick_index: u64,
    task_id: Option<&str>,
    pending_count: u64,
    intent: Intent,
    router_config: &RouterConfig,
    provider_mode: ProviderMode,
    skill_ctx: Option<&SkillContext>,
    providers: &[Box<dyn ModelProvider>],
    redaction: &RedactionContext,
    retrieval: &mut RetrievalContext,
    lenses: &mut LensContext,
    prompt: &PromptContext,
    tool_policy: &ToolPolicyContext,
    context_policy: &mut ContextPolicyContext,
    output_contracts: &mut OutputContractContext,
    workspace_ctx: &WorkspaceContext,
    capsule: &mut RunCapsuleCollector,
    working_memory: &mut WorkingMemory,
    last_state_hash: &str,
) -> Result<RouteTickOutcome, Box<dyn std::error::Error>> {
    let observation = observe(runtime_root, tick_index)?;
    let observation_hash = hash_observation(&observation)?;
    let state = load_or_init(state_path)?;
    let current_hash = state_hash(&state);
    let requested_tick = tick_index;
    let request_hash = task_request_hash(
        tick_index,
        &current_hash,
        &observation_hash,
        &intent,
        requested_tick,
    )?;

    let intent_label = intent_kind(&intent);
    let route_input = RouteInput {
        mode: "route",
        tick_index,
        task_kind: Some(intent_label.as_str()),
        state_hash: Some(current_hash.as_str()),
    };
    let mut observed_files_for_vectors = observation.observed_files.clone();
    observed_files_for_vectors.sort();
    observed_files_for_vectors.dedup();
    let route_decision = match select_provider(router_config, &route_input) {
        Ok(decision) => decision,
        Err(e) => {
            fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
            unreachable!();
        }
    };
    let mut tool_output_refs: Vec<String> = Vec::new();

    let mut provider_id = route_decision.provider_id.as_str().to_string();
    let mut provider_reason = route_decision.reason.clone();
    let mut provider = find_provider(providers, &provider_id);
    let mut provider_available = provider.map(|p| p.is_available()).unwrap_or(false);
    if !provider_available {
        append_event(
            audit,
            AuditEvent::ProviderFailed {
                provider_id: provider_id.clone(),
                request_hash: request_hash.clone(),
                error: "provider_unavailable".to_string(),
            },
        )?;
        if router_config.policy.fail_if_unavailable {
            fail_run(
                audit,
                audit_path,
                runtime_root,
                last_state_hash,
                "provider_unavailable",
            )?;
            unreachable!();
        }
        provider_id = "null".to_string();
        provider_reason = "fallback".to_string();
        provider = find_provider(providers, &provider_id);
        provider_available = provider.map(|p| p.is_available()).unwrap_or(false);
        if !provider_available {
            fail_run(
                audit,
                audit_path,
                runtime_root,
                last_state_hash,
                "provider_unavailable",
            )?;
            unreachable!();
        }
    }
    append_event(
        audit,
        AuditEvent::TaskQueueScanned {
            pending: pending_count,
        },
    )?;

    append_event(
        audit,
        AuditEvent::ObservationCaptured {
            observation: observation.clone(),
        },
    )?;
    append_event(
        audit,
        AuditEvent::StateSnapshotLoaded {
            tick_index,
            state_hash: current_hash.clone(),
        },
    )?;
    append_event(
        audit,
        AuditEvent::IntentSelected {
            intent: intent.clone(),
            request_hash: request_hash.clone(),
        },
    )?;
    append_event(
        audit,
        AuditEvent::RouteSelected {
            provider_id: provider_id.clone(),
            reason: provider_reason.clone(),
            request_hash: request_hash.clone(),
        },
    )?;
    let repo_index_evidence = match maybe_build_repo_index(
        runtime_root,
        &workspace_ctx.run_workspace_root,
        provider_mode,
        audit,
    ) {
        Ok(value) => value,
        Err(e) => {
            fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
            unreachable!();
        }
    };
    let seed_context = select_context(skill_ctx);
    let prompt_template_refs =
        effective_prompt_template_refs(skill_ctx, prompt.template_override_ref.as_deref());

    let retrieval_results: Option<(RetrievalResultsArtifact, String)> = if retrieval.config.enabled
    {
        if retrieval.config_ref.is_none() {
            let value = match serde_json::to_value(&retrieval.config) {
                Ok(value) => value,
                Err(_) => {
                    append_event(
                        audit,
                        AuditEvent::RetrievalFailed {
                            request_hash: request_hash.clone(),
                            reason: "retrieval_failed".to_string(),
                        },
                    )?;
                    fail_run(
                        audit,
                        audit_path,
                        runtime_root,
                        last_state_hash,
                        "retrieval_failed",
                    )?;
                    unreachable!();
                }
            };
            let config_ref =
                match write_json_artifact_atomic(runtime_root, "retrieval_configs", &value) {
                    Ok(value) => value,
                    Err(_) => {
                        append_event(
                            audit,
                            AuditEvent::RetrievalFailed {
                                request_hash: request_hash.clone(),
                                reason: "retrieval_failed".to_string(),
                            },
                        )?;
                        fail_run(
                            audit,
                            audit_path,
                            runtime_root,
                            last_state_hash,
                            "retrieval_failed",
                        )?;
                        unreachable!();
                    }
                };
            append_event(
                audit,
                AuditEvent::RetrievalConfigLoaded {
                    config_ref: config_ref.clone(),
                },
            )?;
            retrieval.config_ref = Some(config_ref.clone());
        }
        let retrieval_query_text = format!(
            "intent:{}\nobserved_files:{}",
            intent_label,
            observed_files_for_vectors.join(",")
        );
        let query = match build_retrieval_query(
            &retrieval.config,
            &RetrievalBuildInput {
                run_id,
                request_hash: &request_hash,
                query_kind: if skill_ctx.is_some() {
                    "skill_context"
                } else {
                    "operator_search"
                },
                tick_index,
                state_hash: &current_hash,
                task_id,
                skill_id: skill_ctx.map(|ctx| ctx.manifest.skill_id.as_str()),
                seed_context_refs: &seed_context.context_refs,
                // GSAMA vector construction is controlled by retrieval config
                // (external_only / hash_fallback_only / external_or_hash_fallback).
                query_vector: None,
                query_vector_ref: None,
                query_text: Some(&retrieval_query_text),
                injected_semantic_vector: None,
                turn_index: tick_index as f32,
                time_since_last: 0.0,
                write_frequency: pending_count as f32,
                entropy: 0.0,
                self_state_shift_cosine: 0.0,
                importance: 1.0,
            },
        ) {
            Ok(query) => query,
            Err(e) => {
                append_event(
                    audit,
                    AuditEvent::RetrievalFailed {
                        request_hash: request_hash.clone(),
                        reason: e.reason().to_string(),
                    },
                )?;
                fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                unreachable!();
            }
        };
        let query_value = match serde_json::to_value(&query) {
            Ok(value) => value,
            Err(_) => {
                append_event(
                    audit,
                    AuditEvent::RetrievalFailed {
                        request_hash: request_hash.clone(),
                        reason: "retrieval_query_invalid".to_string(),
                    },
                )?;
                fail_run(
                    audit,
                    audit_path,
                    runtime_root,
                    last_state_hash,
                    "retrieval_query_invalid",
                )?;
                unreachable!();
            }
        };
        let query_ref =
            match write_json_artifact_atomic(runtime_root, "retrieval_queries", &query_value) {
                Ok(value) => value,
                Err(_) => {
                    append_event(
                        audit,
                        AuditEvent::RetrievalFailed {
                            request_hash: request_hash.clone(),
                            reason: "retrieval_failed".to_string(),
                        },
                    )?;
                    fail_run(
                        audit,
                        audit_path,
                        runtime_root,
                        last_state_hash,
                        "retrieval_failed",
                    )?;
                    unreachable!();
                }
            };
        append_event(
            audit,
            AuditEvent::RetrievalQueryWritten {
                request_hash: request_hash.clone(),
                query_ref: query_ref.clone(),
            },
        )?;
        let results = match execute_retrieval(runtime_root, &retrieval.config, &query, &query_ref) {
            Ok(results) => results,
            Err(e) => {
                append_event(
                    audit,
                    AuditEvent::RetrievalFailed {
                        request_hash: request_hash.clone(),
                        reason: e.reason().to_string(),
                    },
                )?;
                fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                unreachable!();
            }
        };
        append_event(
            audit,
            AuditEvent::RetrievalExecuted {
                request_hash: request_hash.clone(),
                results_count: results.results.len() as u64,
                result_set_hash: results.result_set_hash.clone(),
            },
        )?;
        let results_value = match serde_json::to_value(&results) {
            Ok(value) => value,
            Err(_) => {
                append_event(
                    audit,
                    AuditEvent::RetrievalFailed {
                        request_hash: request_hash.clone(),
                        reason: "retrieval_failed".to_string(),
                    },
                )?;
                fail_run(
                    audit,
                    audit_path,
                    runtime_root,
                    last_state_hash,
                    "retrieval_failed",
                )?;
                unreachable!();
            }
        };
        let results_ref =
            match write_json_artifact_atomic(runtime_root, "retrieval_results", &results_value) {
                Ok(value) => value,
                Err(_) => {
                    append_event(
                        audit,
                        AuditEvent::RetrievalFailed {
                            request_hash: request_hash.clone(),
                            reason: "retrieval_failed".to_string(),
                        },
                    )?;
                    fail_run(
                        audit,
                        audit_path,
                        runtime_root,
                        last_state_hash,
                        "retrieval_failed",
                    )?;
                    unreachable!();
                }
            };
        append_event(
            audit,
            AuditEvent::RetrievalResultsWritten {
                request_hash: request_hash.clone(),
                results_ref: results_ref.clone(),
            },
        )?;
        Some((results, results_ref))
    } else {
        None
    };
    let lens_plan = match build_lens_plan(
        tick_index,
        &intent_label,
        skill_ctx.map(|ctx| ctx.manifest.skill_id.as_str()),
        lenses.mode_id.as_deref(),
        lenses.mode_policy_hash.as_deref(),
        retrieval.config.enabled,
        &lenses.config,
    ) {
        Ok(Some(value)) => value,
        Ok(None) => unreachable!(),
        Err(e) => {
            append_event(
                audit,
                AuditEvent::LensFailed {
                    request_hash: request_hash.clone(),
                    reason: e.reason().to_string(),
                },
            )?;
            fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
            unreachable!();
        }
    };
    let lens_plan_value = match serde_json::to_value(&lens_plan.artifact) {
        Ok(value) => value,
        Err(_) => {
            append_event(
                audit,
                AuditEvent::LensFailed {
                    request_hash: request_hash.clone(),
                    reason: "lens_failed".to_string(),
                },
            )?;
            fail_run(
                audit,
                audit_path,
                runtime_root,
                last_state_hash,
                "lens_failed",
            )?;
            unreachable!();
        }
    };
    let lens_plan_ref =
        match write_json_artifact_atomic(runtime_root, "lens_plans", &lens_plan_value) {
            Ok(value) => value,
            Err(_) => {
                append_event(
                    audit,
                    AuditEvent::LensFailed {
                        request_hash: request_hash.clone(),
                        reason: "lens_failed".to_string(),
                    },
                )?;
                fail_run(
                    audit,
                    audit_path,
                    runtime_root,
                    last_state_hash,
                    "lens_failed",
                )?;
                unreachable!();
            }
        };
    append_event(
        audit,
        AuditEvent::LensPlanBuilt {
            plan_ref: lens_plan_ref,
            plan_hash: lens_plan.plan_hash.clone(),
            selected_lenses: lens_plan.artifact.selected_lenses.clone(),
        },
    )?;
    let lens_outputs: Option<LensOutputsArtifact> = if lens_plan.artifact.selected_lenses.is_empty()
    {
        None
    } else if let Some((retrieval_results, retrieval_results_ref)) = retrieval_results.as_ref() {
        if lenses.config_ref.is_none() {
            let value = match serde_json::to_value(&lenses.config) {
                Ok(value) => value,
                Err(_) => {
                    append_event(
                        audit,
                        AuditEvent::LensFailed {
                            request_hash: request_hash.clone(),
                            reason: "lens_failed".to_string(),
                        },
                    )?;
                    fail_run(
                        audit,
                        audit_path,
                        runtime_root,
                        last_state_hash,
                        "lens_failed",
                    )?;
                    unreachable!();
                }
            };
            let config_ref = match write_json_artifact_atomic(runtime_root, "lens_configs", &value)
            {
                Ok(value) => value,
                Err(_) => {
                    append_event(
                        audit,
                        AuditEvent::LensFailed {
                            request_hash: request_hash.clone(),
                            reason: "lens_failed".to_string(),
                        },
                    )?;
                    fail_run(
                        audit,
                        audit_path,
                        runtime_root,
                        last_state_hash,
                        "lens_failed",
                    )?;
                    unreachable!();
                }
            };
            append_event(
                audit,
                AuditEvent::LensConfigLoaded {
                    config_ref: config_ref.clone(),
                },
            )?;
            lenses.config_ref = Some(config_ref);
        }
        let lens_set: LensSetSelectedArtifact = match build_lens_set_selected(
            &lenses.config,
            lens_plan.artifact.selected_lenses.as_slice(),
            run_id,
            &request_hash,
            retrieval_results_ref,
        ) {
            Ok(value) => value,
            Err(e) => {
                append_event(
                    audit,
                    AuditEvent::LensFailed {
                        request_hash: request_hash.clone(),
                        reason: e.reason().to_string(),
                    },
                )?;
                fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                unreachable!();
            }
        };
        let lens_set_value = match serde_json::to_value(&lens_set) {
            Ok(value) => value,
            Err(_) => {
                append_event(
                    audit,
                    AuditEvent::LensFailed {
                        request_hash: request_hash.clone(),
                        reason: "lens_failed".to_string(),
                    },
                )?;
                fail_run(
                    audit,
                    audit_path,
                    runtime_root,
                    last_state_hash,
                    "lens_failed",
                )?;
                unreachable!();
            }
        };
        let lens_set_ref =
            match write_json_artifact_atomic(runtime_root, "lens_sets", &lens_set_value) {
                Ok(value) => value,
                Err(_) => {
                    append_event(
                        audit,
                        AuditEvent::LensFailed {
                            request_hash: request_hash.clone(),
                            reason: "lens_failed".to_string(),
                        },
                    )?;
                    fail_run(
                        audit,
                        audit_path,
                        runtime_root,
                        last_state_hash,
                        "lens_failed",
                    )?;
                    unreachable!();
                }
            };
        append_event(
            audit,
            AuditEvent::LensSetSelected {
                request_hash: request_hash.clone(),
                lens_set_ref: lens_set_ref.clone(),
            },
        )?;
        let outputs = match execute_lens_pipeline(
            &lenses.config,
            &lens_set_ref,
            &lens_set,
            retrieval_results,
            tick_index,
            &mut |lens_id: &str| {
                append_event(
                    audit,
                    AuditEvent::LensExecuted {
                        request_hash: request_hash.clone(),
                        lens_id: lens_id.to_string(),
                    },
                )
                .map(|_| ())
                .map_err(|_| LensError::new("lens_failed"))
            },
        ) {
            Ok(value) => value,
            Err(e) => {
                append_event(
                    audit,
                    AuditEvent::LensFailed {
                        request_hash: request_hash.clone(),
                        reason: e.reason().to_string(),
                    },
                )?;
                fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                unreachable!();
            }
        };
        let outputs_value = match serde_json::to_value(&outputs) {
            Ok(value) => value,
            Err(_) => {
                append_event(
                    audit,
                    AuditEvent::LensFailed {
                        request_hash: request_hash.clone(),
                        reason: "lens_failed".to_string(),
                    },
                )?;
                fail_run(
                    audit,
                    audit_path,
                    runtime_root,
                    last_state_hash,
                    "lens_failed",
                )?;
                unreachable!();
            }
        };
        let outputs_ref =
            match write_json_artifact_atomic(runtime_root, "lens_outputs", &outputs_value) {
                Ok(value) => value,
                Err(_) => {
                    append_event(
                        audit,
                        AuditEvent::LensFailed {
                            request_hash: request_hash.clone(),
                            reason: "lens_failed".to_string(),
                        },
                    )?;
                    fail_run(
                        audit,
                        audit_path,
                        runtime_root,
                        last_state_hash,
                        "lens_failed",
                    )?;
                    unreachable!();
                }
            };
        append_event(
            audit,
            AuditEvent::LensOutputsWritten {
                request_hash: request_hash.clone(),
                outputs_ref,
            },
        )?;
        Some(outputs)
    } else {
        append_event(
            audit,
            AuditEvent::LensFailed {
                request_hash: request_hash.clone(),
                reason: "lens_requires_retrieval".to_string(),
            },
        )?;
        fail_run(
            audit,
            audit_path,
            runtime_root,
            last_state_hash,
            "lens_requires_retrieval",
        )?;
        unreachable!();
    };
    let policy_ref = match context_policy.policy_ref.clone() {
        Some(existing) => existing,
        None => {
            let policy_value = match serde_json::to_value(&context_policy.policy) {
                Ok(value) => value,
                Err(_) => {
                    fail_run(
                        audit,
                        audit_path,
                        runtime_root,
                        last_state_hash,
                        "context_policy_invalid",
                    )?;
                    unreachable!();
                }
            };
            let policy_ref =
                match write_json_artifact_atomic(runtime_root, "context_policies", &policy_value)
                    .map_err(ProviderError::from)
                {
                    Ok(value) => value,
                    Err(_) => {
                        fail_run(
                            audit,
                            audit_path,
                            runtime_root,
                            last_state_hash,
                            "context_policy_write_failed",
                        )?;
                        unreachable!();
                    }
                };
            append_event(
                audit,
                AuditEvent::ContextPolicyLoaded {
                    policy_ref: policy_ref.clone(),
                },
            )?;
            context_policy.policy_ref = Some(policy_ref.clone());
            policy_ref
        }
    };
    capsule.set_context_policy_ref(policy_ref.clone());
    let mut context_selection = seed_context;
    let candidate_refs: Option<&[String]> = if let Some(outputs) = lens_outputs.as_ref() {
        Some(outputs.refined_context_candidates.as_slice())
    } else if let Some((results, _)) = retrieval_results.as_ref() {
        Some(results.context_candidates.as_slice())
    } else {
        None
    };
    if let Some(candidate_refs) = candidate_refs {
        for candidate in candidate_refs {
            if !is_usable_context_candidate(runtime_root, candidate) {
                continue;
            }
            if context_selection
                .context_refs
                .iter()
                .any(|existing| existing == candidate)
            {
                continue;
            }
            context_selection.context_refs.push(candidate.clone());
        }
    }
    let context_selection =
        match enforce_context_policy(context_selection, &context_policy.policy, skill_ctx) {
            Ok(selection) => selection,
            Err(e) => {
                fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                unreachable!();
            }
        };
    let context_value = match serde_json::to_value(&context_selection) {
        Ok(value) => value,
        Err(_) => {
            append_event(
                audit,
                AuditEvent::ProviderFailed {
                    provider_id: provider_id.clone(),
                    request_hash: request_hash.clone(),
                    error: "context_selection_invalid".to_string(),
                },
            )?;
            fail_run(
                audit,
                audit_path,
                runtime_root,
                last_state_hash,
                "context_selection_invalid",
            )?;
            unreachable!();
        }
    };
    let context_ref = match write_json_artifact_atomic(runtime_root, "contexts", &context_value)
        .map_err(ProviderError::from)
    {
        Ok(value) => value,
        Err(e) => {
            append_event(
                audit,
                AuditEvent::ProviderFailed {
                    provider_id: provider_id.clone(),
                    request_hash: request_hash.clone(),
                    error: e.reason().to_string(),
                },
            )?;
            fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
            unreachable!();
        }
    };
    append_event(
        audit,
        AuditEvent::ContextSelected {
            request_hash: request_hash.clone(),
            context_ref: context_ref.clone(),
        },
    )?;
    capsule.add_context_ref(context_ref.clone());
    let prompt_value = {
        let prompt_templates = prompt_template_refs.clone();
        let skill_id = skill_ctx.map(|ctx| ctx.manifest.skill_id.clone());
        let mut template_texts = Vec::with_capacity(prompt_templates.len());
        for template_ref in &prompt_templates {
            let text = match resolve_prompt_template_text(
                runtime_root,
                template_ref,
                &context_policy.policy,
            ) {
                Ok(value) => value,
                Err(e) => {
                    fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                    unreachable!();
                }
            };
            template_texts.push(text);
        }
        let mut context_snippets = Vec::with_capacity(context_selection.context_refs.len());
        for context_ref in &context_selection.context_refs {
            let body = match resolve_context_body(runtime_root, context_ref, &context_policy.policy)
            {
                Ok(value) => value,
                Err(e) => {
                    fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                    unreachable!();
                }
            };
            context_snippets.push(PromptContextSnippet {
                context_ref: context_ref.clone(),
                body,
            });
        }
        let mut rendered = String::new();
        for text in &template_texts {
            if !rendered.is_empty() {
                rendered.push('\n');
            }
            rendered.push_str(text);
        }
        for snippet in &context_snippets {
            if !rendered.is_empty() {
                rendered.push('\n');
            }
            rendered.push_str(&snippet.body);
        }
        let prompt = PromptArtifact {
            schema: PROMPT_SCHEMA.to_string(),
            request_hash: request_hash.clone(),
            intent_kind: intent_label.clone(),
            skill_id,
            prompt_template_refs: prompt_templates,
            context_ref: context_ref.clone(),
            context_refs: context_selection.context_refs.clone(),
            template_texts,
            context_snippets,
            rendered,
        };
        let value = match serde_json::to_value(&prompt) {
            Ok(value) => value,
            Err(_) => {
                fail_run(
                    audit,
                    audit_path,
                    runtime_root,
                    last_state_hash,
                    "prompt_build_failed",
                )?;
                unreachable!();
            }
        };
        if redaction.config.enabled {
            match minimize_provider_input_with_compiled(
                &value,
                &redaction.config,
                &redaction.compiled_regex,
            ) {
                Ok(redacted) => redacted,
                Err(e) => {
                    fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                    unreachable!();
                }
            }
        } else {
            value
        }
    };
    let prompt_ref = match write_json_artifact_atomic(runtime_root, "prompts", &prompt_value)
        .map_err(ProviderError::from)
    {
        Ok(value) => value,
        Err(_) => {
            fail_run(
                audit,
                audit_path,
                runtime_root,
                last_state_hash,
                "prompt_write_failed",
            )?;
            unreachable!();
        }
    };
    append_event(
        audit,
        AuditEvent::PromptBuilt {
            request_hash: request_hash.clone(),
            prompt_ref: prompt_ref.clone(),
            context_ref: context_ref.clone(),
            policy_ref: policy_ref.clone(),
        },
    )?;
    capsule.add_prompt_ref(prompt_ref.clone());
    {
        let input_value = serde_json::json!({
            "schema": PROVIDER_INPUT_SCHEMA,
            "tick_index": tick_index,
            "state_hash": current_hash,
            "observation_hash": observation_hash,
            "intent": intent.clone()
        });
        let input_ref = if redaction.config.enabled {
            let redacted = match minimize_provider_input_with_compiled(
                &input_value,
                &redaction.config,
                &redaction.compiled_regex,
            ) {
                Ok(value) => value,
                Err(e) => {
                    fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                    unreachable!();
                }
            };
            let input_ref = match write_json_artifact_atomic(runtime_root, "inputs", &redacted)
                .map_err(ProviderError::from)
            {
                Ok(value) => value,
                Err(_) => {
                    fail_run(
                        audit,
                        audit_path,
                        runtime_root,
                        last_state_hash,
                        "provider_input_write_failed",
                    )?;
                    unreachable!();
                }
            };
            append_event(
                audit,
                AuditEvent::ProviderInputRedacted {
                    request_hash: request_hash.clone(),
                    input_ref: input_ref.clone(),
                },
            )?;
            input_ref
        } else {
            match write_json_artifact_atomic(runtime_root, "inputs", &input_value)
                .map_err(ProviderError::from)
            {
                Ok(value) => value,
                Err(_) => {
                    fail_run(
                        audit,
                        audit_path,
                        runtime_root,
                        last_state_hash,
                        "provider_input_write_failed",
                    )?;
                    unreachable!();
                }
            }
        };

        let constraints_value = serde_json::json!({
            "schema": PROVIDER_CONSTRAINTS_SCHEMA,
            "rules": []
        });
        let constraints_ref =
            match write_json_artifact_atomic(runtime_root, "constraints", &constraints_value)
                .map_err(ProviderError::from)
            {
                Ok(value) => value,
                Err(e) => {
                    append_event(
                        audit,
                        AuditEvent::ProviderFailed {
                            provider_id: provider_id.clone(),
                            request_hash: request_hash.clone(),
                            error: e.reason().to_string(),
                        },
                    )?;
                    fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                    unreachable!();
                }
            };

        let request = ProviderRequest::new(
            request_hash.clone(),
            "tick".to_string(),
            input_ref,
            constraints_ref,
        )
        .with_context_ref(context_ref.clone())
        .with_prompt_ref(prompt_ref.clone());
        if request.schema != PROVIDER_REQUEST_SCHEMA {
            append_event(
                audit,
                AuditEvent::ProviderFailed {
                    provider_id: provider_id.clone(),
                    request_hash: request_hash.clone(),
                    error: "provider_request_invalid".to_string(),
                },
            )?;
            fail_run(
                audit,
                audit_path,
                runtime_root,
                last_state_hash,
                "provider_request_invalid",
            )?;
            unreachable!();
        }
        let request_value = match serde_json::to_value(&request) {
            Ok(value) => value,
            Err(_) => {
                append_event(
                    audit,
                    AuditEvent::ProviderFailed {
                        provider_id: provider_id.clone(),
                        request_hash: request_hash.clone(),
                        error: "provider_request_invalid".to_string(),
                    },
                )?;
                fail_run(
                    audit,
                    audit_path,
                    runtime_root,
                    last_state_hash,
                    "provider_request_invalid",
                )?;
                unreachable!();
            }
        };
        let request_ref = match write_json_artifact_atomic(runtime_root, "requests", &request_value)
            .map_err(ProviderError::from)
        {
            Ok(value) => value,
            Err(e) => {
                append_event(
                    audit,
                    AuditEvent::ProviderFailed {
                        provider_id: provider_id.clone(),
                        request_hash: request_hash.clone(),
                        error: e.reason().to_string(),
                    },
                )?;
                fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                unreachable!();
            }
        };
        append_event(
            audit,
            AuditEvent::ProviderRequestWritten {
                provider_id: provider_id.clone(),
                request_hash: request_hash.clone(),
                artifact_ref: request_ref.clone(),
            },
        )?;
        let provider_execution = match execute_provider_with_mode(
            runtime_root,
            provider_mode,
            provider.expect("provider available"),
            &provider_id,
            &request,
            run_id,
            tick_index,
        ) {
            Ok(value) => value,
            Err(e) => {
                if e.reason() == "provider_replay_missing_artifact" {
                    append_event(
                        audit,
                        AuditEvent::ProviderReplayMissingArtifact {
                            request_hash: request_hash.clone(),
                            expected_artifact_path: provider_response_artifact_path(
                                runtime_root,
                                &request_hash,
                            )
                            .to_string_lossy()
                            .to_string(),
                        },
                    )?;
                } else if e.reason() == "provider_record_conflict" {
                    append_event(
                        audit,
                        AuditEvent::ProviderRecordConflict {
                            request_hash: request_hash.clone(),
                            artifact_ref: request_hash.clone(),
                        },
                    )?;
                }
                append_event(
                    audit,
                    AuditEvent::ProviderFailed {
                        provider_id: provider_id.clone(),
                        request_hash: request_hash.clone(),
                        error: e.reason().to_string(),
                    },
                )?;
                fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                unreachable!();
            }
        };
        let provider_response_artifact_ref = provider_execution.provider_response_artifact_ref.clone();
        if provider_execution.loaded_from_artifact {
            append_event(
                audit,
                AuditEvent::ProviderResponseArtifactLoaded {
                    provider_id: provider_id.clone(),
                    request_hash: request_hash.clone(),
                    artifact_ref: provider_response_artifact_ref.clone(),
                },
            )?;
        } else {
            append_event(
                audit,
                AuditEvent::ProviderResponseArtifactWritten {
                    provider_id: provider_id.clone(),
                    request_hash: request_hash.clone(),
                    artifact_ref: provider_response_artifact_ref.clone(),
                },
            )?;
        }
        let mut response = provider_execution.response;

        let output_value = match response.output.take() {
            Some(value) => value,
            None => {
                append_event(
                    audit,
                    AuditEvent::ProviderFailed {
                        provider_id: provider_id.clone(),
                        request_hash: request_hash.clone(),
                        error: "provider_output_missing".to_string(),
                    },
                )?;
                fail_run(
                    audit,
                    audit_path,
                    runtime_root,
                    last_state_hash,
                    "provider_output_missing",
                )?;
                unreachable!();
            }
        };
        let output_ref = match write_json_artifact_atomic(runtime_root, "outputs", &output_value)
            .map_err(ProviderError::from)
        {
            Ok(value) => value,
            Err(e) => {
                append_event(
                    audit,
                    AuditEvent::ProviderFailed {
                        provider_id: provider_id.clone(),
                        request_hash: request_hash.clone(),
                        error: e.reason().to_string(),
                    },
                )?;
                fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                unreachable!();
            }
        };
        response.set_output_ref(output_ref.clone());
        let response_value = match response.to_artifact_value() {
            Ok(value) => value,
            Err(e) => {
                append_event(
                    audit,
                    AuditEvent::ProviderFailed {
                        provider_id: provider_id.clone(),
                        request_hash: request_hash.clone(),
                        error: e.reason().to_string(),
                    },
                )?;
                fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                unreachable!();
            }
        };
        let response_ref =
            match write_json_artifact_atomic(runtime_root, "responses", &response_value)
                .map_err(ProviderError::from)
            {
                Ok(value) => value,
                Err(e) => {
                    append_event(
                        audit,
                        AuditEvent::ProviderFailed {
                            provider_id: provider_id.clone(),
                            request_hash: request_hash.clone(),
                            error: e.reason().to_string(),
                        },
                    )?;
                    fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                    unreachable!();
                }
            };
        append_event(
            audit,
            AuditEvent::ProviderResponseWritten {
                provider_id: provider_id.clone(),
                request_hash: request_hash.clone(),
                artifact_ref: response_ref.clone(),
            },
        )?;
        capsule.add_provider(RunCapsuleProvider {
            provider_id: provider_id.clone(),
            request_ref: request_ref.clone(),
            response_ref: response_ref.clone(),
            output_ref: output_ref.clone(),
            provider_request_hash: Some(request_hash.clone()),
            provider_response_artifact_ref: Some(provider_response_artifact_ref),
        });
        let output_value = match read_output_from_response(runtime_root, &response_ref) {
            Ok(value) => value,
            Err(e) => {
                fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                unreachable!();
            }
        };
        let tool_call_present = output_value.get("tool_call").is_some();
        let contract_id = skill_ctx.and_then(|ctx| ctx.manifest.output_contract.clone());
        if let Some(contract_id) = contract_id {
            let entry = match output_contracts.registry.get(&contract_id) {
                Some(entry) => entry,
                None => {
                    append_event(
                        audit,
                        AuditEvent::ProviderOutputValidated {
                            request_hash: request_hash.clone(),
                            contract_id: contract_id.clone(),
                            ok: false,
                        },
                    )?;
                    append_event(
                        audit,
                        AuditEvent::ProviderOutputRejected {
                            request_hash: request_hash.clone(),
                            contract_id: contract_id.clone(),
                            reason: "output_contract_not_found".to_string(),
                        },
                    )?;
                    fail_run(
                        audit,
                        audit_path,
                        runtime_root,
                        last_state_hash,
                        "output_contract_not_found",
                    )?;
                    unreachable!();
                }
            };
            if !output_contracts.loaded.contains(&contract_id) {
                append_event(
                    audit,
                    AuditEvent::OutputContractLoaded {
                        contract_id: contract_id.clone(),
                        contract_hash: entry.contract_hash.clone(),
                    },
                )?;
                output_contracts.loaded.insert(contract_id.clone());
            }
            match validate_provider_output(&output_value, &entry.contract) {
                Ok(()) => {
                    append_event(
                        audit,
                        AuditEvent::ProviderOutputValidated {
                            request_hash: request_hash.clone(),
                            contract_id: contract_id.clone(),
                            ok: true,
                        },
                    )?;
                }
                Err(e) => {
                    append_event(
                        audit,
                        AuditEvent::ProviderOutputValidated {
                            request_hash: request_hash.clone(),
                            contract_id: contract_id.clone(),
                            ok: false,
                        },
                    )?;
                    append_event(
                        audit,
                        AuditEvent::ProviderOutputRejected {
                            request_hash: request_hash.clone(),
                            contract_id: contract_id.clone(),
                            reason: e.reason().to_string(),
                        },
                    )?;
                    fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                    unreachable!();
                }
            }
        } else if tool_call_present {
            let contract_id = "none".to_string();
            append_event(
                audit,
                AuditEvent::ProviderOutputValidated {
                    request_hash: request_hash.clone(),
                    contract_id: contract_id.clone(),
                    ok: false,
                },
            )?;
            append_event(
                audit,
                AuditEvent::ProviderOutputRejected {
                    request_hash: request_hash.clone(),
                    contract_id: contract_id.clone(),
                    reason: "output_contract_not_found".to_string(),
                },
            )?;
            fail_run(
                audit,
                audit_path,
                runtime_root,
                last_state_hash,
                "output_contract_not_found",
            )?;
            unreachable!();
        }
        if is_port_repo_ingest(skill_ctx) {
            let plan_result = match generate_port_plan_from_provider_output(
                runtime_root,
                repo_index_evidence.as_ref(),
                &output_value,
                tick_index,
                provider_mode,
                &retrieval.config,
                audit,
            ) {
                Ok(value) => value,
                Err(e) => {
                    fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                    unreachable!();
                }
            };
            let _ = (
                &plan_result.repo_identity_root_hash,
                &plan_result.repo_index_snapshot_root_hash,
                &plan_result.plan_root_hash,
            );
            let repo_identity_ref = match normalize_ref("repo_identity", &plan_result.repo_identity_ref)
            {
                Some(value) => value,
                None => {
                    fail_run(
                        audit,
                        audit_path,
                        runtime_root,
                        last_state_hash,
                        "port_plan_write_failed",
                    )?;
                    unreachable!();
                }
            };
            capsule.add_context_ref(repo_identity_ref);
            let repo_snapshot_ref =
                match normalize_ref("repo_index_snapshot", &plan_result.repo_index_snapshot_ref) {
                    Some(value) => value,
                    None => {
                        fail_run(
                            audit,
                            audit_path,
                            runtime_root,
                            last_state_hash,
                            "port_plan_write_failed",
                        )?;
                        unreachable!();
                    }
                };
            capsule.add_context_ref(repo_snapshot_ref);
            let plan_ref = match normalize_ref("port_plans", &plan_result.plan_ref) {
                Some(value) => value,
                None => {
                    fail_run(
                        audit,
                        audit_path,
                        runtime_root,
                        last_state_hash,
                        "port_plan_write_failed",
                    )?;
                    unreachable!();
                }
            };
            capsule.add_context_ref(plan_ref);
            let request_ref = match normalize_ref("port_plan_requests", &plan_result.request_ref) {
                Some(value) => value,
                None => {
                    fail_run(
                        audit,
                        audit_path,
                        runtime_root,
                        last_state_hash,
                        "port_plan_write_failed",
                    )?;
                    unreachable!();
                }
            };
            capsule.add_context_ref(request_ref);
            if let Some(summary_ref) = plan_result.summary_ref.as_ref() {
                let summary_ref = match normalize_ref("port_plan_summaries", summary_ref) {
                    Some(value) => value,
                    None => {
                        fail_run(
                            audit,
                            audit_path,
                            runtime_root,
                            last_state_hash,
                            "port_plan_write_failed",
                        )?;
                        unreachable!();
                    }
                };
                capsule.add_context_ref(summary_ref);
            }
        }
        let tool_call = if tool_call_present {
            match parse_tool_call_from_provider_output(&output_value) {
                Ok(call) => call,
                Err(e) => {
                    fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                    unreachable!();
                }
            }
        } else {
            None
        };

        if let Some(mut call) = tool_call {
            if call.request_hash != request_hash {
                fail_run(
                    audit,
                    audit_path,
                    runtime_root,
                    last_state_hash,
                    "tool_call_invalid",
                )?;
                unreachable!();
            }
            let input_ref = match (call.input_ref.as_deref(), call.input.as_ref()) {
                (Some(input_ref), None) => input_ref.to_string(),
                (None, Some(input)) => {
                    match write_json_artifact_atomic(runtime_root, "tool_inputs", input) {
                        Ok(value) => value,
                        Err(e) => {
                            fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                            unreachable!();
                        }
                    }
                }
                _ => {
                    fail_run(
                        audit,
                        audit_path,
                        runtime_root,
                        last_state_hash,
                        "tool_call_invalid",
                    )?;
                    unreachable!();
                }
            };
            call.input_ref = Some(input_ref.clone());
            call.input = None;
            if let Some(skill_ctx) = skill_ctx {
                if let Err(e) = enforce_tool_call(runtime_root, skill_ctx, &call, audit) {
                    if let Some(detail) = e.detail() {
                        eprintln!("detail: {}", detail);
                    }
                    fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                    unreachable!();
                }
            }
            let registry = match ToolRegistry::load_tools(runtime_root) {
                Ok(registry) => registry,
                Err(e) => {
                    fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                    unreachable!();
                }
            };
            if capsule.tool_registry_hash_is_none() {
                let value = registry.as_registry_value();
                let registry_hash = match hash_canonical_value(&value) {
                    Ok(hash) => hash,
                    Err(_) => {
                        fail_run(
                            audit,
                            audit_path,
                            runtime_root,
                            last_state_hash,
                            "run_capsule_build_failed",
                        )?;
                        unreachable!();
                    }
                };
                capsule.set_tool_registry_hash(registry_hash);
            }
            if capsule.tool_policy_hash_is_none() {
                let value = if tool_policy.mode_constraints == ModeToolConstraints::default() {
                    match serde_json::to_value(&tool_policy.config) {
                        Ok(value) => value,
                        Err(_) => {
                            fail_run(
                                audit,
                                audit_path,
                                runtime_root,
                                last_state_hash,
                                "run_capsule_build_failed",
                            )?;
                            unreachable!();
                        }
                    }
                } else {
                    serde_json::json!({
                        "policy_config": &tool_policy.config,
                        "mode_tool_constraints": &tool_policy.mode_constraints
                    })
                };
                let policy_hash = match hash_canonical_value(&value) {
                    Ok(hash) => hash,
                    Err(_) => {
                        fail_run(
                            audit,
                            audit_path,
                            runtime_root,
                            last_state_hash,
                            "run_capsule_build_failed",
                        )?;
                        unreachable!();
                    }
                };
                capsule.set_tool_policy_hash(policy_hash);
            }
            let spec = match registry.get(&call.tool_id) {
                Some(spec) => spec,
                None => {
                    fail_run(
                        audit,
                        audit_path,
                        runtime_root,
                        last_state_hash,
                        "tool_spec_missing",
                    )?;
                    unreachable!();
                }
            };
            if tool_policy.mode_constraints.is_denied(spec.id.as_str()) {
                append_event(
                    audit,
                    AuditEvent::ToolExecutionDenied {
                        tool_id: spec.id.as_str().to_string(),
                        reason: "tool_not_allowed".to_string(),
                        request_hash: call.request_hash.clone(),
                    },
                )?;
                fail_run(
                    audit,
                    audit_path,
                    runtime_root,
                    last_state_hash,
                    "tool_not_allowed",
                )?;
                unreachable!();
            }
            let mut effective_spec = spec.clone();
            if tool_policy
                .mode_constraints
                .requires_approval(effective_spec.id.as_str())
            {
                effective_spec.requires_approval = true;
            }
            if tool_policy
                .mode_constraints
                .requires_arming(effective_spec.id.as_str())
            {
                effective_spec.requires_arming = true;
            }
            let policy_input = ToolPolicyInput {
                tool_id: &effective_spec.id,
                spec: &effective_spec,
                mode: "route",
                request_hash: call.request_hash.as_str(),
                input_ref: input_ref.as_str(),
            };
            let output_ref = match execute_tool(
                runtime_root,
                &registry,
                &tool_policy.config,
                &policy_input,
                Some(workspace_ctx),
                audit,
            ) {
                Ok(output_ref) => output_ref,
                Err(e) => {
                    fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                    unreachable!();
                }
            };
            tool_output_refs.push(output_ref.clone());
            capsule.add_tool_io(RunCapsuleToolIo {
                tool_id: call.tool_id.as_str().to_string(),
                input_ref,
                output_ref,
            });
        }
    }

    if retrieval.config.enabled && retrieval.config.kind == RetrievalKind::Gsama {
        if let Err(e) = preflight_gsama_store(runtime_root, &retrieval.config) {
            fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
            unreachable!();
        }
    }
    let h = tick_core(
        runtime_root,
        audit,
        audit_path,
        state_path,
        tick_index,
        &intent,
        &request_hash,
        tool_output_refs,
        state,
        working_memory,
        last_state_hash,
        Some(capsule),
    )?;

    if retrieval.config.enabled && retrieval.config.kind == RetrievalKind::Gsama {
        let episode_hash = match load_episode_head(runtime_root) {
            Ok(Some(value)) => value,
            Ok(None) => {
                fail_run(
                    audit,
                    audit_path,
                    runtime_root,
                    last_state_hash,
                    "gsama_store_write_failed",
                )?;
                unreachable!();
            }
            Err(e) => {
                fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                unreachable!();
            }
        };
        let episode_ref = format!("episodes/{}", episode_hash);
        let context_ref =
            match write_context_pointer_artifact(runtime_root, run_id, tick_index, &episode_hash) {
                Ok(value) => value,
                Err(e) => {
                    fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                    unreachable!();
                }
            };
        let gsama_text = format!(
            "intent:{}\nrequest_hash:{}\nobserved_files:{}",
            intent_label,
            request_hash,
            observed_files_for_vectors.join(",")
        );
        if let Err(e) = append_episode_to_gsama_store(
            runtime_root,
            &retrieval.config,
            &GsamaEpisodeWriteInput {
                text: &gsama_text,
                tick_index,
                episode_ref: &episode_ref,
                context_ref: &context_ref,
                intent_kind: intent_label.as_str(),
                semantic_vector: None,
                entropy: 0.0,
                feature_profile: GsamaFeatureProfile {
                    turn_index: tick_index as f32,
                    time_since_last: 0.0,
                    write_frequency: pending_count as f32,
                    entropy: 0.0,
                    self_state_shift_cosine: 0.0,
                    importance: 1.0,
                },
                extra_tags: Vec::new(),
            },
            provider_mode,
        ) {
            fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
            unreachable!();
        }
    }

    Ok(RouteTickOutcome {
        state_hash: h,
        request_hash,
        observation_hash,
        state_hash_before: current_hash,
    })
}
