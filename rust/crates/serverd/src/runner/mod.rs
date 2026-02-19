use crate::audit::{
    append_event, fail_run, filter_events_for_run, read_audit_events, succeed_run, AuditEvent,
};
use crate::capsule::run_capsule::{write_run_capsule, RunCapsuleRun, RunCapsuleSkill};
use crate::capsule::run_capsule_collector::RunCapsuleCollector;
use crate::command::{Args, IngestArgs, InputSource, ReplayArgs, VerifyArgs};
use crate::lenses::load_lens_config;
use crate::memory::{
    list_episode_chain, load_episode_head, load_memory_config, load_working_memory,
    write_working_snapshot,
};
use crate::memory_lattice::{
    build_memory_lattice, load_memory_lattice_config, MemoryLatticeConfig,
};
use crate::modes::{
    apply_mode_profile, load_mode_config, load_mode_profile, load_mode_route_config,
    resolve_selected_mode_with_route, ModeApplyInput, ModeToolConstraints,
};
use crate::output_contract::load_output_contracts;
use crate::policy::context_policy::load_context_policy;
use crate::policy::workspace::load_workspace_policy;
use crate::provider::{
    MockPortPlanProvider, MockProvider, MockToolProvider, ModelProvider, NullProvider,
    ProviderError,
};
use crate::redaction::{compile_regex_redactions, load_redaction_config};
use crate::retrieval::load_retrieval_config;
use crate::route::{
    run_route_tick, ContextPolicyContext, LensContext, OutputContractContext, PromptContext,
    RedactionContext, RetrievalContext, ToolPolicyContext,
};
use crate::router::load_router_config;
use crate::runtime::artifacts::write_json_artifact_atomic;
use crate::skills::load_skill_context;
use crate::state_delta_artifact::{apply_delta_from_artifact, write_delta_artifact};
use crate::task::queue::list_pending_tasks;
use crate::task::task_status::{
    read_task_status, write_task_status_atomic, TaskStatus, TaskStatusKind, TASK_STATUS_SCHEMA,
};
use crate::task::task_store::{
    canonical_task_bytes, is_safe_task_id, persist_task, Intent, TaskRequest, TaskSource,
};
use crate::tick_core::{
    hash_canonical_value, hash_observation, observe, task_request_hash, tick_core,
};
use crate::tools::policy::load_policy_config;
use pie_audit_log::{verify_log, AuditAppender};
use pie_common::{canonical_json_bytes, sha256_bytes};
use pie_kernel_state::{load_or_init, save, state_hash, StateDelta};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_TASK_BYTES: usize = 1024 * 1024;

fn select_intent(delta: &StateDelta) -> Intent {
    // Rule-driven intent selection (null mode)
    // If --delta tick:0 => NoOp, else ApplyDelta(args.delta)
    match delta {
        StateDelta::TickAdvance { by: 0 } => Intent::NoOp,
        _ => Intent::ApplyDelta {
            delta: delta.clone(),
        },
    }
}

fn is_verify_run_id(value: &str) -> bool {
    let rest = match value.strip_prefix("sha256:") {
        Some(rest) => rest,
        None => return false,
    };
    rest.len() == 64 && rest.chars().all(|c| c.is_ascii_hexdigit())
}

fn read_input_bytes(source: &InputSource) -> Result<Vec<u8>, std::io::Error> {
    match source {
        InputSource::File(path) => std::fs::read(path),
        InputSource::Stdin => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn final_state_hash_for_run(audit_path: &Path, run_id: &str) -> Result<String, &'static str> {
    let events = read_audit_events(audit_path).map_err(|_| "verify_run_invalid")?;
    let run_events = filter_events_for_run(&events, run_id).map_err(|_| "verify_run_invalid")?;
    for event in run_events.iter().rev() {
        if event.get("event_type").and_then(|v| v.as_str()) == Some("run_completed") {
            let hash = event
                .get("final_state_hash")
                .and_then(|v| v.as_str())
                .ok_or("verify_run_invalid")?;
            return Ok(hash.to_string());
        }
    }
    Err("verify_run_invalid")
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn persist_run_output_task_request(
    runtime_root: &Path,
    task_request: &Option<TaskRequest>,
) -> Result<(), &'static str> {
    let task = match task_request {
        Some(task) => task,
        None => return Ok(()),
    };
    persist_task(runtime_root, task).map_err(|e| e.reason())?;
    match read_task_status(runtime_root, &task.task_id) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => {
            let pending_status = TaskStatus {
                schema: TASK_STATUS_SCHEMA.to_string(),
                task_id: task.task_id.clone(),
                status: TaskStatusKind::Pending,
                enqueued_at: now_unix_seconds(),
                applied_at: None,
                last_hash: None,
            };
            write_task_status_atomic(runtime_root, &task.task_id, &pending_status)
                .map(|_| ())
                .map_err(|e| e.reason())
        }
        Err(e) => Err(e.reason()),
    }
}

fn delta_ref_from_delta(delta: &StateDelta) -> Result<String, Box<dyn std::error::Error>> {
    let value = serde_json::to_value(delta)?;
    hash_canonical_value(&value)
}

fn build_providers() -> Result<Vec<Box<dyn ModelProvider>>, ProviderError> {
    Ok(vec![
        Box::new(MockProvider::new()?),
        Box::new(MockToolProvider::new()?),
        // Test-only provider: never selected unless router config explicitly sets "mock_port_plan".
        Box::new(MockPortPlanProvider::new()?),
        Box::new(NullProvider::new()?),
    ])
}

fn compute_run_id(input: &serde_json::Value) -> Result<String, Box<dyn std::error::Error>> {
    hash_canonical_value(input)
}

fn fail_mode_run(
    audit: &mut AuditAppender,
    audit_path: &Path,
    runtime_root: &Path,
    last_state_hash: &str,
    reason: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    append_event(
        audit,
        AuditEvent::ModeFailed {
            reason: reason.to_string(),
        },
    )?;
    fail_run(audit, audit_path, runtime_root, last_state_hash, reason)
}

fn maybe_build_memory_lattice(
    runtime_root: &Path,
    audit: &mut AuditAppender,
    audit_path: &Path,
    tick_index: u64,
    config: &MemoryLatticeConfig,
    last_state_hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(lattice) = (match build_memory_lattice(runtime_root, tick_index, config) {
        Ok(value) => value,
        Err(e) => {
            return fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason());
        }
    }) else {
        return Ok(());
    };
    let value = match serde_json::to_value(&lattice.artifact) {
        Ok(value) => value,
        Err(_) => {
            return fail_run(
                audit,
                audit_path,
                runtime_root,
                last_state_hash,
                "memory_lattice_build_failed",
            );
        }
    };
    let lattice_ref = match write_json_artifact_atomic(runtime_root, "memory_lattices", &value) {
        Ok(value) => value,
        Err(_) => {
            return fail_run(
                audit,
                audit_path,
                runtime_root,
                last_state_hash,
                "memory_lattice_build_failed",
            );
        }
    };
    append_event(
        audit,
        AuditEvent::MemoryLatticeBuilt {
            lattice_ref,
            lattice_hash: lattice.lattice_hash,
            item_count: lattice.item_count,
            bytes: lattice.bytes,
        },
    )?;
    Ok(())
}

fn execute_one_tick(
    runtime_root: &Path,
    audit: &mut AuditAppender,
    tick_index: u64,
    intent: Intent,
    mut capsule: Option<&mut RunCapsuleCollector>,
) -> Result<String, Box<dyn std::error::Error>> {
    let observation = observe(runtime_root, tick_index)?;
    let observation_hash = hash_observation(&observation)?;
    append_event(
        audit,
        AuditEvent::ObservationCaptured {
            observation: observation.clone(),
        },
    )?;

    let state_path = runtime_root.join("state").join("kernel_state.json");
    let state = load_or_init(&state_path)?;
    let current_hash = state_hash(&state);
    if let Some(ref mut collector) = capsule {
        collector.ensure_state(current_hash.clone());
    }
    append_event(
        audit,
        AuditEvent::StateSnapshotLoaded {
            tick_index,
            state_hash: current_hash.clone(),
        },
    )?;
    let requested_tick = tick_index;
    let request_hash = task_request_hash(
        tick_index,
        &current_hash,
        &observation_hash,
        &intent,
        requested_tick,
    )?;
    append_event(
        audit,
        AuditEvent::IntentSelected {
            intent: intent.clone(),
            request_hash: request_hash.clone(),
        },
    )?;

    let effective_delta = match &intent {
        Intent::NoOp => StateDelta::TickAdvance { by: 0 },
        Intent::ApplyDelta { delta } => delta.clone(),
    };
    append_event(
        audit,
        AuditEvent::StateDeltaProposed {
            tick_index,
            delta: effective_delta.clone(),
        },
    )?;
    let delta_ref = write_delta_artifact(runtime_root, &effective_delta)?;
    append_event(
        audit,
        AuditEvent::StateDeltaArtifactWritten {
            delta_ref: delta_ref.clone(),
            request_hash: request_hash.clone(),
        },
    )?;
    let next = apply_delta_from_artifact(runtime_root, &delta_ref, state)?;
    save(&state_path, &next)?;
    let h = state_hash(&next);
    append_event(
        audit,
        AuditEvent::StateDeltaApplied {
            tick_index,
            next_state_hash: h.clone(),
        },
    )?;
    if let Some(ref mut collector) = capsule {
        collector.add_state_delta_ref(delta_ref.clone(), h.clone());
    }
    append_event(
        audit,
        AuditEvent::TickCompleted {
            tick_index,
            state_hash: h.clone(),
            request_hash,
        },
    )?;

    Ok(h)
}

pub(crate) fn run_null(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(args.runtime_root.join("logs"))?;
    std::fs::create_dir_all(args.runtime_root.join("state"))?;
    let state_path = args.runtime_root.join("state").join("kernel_state.json");
    let (initial_state_hash, initial_state_error) = match load_or_init(&state_path) {
        Ok(state) => (state_hash(&state), None),
        Err(_) => ("state_hash_error".to_string(), Some("state_load_failed")),
    };
    let mut run_id_error: Option<&'static str> = None;
    let delta_ref = match delta_ref_from_delta(&args.delta) {
        Ok(value) => Some(value),
        Err(_) => {
            run_id_error = Some("run_capsule_build_failed");
            None
        }
    };
    let run_id_value = serde_json::json!({
        "mode": "null",
        "ticks": args.ticks,
        "delta_ref": delta_ref.clone(),
        "initial_state_hash": initial_state_hash.clone()
    });
    let run_id = match compute_run_id(&run_id_value) {
        Ok(value) => value,
        Err(_) => {
            run_id_error = Some("run_capsule_build_failed");
            "sha256:".to_string()
        }
    };
    let audit_path = args.runtime_root.join("logs").join("audit_rust.jsonl");
    let mut audit = AuditAppender::open(&audit_path)?;
    append_event(
        &mut audit,
        AuditEvent::RunStarted {
            run_id: run_id.clone(),
        },
    )?;
    if let Some(reason) = run_id_error {
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            "sha256:",
            reason,
        );
    }
    let mut last_state_hash = "sha256:".to_string();
    let mut last_task_request: Option<TaskRequest> = None;
    if let Some(reason) = initial_state_error {
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            &last_state_hash,
            reason,
        );
    }
    let mut capsule = RunCapsuleCollector::new(
        RunCapsuleRun {
            run_id: run_id.clone(),
            mode: "null".to_string(),
            provider_mode: None,
            ticks: Some(args.ticks),
            delta_ref,
        },
        Some(initial_state_hash),
    );

    let memory_config = match load_memory_config(&args.runtime_root) {
        Ok(config) => config,
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };

    let mut working_memory = match load_working_memory(&args.runtime_root, &memory_config) {
        Ok(memory) => memory,
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };

    if let Err(e) = load_episode_head(&args.runtime_root) {
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            &last_state_hash,
            e.reason(),
        );
    }

    for tick_index in 0..args.ticks {
        let pending = match list_pending_tasks(&args.runtime_root) {
            Ok(rows) => rows,
            Err(e) => {
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    e.reason(),
                );
            }
        };
        append_event(
            &mut audit,
            AuditEvent::TaskQueueScanned {
                pending: pending.len() as u64,
            },
        )?;

        if let Some(next) = pending.first() {
            let task_id = next.task_id.clone();
            let status = &next.status;

            let task_path = args
                .runtime_root
                .join("tasks")
                .join(format!("{}.json", task_id));
            let bytes = match std::fs::read(&task_path) {
                Ok(b) => b,
                Err(_) => {
                    return fail_run(
                        &mut audit,
                        &audit_path,
                        &args.runtime_root,
                        &last_state_hash,
                        "task_not_found",
                    );
                }
            };
            let task: TaskRequest = match serde_json::from_slice(&bytes) {
                Ok(t) => t,
                Err(e) => {
                    let reason = match e.classify() {
                        serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                            "invalid_task_json"
                        }
                        serde_json::error::Category::Data => "invalid_task_request",
                        serde_json::error::Category::Io => "invalid_task_json",
                    };
                    return fail_run(
                        &mut audit,
                        &audit_path,
                        &args.runtime_root,
                        &last_state_hash,
                        reason,
                    );
                }
            };
            if task.task_id != task_id {
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    "invalid_task_request",
                );
            }

            append_event(
                &mut audit,
                AuditEvent::TaskClaimed {
                    task_id: task_id.clone(),
                },
            )?;
            last_state_hash = execute_one_tick(
                &args.runtime_root,
                &mut audit,
                task.tick_index,
                task.intent.clone(),
                Some(&mut capsule),
            )?;
            if let Err(e) = write_working_snapshot(
                &args.runtime_root,
                task.tick_index,
                working_memory.entries(),
            ) {
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    e.reason(),
                );
            }
            let applied_status = TaskStatus {
                schema: TASK_STATUS_SCHEMA.to_string(),
                task_id: task_id.clone(),
                status: TaskStatusKind::Applied,
                enqueued_at: status.enqueued_at,
                applied_at: Some(now_unix_seconds()),
                last_hash: Some(last_state_hash.clone()),
            };
            if write_task_status_atomic(&args.runtime_root, &task_id, &applied_status).is_err() {
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    "task_status_write_failed",
                );
            }
            append_event(
                &mut audit,
                AuditEvent::TaskApplied {
                    task_id,
                    state_hash: last_state_hash.clone(),
                },
            )?;
            continue;
        }

        // Stage 1 tick loop with deterministic event ordering

        // 1. observation_captured
        let observation = observe(&args.runtime_root, tick_index)?;
        let observation_hash = hash_observation(&observation)?;
        append_event(
            &mut audit,
            AuditEvent::ObservationCaptured {
                observation: observation.clone(),
            },
        )?;

        // 2. state_snapshot_loaded
        let state = load_or_init(&state_path)?;
        let current_hash = state_hash(&state);
        append_event(
            &mut audit,
            AuditEvent::StateSnapshotLoaded {
                tick_index,
                state_hash: current_hash.clone(),
            },
        )?;

        // 3. intent_selected
        let intent = select_intent(&args.delta);
        let requested_tick = tick_index;
        let request_hash = task_request_hash(
            tick_index,
            &current_hash,
            &observation_hash,
            &intent,
            requested_tick,
        )?;
        let task_id = request_hash
            .strip_prefix("sha256:")
            .map(|h| format!("req-{}", h))
            .unwrap_or_else(|| format!("req-{}", request_hash));
        last_task_request = Some(TaskRequest {
            task_id,
            tick_index,
            intent: intent.clone(),
            run_id: Some(run_id.clone()),
            state_hash: Some(current_hash.clone()),
            observation_hash: Some(observation_hash),
            requested_tick: Some(requested_tick),
            request_hash: Some(request_hash.clone()),
            meta: serde_json::Map::new(),
        });
        append_event(
            &mut audit,
            AuditEvent::IntentSelected {
                intent: intent.clone(),
                request_hash: request_hash.clone(),
            },
        )?;
        let h = tick_core(
            &args.runtime_root,
            &mut audit,
            &audit_path,
            &state_path,
            tick_index,
            &intent,
            &request_hash,
            Vec::new(),
            state,
            &mut working_memory,
            &last_state_hash,
            Some(&mut capsule),
        )?;
        last_state_hash = h;
    }

    let audit_head_hash = audit.last_hash().to_string();
    let capsule = capsule.finalize(audit_head_hash, Some(last_state_hash.clone()));
    let (capsule_ref, capsule_hash) = match write_run_capsule(&args.runtime_root, &capsule) {
        Ok(values) => values,
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };
    append_event(
        &mut audit,
        AuditEvent::RunCapsuleWritten {
            capsule_ref,
            capsule_hash,
        },
    )?;
    if let Err(reason) = persist_run_output_task_request(&args.runtime_root, &last_task_request) {
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            &last_state_hash,
            reason,
        );
    }
    append_event(
        &mut audit,
        AuditEvent::RunCompleted {
            run_id: run_id.clone(),
            final_state_hash: last_state_hash.clone(),
        },
    )?;

    // Normalize audit_path to avoid ../ segments
    let normalized_audit_path =
        std::fs::canonicalize(&audit_path).unwrap_or_else(|_| audit_path.clone());

    succeed_run(
        &mut audit,
        &audit_path,
        serde_json::json!({
            "ok": true,
            "run_id": run_id,
            "state_hash": last_state_hash,
            "audit_path": normalized_audit_path.to_string_lossy(),
            "task_request": last_task_request
        }),
        true,
    )
}

pub(crate) fn run_route(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(args.runtime_root.join("logs"))?;
    std::fs::create_dir_all(args.runtime_root.join("state"))?;
    let state_path = args.runtime_root.join("state").join("kernel_state.json");
    let (initial_state_hash, initial_state_error) = match load_or_init(&state_path) {
        Ok(state) => (state_hash(&state), None),
        Err(_) => ("state_hash_error".to_string(), Some("state_load_failed")),
    };
    let mut run_id_error: Option<&'static str> = None;
    let delta_ref = match delta_ref_from_delta(&args.delta) {
        Ok(value) => Some(value),
        Err(_) => {
            run_id_error = Some("run_capsule_build_failed");
            None
        }
    };
    let (router_config, router_config_hash, router_config_error) =
        match load_router_config(&args.runtime_root) {
            Ok(config) => {
                let value = match serde_json::to_value(&config) {
                    Ok(value) => value,
                    Err(_) => {
                        run_id_error = Some("run_capsule_build_failed");
                        serde_json::json!({})
                    }
                };
                let hash = match hash_canonical_value(&value) {
                    Ok(hash) => Some(hash),
                    Err(_) => {
                        run_id_error = Some("run_capsule_build_failed");
                        None
                    }
                };
                (Some(config), hash, None)
            }
            Err(e) => (None, None, Some(e.reason())),
        };
    let run_id_value = serde_json::json!({
        "mode": "route",
        "provider_mode": args.provider_mode.as_str(),
        "ticks": args.ticks,
        "delta_ref": delta_ref.clone(),
        "skill_id": args.skill_id.clone(),
        "initial_state_hash": initial_state_hash.clone(),
        "router_config_hash": router_config_hash.clone()
    });
    let run_id = match compute_run_id(&run_id_value) {
        Ok(value) => value,
        Err(_) => {
            run_id_error = Some("run_capsule_build_failed");
            "sha256:".to_string()
        }
    };
    let audit_path = args.runtime_root.join("logs").join("audit_rust.jsonl");
    let mut audit = AuditAppender::open(&audit_path)?;
    append_event(
        &mut audit,
        AuditEvent::RunStarted {
            run_id: run_id.clone(),
        },
    )?;
    if let Some(reason) = run_id_error {
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            "sha256:",
            reason,
        );
    }
    let mut last_state_hash = "sha256:".to_string();
    let mut last_task_request: Option<TaskRequest> = None;
    if let Some(reason) = initial_state_error {
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            &last_state_hash,
            reason,
        );
    }
    if let Some(reason) = router_config_error {
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            &last_state_hash,
            reason,
        );
    }
    let provider_mode_config = serde_json::json!({
        "provider_mode": args.provider_mode.as_str()
    });
    let provider_mode_config_hash = match hash_canonical_value(&provider_mode_config) {
        Ok(value) => value,
        Err(_) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                "provider_mode_invalid",
            );
        }
    };
    append_event(
        &mut audit,
        AuditEvent::ProviderModeSelected {
            provider_mode: args.provider_mode.as_str().to_string(),
            config_hash: provider_mode_config_hash,
        },
    )?;
    let workspace_ctx = match load_workspace_policy(&args.runtime_root, &run_id) {
        Ok(ctx) => {
            append_event(
                &mut audit,
                AuditEvent::WorkspacePolicyLoaded {
                    policy_hash: ctx.policy_hash.clone(),
                },
            )?;
            ctx
        }
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };
    let mut capsule = RunCapsuleCollector::new(
        RunCapsuleRun {
            run_id: run_id.clone(),
            mode: "route".to_string(),
            provider_mode: Some(args.provider_mode.as_str().to_string()),
            ticks: Some(args.ticks),
            delta_ref,
        },
        Some(initial_state_hash),
    );
    if let Some(hash) = router_config_hash {
        capsule.set_router_hash(hash);
    }
    let redaction_config = match load_redaction_config(&args.runtime_root) {
        Ok(config) => config,
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };
    let redaction_ctx = if redaction_config.enabled {
        let compiled_regex = match compile_regex_redactions(&redaction_config) {
            Ok(list) => list,
            Err(e) => {
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    e.reason(),
                );
            }
        };
        let config_value = match serde_json::to_value(&redaction_config) {
            Ok(value) => value,
            Err(_) => {
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    "redaction_failed",
                );
            }
        };
        let config_ref = match write_json_artifact_atomic(
            &args.runtime_root,
            "redaction_configs",
            &config_value,
        ) {
            Ok(value) => value,
            Err(_) => {
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    "redaction_failed",
                );
            }
        };
        append_event(
            &mut audit,
            AuditEvent::RedactionConfigLoaded {
                config_ref: config_ref.clone(),
                run_id: run_id.clone(),
            },
        )?;
        RedactionContext {
            config: redaction_config,
            compiled_regex,
        }
    } else {
        RedactionContext {
            config: redaction_config,
            compiled_regex: Vec::new(),
        }
    };
    let context_policy = match load_context_policy(&args.runtime_root) {
        Ok(policy) => policy,
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };
    let mut context_policy_ctx = ContextPolicyContext {
        policy: context_policy,
        policy_ref: None,
    };
    let retrieval_config = match load_retrieval_config(&args.runtime_root) {
        Ok(config) => config,
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };
    let mut retrieval_ctx = RetrievalContext {
        config: retrieval_config,
        config_ref: None,
    };
    let lens_config = match load_lens_config(&args.runtime_root) {
        Ok(config) => config,
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };
    let mut lens_ctx = LensContext {
        config: lens_config,
        config_ref: None,
        mode_id: None,
        mode_policy_hash: None,
    };
    let output_contracts = match load_output_contracts(&args.runtime_root) {
        Ok(registry) => registry,
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };
    let mut output_contract_ctx = OutputContractContext {
        registry: output_contracts,
        loaded: BTreeSet::new(),
    };
    let skill_ctx = if let Some(skill_id) = &args.skill_id {
        let ctx = match load_skill_context(&args.runtime_root, skill_id) {
            Ok(ctx) => ctx,
            Err(e) => {
                if let Some(detail) = e.detail() {
                    eprintln!("detail: {}", detail);
                }
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    e.reason(),
                );
            }
        };
        append_event(
            &mut audit,
            AuditEvent::SkillSelected {
                skill_id: ctx.manifest.skill_id.clone(),
                skill_manifest_hash: ctx.manifest_hash.clone(),
            },
        )?;
        Some(ctx)
    } else {
        None
    };
    if let Some(ctx) = skill_ctx.as_ref() {
        let output_contract_id = ctx.manifest.output_contract.clone();
        let output_contract_hash = output_contract_id
            .as_ref()
            .and_then(|id| output_contract_ctx.registry.get(id))
            .map(|entry| entry.contract_hash.clone());
        capsule.set_skill(RunCapsuleSkill {
            skill_id: ctx.manifest.skill_id.clone(),
            skill_manifest_hash: ctx.manifest_hash.clone(),
            output_contract_id,
            output_contract_hash,
        });
    }
    let base_prompt_template_refs = skill_ctx
        .as_ref()
        .map(|ctx| ctx.manifest.prompt_template_refs.clone())
        .unwrap_or_default();
    let mut prompt_ctx = PromptContext {
        template_override_ref: None,
    };
    let mut mode_tool_constraints = ModeToolConstraints::default();
    let tool_policy_config = match load_policy_config(&args.runtime_root) {
        Ok(config) => config,
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };
    let mode_config = match load_mode_config(&args.runtime_root) {
        Ok(config) => config,
        Err(e) => {
            return fail_mode_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };
    if mode_config.enabled {
        let mode_route = match load_mode_route_config(&args.runtime_root, &mode_config) {
            Ok(config) => config,
            Err(e) => {
                return fail_mode_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    e.reason(),
                );
            }
        };
        let routed_skill_mode = if args.mode_profile.is_none() && mode_route.loaded_from_file {
            skill_ctx.as_ref().and_then(|ctx| {
                mode_route
                    .config
                    .by_skill
                    .get(ctx.manifest.skill_id.as_str())
                    .map(|mode_id| (ctx.manifest.skill_id.clone(), mode_id.clone()))
            })
        } else {
            None
        };
        let selected_mode = match resolve_selected_mode_with_route(
            &mode_config,
            &mode_route.config,
            args.mode_profile.as_deref(),
            skill_ctx.as_ref().map(|ctx| ctx.manifest.skill_id.as_str()),
        ) {
            Ok(Some(mode_id)) => mode_id,
            Ok(None) => unreachable!(),
            Err(e) => {
                return fail_mode_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    e.reason(),
                );
            }
        };
        let mode_profile = match load_mode_profile(
            &args.runtime_root,
            &selected_mode,
            mode_config.max_profile_bytes,
        ) {
            Ok(profile) => profile,
            Err(e) => {
                return fail_mode_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    e.reason(),
                );
            }
        };
        let effective_mode = match apply_mode_profile(
            &selected_mode,
            &mode_profile,
            &ModeApplyInput {
                runtime_root: &args.runtime_root,
                base_retrieval: &retrieval_ctx.config,
                base_lenses: &lens_ctx.config,
                base_prompt_template_refs: &base_prompt_template_refs,
            },
        ) {
            Ok(mode) => mode,
            Err(e) => {
                return fail_mode_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    e.reason(),
                );
            }
        };
        let mode_config_value = match serde_json::to_value(&mode_config) {
            Ok(value) => value,
            Err(_) => {
                return fail_mode_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    "mode_config_invalid",
                );
            }
        };
        let mode_config_ref = match write_json_artifact_atomic(
            &args.runtime_root,
            "mode_configs",
            &mode_config_value,
        ) {
            Ok(value) => value,
            Err(_) => {
                return fail_mode_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    "mode_config_invalid",
                );
            }
        };
        append_event(
            &mut audit,
            AuditEvent::ModeConfigLoaded {
                config_ref: mode_config_ref,
            },
        )?;
        if let Some((skill_id, mode_id)) = routed_skill_mode {
            let mode_route_value = match serde_json::to_value(&mode_route.config) {
                Ok(value) => value,
                Err(_) => {
                    return fail_mode_run(
                        &mut audit,
                        &audit_path,
                        &args.runtime_root,
                        &last_state_hash,
                        "mode_config_invalid",
                    );
                }
            };
            let route_ref = match write_json_artifact_atomic(
                &args.runtime_root,
                "mode_routes",
                &mode_route_value,
            ) {
                Ok(value) => value,
                Err(_) => {
                    return fail_mode_run(
                        &mut audit,
                        &audit_path,
                        &args.runtime_root,
                        &last_state_hash,
                        "mode_config_invalid",
                    );
                }
            };
            append_event(
                &mut audit,
                AuditEvent::ModeRouted {
                    skill_id,
                    mode_id,
                    route_ref,
                },
            )?;
        }
        let mode_profile_value = match serde_json::to_value(&mode_profile) {
            Ok(value) => value,
            Err(_) => {
                return fail_mode_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    "mode_profile_invalid",
                );
            }
        };
        let mode_profile_ref = match write_json_artifact_atomic(
            &args.runtime_root,
            "mode_profiles",
            &mode_profile_value,
        ) {
            Ok(value) => value,
            Err(_) => {
                return fail_mode_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    "mode_profile_invalid",
                );
            }
        };
        append_event(
            &mut audit,
            AuditEvent::ModeProfileSelected {
                mode_id: selected_mode.clone(),
                profile_ref: mode_profile_ref,
            },
        )?;
        let mode_applied_value = match serde_json::to_value(&effective_mode.applied_artifact) {
            Ok(value) => value,
            Err(_) => {
                return fail_mode_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    "mode_profile_invalid",
                );
            }
        };
        if write_json_artifact_atomic(&args.runtime_root, "mode_applied", &mode_applied_value)
            .is_err()
        {
            return fail_mode_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                "mode_profile_invalid",
            );
        }
        append_event(
            &mut audit,
            AuditEvent::ModeApplied {
                mode_id: effective_mode.mode_id.clone(),
                mode_hash: effective_mode.mode_hash.clone(),
            },
        )?;
        if let Some(policy_hash) = effective_mode.mode_policy_hash.clone() {
            append_event(
                &mut audit,
                AuditEvent::ModePolicyApplied {
                    mode_id: effective_mode.mode_id.clone(),
                    policy_hash,
                },
            )?;
        }
        retrieval_ctx.config = effective_mode.retrieval_config;
        retrieval_ctx.config_ref = None;
        lens_ctx.config = effective_mode.lens_config;
        lens_ctx.config_ref = None;
        lens_ctx.mode_id = Some(effective_mode.mode_id.clone());
        lens_ctx.mode_policy_hash = effective_mode.mode_policy_hash.clone();
        prompt_ctx.template_override_ref = effective_mode.prompt_template_ref;
        mode_tool_constraints = effective_mode.tool_constraints;
    }
    let effective_prompt_template_refs = match prompt_ctx.template_override_ref.as_ref() {
        Some(template_ref) => vec![template_ref.clone()],
        None => base_prompt_template_refs,
    };
    capsule.set_prompt_template_refs(effective_prompt_template_refs);
    let tool_policy_ctx = ToolPolicyContext {
        config: tool_policy_config,
        mode_constraints: mode_tool_constraints,
    };

    let router_config = router_config.expect("router config loaded");

    let providers = match build_providers() {
        Ok(providers) => providers,
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };

    let memory_config = match load_memory_config(&args.runtime_root) {
        Ok(config) => config,
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };

    let mut working_memory = match load_working_memory(&args.runtime_root, &memory_config) {
        Ok(memory) => memory,
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };
    let memory_lattice_config = match load_memory_lattice_config(&args.runtime_root) {
        Ok(config) => config,
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };

    if let Err(e) = load_episode_head(&args.runtime_root) {
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            &last_state_hash,
            e.reason(),
        );
    }

    for tick_index in 0..args.ticks {
        let pending = match list_pending_tasks(&args.runtime_root) {
            Ok(rows) => rows,
            Err(e) => {
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    e.reason(),
                );
            }
        };

        if let Some(next) = pending.first() {
            let task_id = next.task_id.clone();
            let status = &next.status;

            let task_path = args
                .runtime_root
                .join("tasks")
                .join(format!("{}.json", task_id));
            let bytes = match std::fs::read(&task_path) {
                Ok(b) => b,
                Err(_) => {
                    return fail_run(
                        &mut audit,
                        &audit_path,
                        &args.runtime_root,
                        &last_state_hash,
                        "task_not_found",
                    );
                }
            };
            let task: TaskRequest = match serde_json::from_slice(&bytes) {
                Ok(t) => t,
                Err(e) => {
                    let reason = match e.classify() {
                        serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                            "invalid_task_json"
                        }
                        serde_json::error::Category::Data => "invalid_task_request",
                        serde_json::error::Category::Io => "invalid_task_json",
                    };
                    return fail_run(
                        &mut audit,
                        &audit_path,
                        &args.runtime_root,
                        &last_state_hash,
                        reason,
                    );
                }
            };
            if task.task_id != task_id {
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    "invalid_task_request",
                );
            }

            append_event(
                &mut audit,
                AuditEvent::TaskClaimed {
                    task_id: task_id.clone(),
                },
            )?;
            maybe_build_memory_lattice(
                &args.runtime_root,
                &mut audit,
                &audit_path,
                task.tick_index,
                &memory_lattice_config,
                &last_state_hash,
            )?;
            let outcome = run_route_tick(
                &args.runtime_root,
                &mut audit,
                &audit_path,
                &state_path,
                &run_id,
                task.tick_index,
                Some(task.task_id.as_str()),
                pending.len() as u64,
                task.intent.clone(),
                &router_config,
                args.provider_mode,
                skill_ctx.as_ref(),
                &providers,
                &redaction_ctx,
                &mut retrieval_ctx,
                &mut lens_ctx,
                &prompt_ctx,
                &tool_policy_ctx,
                &mut context_policy_ctx,
                &mut output_contract_ctx,
                &workspace_ctx,
                &mut capsule,
                &mut working_memory,
                &last_state_hash,
            )?;
            last_state_hash = outcome.state_hash;
            let applied_status = TaskStatus {
                schema: TASK_STATUS_SCHEMA.to_string(),
                task_id: task_id.clone(),
                status: TaskStatusKind::Applied,
                enqueued_at: status.enqueued_at,
                applied_at: Some(now_unix_seconds()),
                last_hash: Some(last_state_hash.clone()),
            };
            if write_task_status_atomic(&args.runtime_root, &task_id, &applied_status).is_err() {
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    "task_status_write_failed",
                );
            }
            append_event(
                &mut audit,
                AuditEvent::TaskApplied {
                    task_id,
                    state_hash: last_state_hash.clone(),
                },
            )?;
            continue;
        }

        let intent = select_intent(&args.delta);
        maybe_build_memory_lattice(
            &args.runtime_root,
            &mut audit,
            &audit_path,
            tick_index,
            &memory_lattice_config,
            &last_state_hash,
        )?;
        let outcome = run_route_tick(
            &args.runtime_root,
            &mut audit,
            &audit_path,
            &state_path,
            &run_id,
            tick_index,
            None,
            pending.len() as u64,
            intent.clone(),
            &router_config,
            args.provider_mode,
            skill_ctx.as_ref(),
            &providers,
            &redaction_ctx,
            &mut retrieval_ctx,
            &mut lens_ctx,
            &prompt_ctx,
            &tool_policy_ctx,
            &mut context_policy_ctx,
            &mut output_contract_ctx,
            &workspace_ctx,
            &mut capsule,
            &mut working_memory,
            &last_state_hash,
        )?;
        let task_id = outcome
            .request_hash
            .strip_prefix("sha256:")
            .map(|h| format!("req-{}", h))
            .unwrap_or_else(|| format!("req-{}", outcome.request_hash));
        last_task_request = Some(TaskRequest {
            task_id,
            tick_index,
            intent,
            run_id: Some(run_id.clone()),
            state_hash: Some(outcome.state_hash_before),
            observation_hash: Some(outcome.observation_hash),
            requested_tick: Some(tick_index),
            request_hash: Some(outcome.request_hash.clone()),
            meta: serde_json::Map::new(),
        });
        last_state_hash = outcome.state_hash;
    }
    let audit_head_hash = audit.last_hash().to_string();
    let capsule = capsule.finalize(audit_head_hash, Some(last_state_hash.clone()));
    let (capsule_ref, capsule_hash) = match write_run_capsule(&args.runtime_root, &capsule) {
        Ok(values) => values,
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };
    append_event(
        &mut audit,
        AuditEvent::RunCapsuleWritten {
            capsule_ref,
            capsule_hash,
        },
    )?;
    if let Err(reason) = persist_run_output_task_request(&args.runtime_root, &last_task_request) {
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            &last_state_hash,
            reason,
        );
    }
    append_event(
        &mut audit,
        AuditEvent::RunCompleted {
            run_id: run_id.clone(),
            final_state_hash: last_state_hash.clone(),
        },
    )?;

    let normalized_audit_path =
        std::fs::canonicalize(&audit_path).unwrap_or_else(|_| audit_path.clone());

    succeed_run(
        &mut audit,
        &audit_path,
        serde_json::json!({
            "ok": true,
            "run_id": run_id,
            "state_hash": last_state_hash,
            "audit_path": normalized_audit_path.to_string_lossy(),
            "task_request": last_task_request
        }),
        true,
    )
}

pub(crate) fn run_replay(args: ReplayArgs) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(args.runtime_root.join("logs"))?;
    std::fs::create_dir_all(args.runtime_root.join("state"))?;
    let mut run_id_error: Option<&'static str> = None;
    let run_id_value = serde_json::json!({
        "mode": "replay",
        "task_id": args.task_id.clone()
    });
    let run_id = match compute_run_id(&run_id_value) {
        Ok(value) => value,
        Err(_) => {
            run_id_error = Some("run_capsule_build_failed");
            "sha256:".to_string()
        }
    };
    let audit_path = args.runtime_root.join("logs").join("audit_rust.jsonl");
    let mut audit = AuditAppender::open(&audit_path)?;
    append_event(
        &mut audit,
        AuditEvent::RunStarted {
            run_id: run_id.clone(),
        },
    )?;
    if let Some(reason) = run_id_error {
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            "sha256:",
            reason,
        );
    }

    let mut last_state_hash = "sha256:".to_string();
    let mut capsule = RunCapsuleCollector::new(
        RunCapsuleRun {
            run_id: run_id.clone(),
            mode: "replay".to_string(),
            provider_mode: None,
            ticks: None,
            delta_ref: None,
        },
        None,
    );

    append_event(
        &mut audit,
        AuditEvent::TaskReplayRequested {
            task_id: args.task_id.clone(),
        },
    )?;

    if !is_safe_task_id(&args.task_id) {
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            &last_state_hash,
            "task_not_found",
        );
    }

    let task_path = args
        .runtime_root
        .join("tasks")
        .join(format!("{}.json", args.task_id));
    let bytes = match std::fs::read(&task_path) {
        Ok(b) => b,
        Err(_) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                "task_not_found",
            );
        }
    };

    let task: TaskRequest = match serde_json::from_slice(&bytes) {
        Ok(t) => t,
        Err(e) => {
            let reason = match e.classify() {
                serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                    "invalid_task_json"
                }
                serde_json::error::Category::Data => "invalid_task_request",
                serde_json::error::Category::Io => "invalid_task_json",
            };
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                reason,
            );
        }
    };

    if task.task_id != args.task_id {
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            &last_state_hash,
            "invalid_task_request",
        );
    }

    append_event(
        &mut audit,
        AuditEvent::TaskReplayLoaded {
            task_id: task.task_id.clone(),
        },
    )?;
    let status = match read_task_status(&args.runtime_root, &task.task_id) {
        Ok(Some(status)) => status,
        Ok(None) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                "task_status_missing",
            );
        }
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };

    match status.status {
        TaskStatusKind::Applied => {
            if let Some(hash) = status.last_hash.clone() {
                last_state_hash = hash.clone();
                capsule.ensure_state(hash);
            }
            append_event(
                &mut audit,
                AuditEvent::TaskAlreadyApplied {
                    task_id: task.task_id.clone(),
                },
            )?;
        }
        TaskStatusKind::Rejected => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                "task_rejected",
            );
        }
        TaskStatusKind::Pending => {
            append_event(
                &mut audit,
                AuditEvent::TaskClaimed {
                    task_id: task.task_id.clone(),
                },
            )?;
            last_state_hash = execute_one_tick(
                &args.runtime_root,
                &mut audit,
                task.tick_index,
                task.intent.clone(),
                Some(&mut capsule),
            )?;
            let applied_status = TaskStatus {
                schema: TASK_STATUS_SCHEMA.to_string(),
                task_id: task.task_id.clone(),
                status: TaskStatusKind::Applied,
                enqueued_at: status.enqueued_at,
                applied_at: Some(now_unix_seconds()),
                last_hash: Some(last_state_hash.clone()),
            };
            if write_task_status_atomic(&args.runtime_root, &task.task_id, &applied_status).is_err()
            {
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    "task_status_write_failed",
                );
            }
            append_event(
                &mut audit,
                AuditEvent::TaskApplied {
                    task_id: task.task_id.clone(),
                    state_hash: last_state_hash.clone(),
                },
            )?;
        }
    }

    let audit_head_hash = audit.last_hash().to_string();
    let capsule = capsule.finalize(audit_head_hash, Some(last_state_hash.clone()));
    let (capsule_ref, capsule_hash) = match write_run_capsule(&args.runtime_root, &capsule) {
        Ok(values) => values,
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };
    append_event(
        &mut audit,
        AuditEvent::RunCapsuleWritten {
            capsule_ref,
            capsule_hash,
        },
    )?;
    append_event(
        &mut audit,
        AuditEvent::RunCompleted {
            run_id: run_id.clone(),
            final_state_hash: last_state_hash.clone(),
        },
    )?;

    succeed_run(
        &mut audit,
        &audit_path,
        serde_json::json!({
            "ok": true,
            "task_id": task.task_id,
            "runtime_root": args.runtime_root.to_string_lossy(),
            "audit_path": audit_path.to_string_lossy()
        }),
        false,
    )
}

pub(crate) fn run_ingest(args: IngestArgs) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(args.runtime_root.join("logs"))?;
    std::fs::create_dir_all(args.runtime_root.join("state"))?;
    let source = match &args.source {
        InputSource::Stdin => TaskSource::Stdin,
        InputSource::File(_) => TaskSource::File,
    };
    let source_label = match source {
        TaskSource::Stdin => "stdin",
        TaskSource::File => "file",
    };
    let mut input_error: Option<&'static str> = None;
    let bytes = match read_input_bytes(&args.source) {
        Ok(b) => b,
        Err(_) => {
            input_error = Some("input_read_failed");
            Vec::new()
        }
    };
    let input_hash = if input_error.is_none() {
        Some(sha256_bytes(&bytes))
    } else {
        None
    };
    let mut run_id_error: Option<&'static str> = None;
    let run_id_value = serde_json::json!({
        "mode": "ingest",
        "source": source_label,
        "input_hash": input_hash.clone()
    });
    let run_id = match compute_run_id(&run_id_value) {
        Ok(value) => value,
        Err(_) => {
            run_id_error = Some("run_capsule_build_failed");
            "sha256:".to_string()
        }
    };
    let audit_path = args.runtime_root.join("logs").join("audit_rust.jsonl");
    let mut audit = AuditAppender::open(&audit_path)?;
    append_event(
        &mut audit,
        AuditEvent::RunStarted {
            run_id: run_id.clone(),
        },
    )?;
    if let Some(reason) = run_id_error {
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            "sha256:",
            reason,
        );
    }

    let last_state_hash = "sha256:".to_string();
    let capsule = RunCapsuleCollector::new(
        RunCapsuleRun {
            run_id: run_id.clone(),
            mode: "ingest".to_string(),
            provider_mode: None,
            ticks: None,
            delta_ref: None,
        },
        None,
    );

    if let Some(reason) = input_error {
        append_event(
            &mut audit,
            AuditEvent::TaskRejected {
                reason: reason.to_string(),
            },
        )?;
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            &last_state_hash,
            reason,
        );
    }
    append_event(
        &mut audit,
        AuditEvent::TaskReceived {
            source,
            bytes: bytes.len() as u64,
        },
    )?;

    if bytes.is_empty() {
        append_event(
            &mut audit,
            AuditEvent::TaskRejected {
                reason: "empty_input".to_string(),
            },
        )?;
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            &last_state_hash,
            "empty_input",
        );
    }

    if bytes.len() > MAX_TASK_BYTES {
        append_event(
            &mut audit,
            AuditEvent::TaskRejected {
                reason: "oversize_input".to_string(),
            },
        )?;
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            &last_state_hash,
            "oversize_input",
        );
    }

    let task: TaskRequest = match serde_json::from_slice(&bytes) {
        Ok(t) => t,
        Err(e) => {
            let reason = match e.classify() {
                serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                    "invalid_json"
                }
                serde_json::error::Category::Data => "schema_mismatch",
                serde_json::error::Category::Io => "input_read_failed",
            };
            append_event(
                &mut audit,
                AuditEvent::TaskRejected {
                    reason: reason.to_string(),
                },
            )?;
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                reason,
            );
        }
    };

    if task.task_id.trim().is_empty() {
        append_event(
            &mut audit,
            AuditEvent::TaskRejected {
                reason: "task_id_empty".to_string(),
            },
        )?;
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            &last_state_hash,
            "task_id_empty",
        );
    }

    if task.task_id.len() > 128 {
        append_event(
            &mut audit,
            AuditEvent::TaskRejected {
                reason: "task_id_too_long".to_string(),
            },
        )?;
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            &last_state_hash,
            "task_id_too_long",
        );
    }

    if !is_safe_task_id(&task.task_id) {
        append_event(
            &mut audit,
            AuditEvent::TaskRejected {
                reason: "task_id_unsafe".to_string(),
            },
        )?;
        return fail_run(
            &mut audit,
            &audit_path,
            &args.runtime_root,
            &last_state_hash,
            "task_id_unsafe",
        );
    }
    let task_path = args
        .runtime_root
        .join("tasks")
        .join(format!("{}.json", task.task_id));
    let mut existing_status: Option<TaskStatus> = None;
    if task_path.exists() {
        let incoming = match canonical_task_bytes(&task) {
            Ok(bytes) => bytes,
            Err(e) => {
                append_event(
                    &mut audit,
                    AuditEvent::TaskRejected {
                        reason: e.reason().to_string(),
                    },
                )?;
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    e.reason(),
                );
            }
        };
        let existing = match std::fs::read(&task_path) {
            Ok(bytes) => bytes,
            Err(_) => {
                append_event(
                    &mut audit,
                    AuditEvent::TaskRejected {
                        reason: "task_persist_read_failed".to_string(),
                    },
                )?;
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    "task_persist_read_failed",
                );
            }
        };
        let existing_value: serde_json::Value = match serde_json::from_slice(&existing) {
            Ok(v) => v,
            Err(_) => {
                append_event(
                    &mut audit,
                    AuditEvent::TaskRejected {
                        reason: "task_persist_read_failed".to_string(),
                    },
                )?;
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    "task_persist_read_failed",
                );
            }
        };
        let existing_canon = match canonical_json_bytes(&existing_value) {
            Ok(bytes) => bytes,
            Err(_) => {
                append_event(
                    &mut audit,
                    AuditEvent::TaskRejected {
                        reason: "task_persist_read_failed".to_string(),
                    },
                )?;
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    "task_persist_read_failed",
                );
            }
        };
        if existing_canon != incoming {
            append_event(
                &mut audit,
                AuditEvent::TaskRejected {
                    reason: "task_id_conflict".to_string(),
                },
            )?;
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                "task_id_conflict",
            );
        }
        match read_task_status(&args.runtime_root, &task.task_id) {
            Ok(status) => existing_status = status,
            Err(e) => {
                append_event(
                    &mut audit,
                    AuditEvent::TaskRejected {
                        reason: e.reason().to_string(),
                    },
                )?;
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    e.reason(),
                );
            }
        }
    }

    append_event(
        &mut audit,
        AuditEvent::TaskAccepted {
            task_id: task.task_id.clone(),
        },
    )?;
    let persisted_path = if task_path.exists() {
        task_path.clone()
    } else {
        match persist_task(&args.runtime_root, &task) {
            Ok((path, _)) => path,
            Err(e) => {
                append_event(
                    &mut audit,
                    AuditEvent::TaskPersistFailed {
                        task_id: task.task_id.clone(),
                        reason: e.reason().to_string(),
                    },
                )?;
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    e.reason(),
                );
            }
        }
    };
    append_event(
        &mut audit,
        AuditEvent::TaskPersisted {
            task_id: task.task_id.clone(),
            path: persisted_path.to_string_lossy().to_string(),
        },
    )?;

    let status = if let Some(status) = existing_status {
        Some(status)
    } else {
        match read_task_status(&args.runtime_root, &task.task_id) {
            Ok(status) => status,
            Err(e) => {
                append_event(
                    &mut audit,
                    AuditEvent::TaskPersistFailed {
                        task_id: task.task_id.clone(),
                        reason: e.reason().to_string(),
                    },
                )?;
                return fail_run(
                    &mut audit,
                    &audit_path,
                    &args.runtime_root,
                    &last_state_hash,
                    e.reason(),
                );
            }
        }
    };

    if let Some(status) = status {
        if status.status == TaskStatusKind::Pending {
            append_event(
                &mut audit,
                AuditEvent::TaskEnqueued {
                    task_id: task.task_id.clone(),
                },
            )?;
        }
    } else {
        let pending_status = TaskStatus {
            schema: TASK_STATUS_SCHEMA.to_string(),
            task_id: task.task_id.clone(),
            status: TaskStatusKind::Pending,
            enqueued_at: now_unix_seconds(),
            applied_at: None,
            last_hash: None,
        };
        if write_task_status_atomic(&args.runtime_root, &task.task_id, &pending_status).is_err() {
            append_event(
                &mut audit,
                AuditEvent::TaskPersistFailed {
                    task_id: task.task_id.clone(),
                    reason: "task_status_write_failed".to_string(),
                },
            )?;
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                "task_status_write_failed",
            );
        }
        append_event(
            &mut audit,
            AuditEvent::TaskEnqueued {
                task_id: task.task_id.clone(),
            },
        )?;
    }
    let audit_head_hash = audit.last_hash().to_string();
    let capsule = capsule.finalize(audit_head_hash, Some(last_state_hash.clone()));
    let (capsule_ref, capsule_hash) = match write_run_capsule(&args.runtime_root, &capsule) {
        Ok(values) => values,
        Err(e) => {
            return fail_run(
                &mut audit,
                &audit_path,
                &args.runtime_root,
                &last_state_hash,
                e.reason(),
            );
        }
    };
    append_event(
        &mut audit,
        AuditEvent::RunCapsuleWritten {
            capsule_ref,
            capsule_hash,
        },
    )?;

    append_event(
        &mut audit,
        AuditEvent::RunCompleted {
            run_id: run_id.clone(),
            final_state_hash: last_state_hash.clone(),
        },
    )?;
    succeed_run(
        &mut audit,
        &audit_path,
        serde_json::json!({
            "ok": true,
            "task_id": task.task_id,
            "runtime_root": args.runtime_root.to_string_lossy(),
            "audit_path": audit_path.to_string_lossy()
        }),
        false,
    )
}

pub(crate) fn run_verify(args: VerifyArgs) -> Result<(), Box<dyn std::error::Error>> {
    let audit_path = args.runtime_root.join("logs").join("audit_rust.jsonl");

    if !audit_path.exists() {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "ok": false,
                "error": "audit log not found",
                "audit_path": audit_path.to_string_lossy()
            }))?
        );
        return Err(
            std::io::Error::new(std::io::ErrorKind::NotFound, "audit log not found").into(),
        );
    }
    if let Some(run_id) = args.run_id.as_ref() {
        if !is_verify_run_id(run_id) {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "ok": false,
                    "audit_path": audit_path.to_string_lossy(),
                    "error": "verify_run_invalid"
                }))?
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "verify_run_invalid",
            )
            .into());
        }
    }
    if args.verify_memory {
        if let Err(e) = load_memory_config(&args.runtime_root)
            .and_then(|config| load_working_memory(&args.runtime_root, &config).map(|_| ()))
        {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "ok": false,
                    "audit_path": audit_path.to_string_lossy(),
                    "error": e.reason()
                }))?
            );
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, e.reason()).into());
        }
        if let Err(e) = list_episode_chain(&args.runtime_root) {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "ok": false,
                    "audit_path": audit_path.to_string_lossy(),
                    "error": e.reason()
                }))?
            );
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, e.reason()).into());
        }
    }
    let mut audit = AuditAppender::open(&audit_path)?;

    match verify_log(&audit_path) {
        Ok(last_hash) => {
            let mut payload = serde_json::Map::new();
            payload.insert("ok".to_string(), serde_json::Value::Bool(true));
            payload.insert(
                "audit_path".to_string(),
                serde_json::Value::String(audit_path.to_string_lossy().to_string()),
            );
            payload.insert(
                "last_hash".to_string(),
                serde_json::Value::String(last_hash),
            );
            if let Some(run_id) = args.run_id.as_ref() {
                match final_state_hash_for_run(&audit_path, run_id) {
                    Ok(state_hash) => {
                        payload.insert(
                            "run_id".to_string(),
                            serde_json::Value::String(run_id.to_string()),
                        );
                        payload.insert(
                            "final_state_hash".to_string(),
                            serde_json::Value::String(state_hash),
                        );
                    }
                    Err(reason) => {
                        println!(
                            "{}",
                            serde_json::to_string(&serde_json::json!({
                                "ok": false,
                                "audit_path": audit_path.to_string_lossy(),
                                "error": reason
                            }))?
                        );
                        return Err(
                            std::io::Error::new(std::io::ErrorKind::InvalidInput, reason).into(),
                        );
                    }
                }
            }
            succeed_run(
                &mut audit,
                &audit_path,
                serde_json::Value::Object(payload),
                false,
            )
        }
        Err(e) => {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "ok": false,
                    "audit_path": audit_path.to_string_lossy(),
                    "error": e.to_string()
                }))?
            );
            Err(e.into())
        }
    }
}
