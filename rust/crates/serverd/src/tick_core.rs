use crate::audit::{append_event, fail_run, AuditEvent, Observation};
use crate::memory::{
    append_episode, load_episode_head, open_memory_enabled, write_open_memory_mirror,
    write_working_snapshot, EpisodePayload, WorkingMemory,
};
use crate::state_delta_artifact::{apply_delta_from_artifact, write_delta_artifact};
use crate::task::task_store::Intent;
use pie_audit_log::AuditAppender;
use pie_common::{canonical_json_bytes, sha256_bytes};
use pie_kernel_state::{save, state_hash, StateDelta};
use std::path::PathBuf;

pub(crate) fn observe(
    runtime_root: &PathBuf,
    tick_index: u64,
) -> Result<Observation, std::io::Error> {
    // Deterministic observation: list files under runtime root, sorted
    let mut observed = Vec::new();

    fn collect_files(
        base: &std::path::Path,
        dir: &std::path::Path,
        out: &mut Vec<String>,
    ) -> Result<(), std::io::Error> {
        if !dir.exists() {
            return Ok(());
        }

        for entry_result in std::fs::read_dir(dir)? {
            let entry = entry_result?;
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().and_then(|n| n.to_str()) == Some("logs") {
                    continue;
                }
                collect_files(base, &path, out)?;
            } else if path.is_file() {
                let rel = path.strip_prefix(base).unwrap_or(&path);
                out.push(rel.to_string_lossy().to_string());
            }
        }
        Ok(())
    }

    collect_files(runtime_root, runtime_root, &mut observed)?;
    observed.sort();

    Ok(Observation {
        tick_index,
        observed_files: observed,
    })
}

pub(crate) fn hash_canonical_value(
    value: &serde_json::Value,
) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = canonical_json_bytes(value)?;
    Ok(sha256_bytes(&bytes))
}

pub(crate) fn hash_observation(
    observation: &Observation,
) -> Result<String, Box<dyn std::error::Error>> {
    let value = serde_json::to_value(observation)?;
    hash_canonical_value(&value)
}

pub(crate) fn task_request_hash(
    tick_index: u64,
    state_hash: &str,
    observation_hash: &str,
    intent: &Intent,
    requested_tick: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    let value = serde_json::json!({
        "tick_index": tick_index,
        "state_hash": state_hash,
        "observation_hash": observation_hash,
        "intent": intent,
        "requested_tick": requested_tick
    });
    hash_canonical_value(&value)
}

pub(crate) fn tick_core(
    runtime_root: &PathBuf,
    audit: &mut AuditAppender,
    audit_path: &PathBuf,
    state_path: &PathBuf,
    tick_index: u64,
    intent: &Intent,
    request_hash: &str,
    artifact_refs: Vec<String>,
    state: pie_state::GsamaState,
    working_memory: &mut WorkingMemory,
    last_state_hash: &str,
    mut capsule: Option<&mut crate::capsule::run_capsule_collector::RunCapsuleCollector>,
) -> Result<String, Box<dyn std::error::Error>> {
    let effective_delta = match intent {
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
    let delta_ref = match write_delta_artifact(runtime_root, &effective_delta) {
        Ok(delta_ref) => delta_ref,
        Err(e) => {
            fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
            unreachable!();
        }
    };
    append_event(
        audit,
        AuditEvent::StateDeltaArtifactWritten {
            delta_ref: delta_ref.clone(),
            request_hash: request_hash.to_string(),
        },
    )?;
    let next = match apply_delta_from_artifact(runtime_root, &delta_ref, state) {
        Ok(state) => state,
        Err(e) => {
            fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
            unreachable!();
        }
    };
    save(state_path, &next)?;
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

    let payload = EpisodePayload {
        tick_index,
        intent_kind: intent_kind(intent),
        request_hash: request_hash.to_string(),
        state_delta_ref: delta_ref,
        artifact_refs,
    };
    let prev_hash = match load_episode_head(runtime_root) {
        Ok(head) => head,
        Err(e) => {
            fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
            unreachable!();
        }
    };
    let episode_hash = match append_episode(runtime_root, prev_hash, payload.clone()) {
        Ok(hash) => hash,
        Err(e) => {
            fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
            unreachable!();
        }
    };
    append_event(
        audit,
        AuditEvent::EpisodeAppended {
            episode_hash: episode_hash.clone(),
            artifact_refs_count: payload.artifact_refs.len() as u64,
        },
    )?;
    let update = working_memory.insert(request_hash.to_string(), episode_hash.clone(), tick_index);
    append_event(
        audit,
        AuditEvent::WorkingMemoryUpdated {
            keys_added: update.keys_added,
            keys_evicted: update.keys_evicted,
        },
    )?;
    if open_memory_enabled() {
        let items = match write_open_memory_mirror(runtime_root, &[episode_hash]) {
            Ok(count) => count,
            Err(e) => {
                fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
                unreachable!();
            }
        };
        append_event(
            audit,
            AuditEvent::OpenMemoryMirrorWritten {
                enabled: true,
                items,
            },
        )?;
    }

    if let Err(e) = write_working_snapshot(runtime_root, tick_index, working_memory.entries()) {
        fail_run(audit, audit_path, runtime_root, last_state_hash, e.reason())?;
        unreachable!();
    }
    append_event(
        audit,
        AuditEvent::TickCompleted {
            tick_index,
            state_hash: h.clone(),
            request_hash: request_hash.to_string(),
        },
    )?;

    Ok(h)
}

pub(crate) fn intent_kind(intent: &Intent) -> String {
    match intent {
        Intent::NoOp => "no_op".to_string(),
        Intent::ApplyDelta { .. } => "apply_delta".to_string(),
    }
}
