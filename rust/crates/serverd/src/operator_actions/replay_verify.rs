use crate::audit::{filter_events_for_run, succeed_run};
use crate::capsule::run_capsule::RunCapsule;
use crate::command::OperatorReplayVerifyArgs;
use crate::mutations::{
    map_audit_read_error, read_audit_events_checked, read_capsule_bytes, resolve_capsule_ref,
    MutationError,
};
use crate::operator_actions::common::{
    emit_completed, emit_error, emit_refused_and_error, emit_requested, prepare_operator_audit,
    OperatorActionTarget, OPERATOR_REPLAY_VERIFY_ACTION,
};
use crate::runtime::artifacts::{is_sha256_ref, write_json_artifact_atomic};
use pie_audit_log::verify_log;
use pie_common::sha256_bytes;
use std::path::Path;

const OPERATOR_REPLAY_VERIFY_RESULT_SCHEMA: &str = "serverd.operator_replay_verify_result.v1";

pub(crate) fn run_operator_replay_verify(
    args: OperatorReplayVerifyArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut audit, audit_path) = match prepare_operator_audit(&args.runtime_root) {
        Ok(value) => value,
        Err(err) => return emit_error(err.reason()),
    };
    let mut target = OperatorActionTarget {
        run_id: args.run_id.clone(),
        target_id: None,
        target_ref: args.capsule_ref.clone(),
    };
    if emit_requested(&mut audit, OPERATOR_REPLAY_VERIFY_ACTION, &target, None).is_err() {
        return emit_error("operator_audit_failed");
    }

    let (run_id, capsule_ref, run_events) = match resolve_run_and_capsule(&args) {
        Ok(value) => value,
        Err(err) => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_REPLAY_VERIFY_ACTION,
                &target,
                err.reason(),
            )
        }
    };
    target.run_id = Some(run_id.clone());
    target.target_ref = Some(capsule_ref.clone());

    let capsule_bytes = match read_capsule_bytes(&args.runtime_root, &capsule_ref) {
        Ok(value) => value,
        Err(err) => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_REPLAY_VERIFY_ACTION,
                &target,
                err.reason(),
            )
        }
    };
    let capsule_hash = sha256_bytes(&capsule_bytes);
    let capsule: RunCapsule = match serde_json::from_slice(&capsule_bytes) {
        Ok(value) => value,
        Err(_) => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_REPLAY_VERIFY_ACTION,
                &target,
                "replay_verify_capsule_invalid",
            )
        }
    };
    if !is_sha256_ref(&capsule.run.run_id) {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_REPLAY_VERIFY_ACTION,
            &target,
            "replay_verify_capsule_invalid",
        );
    }
    let current_audit_head_hash = match verify_log(&audit_path) {
        Ok(value) => value,
        Err(_) => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_REPLAY_VERIFY_ACTION,
                &target,
                "replay_verify_audit_invalid",
            )
        }
    };
    let capsule_audit_head_hash = capsule.audit.audit_head_hash.clone();
    if !is_sha256_ref(&capsule_audit_head_hash) {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_REPLAY_VERIFY_ACTION,
            &target,
            "replay_verify_capsule_invalid",
        );
    }
    let audit_final_state_hash = match final_state_hash_for_run(&run_events) {
        Ok(value) => value,
        Err(err) => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_REPLAY_VERIFY_ACTION,
                &target,
                err.reason(),
            )
        }
    };
    let capsule_final_state_hash = match capsule.state.as_ref() {
        Some(value) if is_sha256_ref(&value.final_state_hash) => value.final_state_hash.clone(),
        _ => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_REPLAY_VERIFY_ACTION,
                &target,
                "replay_verify_capsule_invalid",
            )
        }
    };

    let mut mismatch_location: Option<String> = None;
    let mut pass = true;
    if capsule_hash != capsule_ref {
        mark_mismatch(&mut pass, &mut mismatch_location, "capsule_ref_hash");
    }
    if capsule.run.run_id != run_id {
        mark_mismatch(&mut pass, &mut mismatch_location, "run_id");
    }
    if capsule_final_state_hash != audit_final_state_hash {
        mark_mismatch(&mut pass, &mut mismatch_location, "final_state_hash");
    }
    if capsule_audit_head_hash != current_audit_head_hash {
        mark_mismatch(&mut pass, &mut mismatch_location, "audit_head_hash");
    }

    let mut compared_hashes = serde_json::Map::new();
    compared_hashes.insert(
        "capsule_ref".to_string(),
        serde_json::Value::String(capsule_ref.clone()),
    );
    compared_hashes.insert(
        "capsule_hash".to_string(),
        serde_json::Value::String(capsule_hash.clone()),
    );
    compared_hashes.insert(
        "audit_final_state_hash".to_string(),
        serde_json::Value::String(audit_final_state_hash.clone()),
    );
    compared_hashes.insert(
        "capsule_final_state_hash".to_string(),
        serde_json::Value::String(capsule_final_state_hash.clone()),
    );
    compared_hashes.insert(
        "capsule_audit_head_hash".to_string(),
        serde_json::Value::String(capsule_audit_head_hash),
    );
    compared_hashes.insert(
        "current_audit_head_hash".to_string(),
        serde_json::Value::String(current_audit_head_hash),
    );

    let mut result = serde_json::Map::new();
    result.insert(
        "schema".to_string(),
        serde_json::Value::String(OPERATOR_REPLAY_VERIFY_RESULT_SCHEMA.to_string()),
    );
    result.insert(
        "run_id".to_string(),
        serde_json::Value::String(run_id.clone()),
    );
    result.insert(
        "capsule_ref".to_string(),
        serde_json::Value::String(capsule_ref.clone()),
    );
    result.insert("pass".to_string(), serde_json::Value::Bool(pass));
    result.insert(
        "compared_hashes".to_string(),
        serde_json::Value::Object(compared_hashes),
    );
    if let Some(location) = mismatch_location.as_ref() {
        result.insert(
            "mismatch_location".to_string(),
            serde_json::Value::String(location.clone()),
        );
    }
    let result_value = serde_json::Value::Object(result);
    let verification_ref = match write_json_artifact_atomic(
        &args.runtime_root,
        "operator_replay_verify",
        &result_value,
    ) {
        Ok(value) => value,
        Err(err) => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_REPLAY_VERIFY_ACTION,
                &target,
                err.reason(),
            )
        }
    };
    if let Err(err) = emit_completed(
        &mut audit,
        OPERATOR_REPLAY_VERIFY_ACTION,
        &target,
        Some(verification_ref.clone()),
        Some(verification_ref.clone()),
    ) {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_REPLAY_VERIFY_ACTION,
            &target,
            err.reason(),
        );
    }
    let mut payload = serde_json::Map::new();
    payload.insert("ok".to_string(), serde_json::Value::Bool(true));
    payload.insert(
        "action".to_string(),
        serde_json::Value::String(OPERATOR_REPLAY_VERIFY_ACTION.to_string()),
    );
    payload.insert("run_id".to_string(), serde_json::Value::String(run_id));
    payload.insert(
        "capsule_ref".to_string(),
        serde_json::Value::String(capsule_ref),
    );
    payload.insert(
        "verification_ref".to_string(),
        serde_json::Value::String(verification_ref),
    );
    payload.insert("pass".to_string(), serde_json::Value::Bool(pass));
    if let Some(location) = mismatch_location {
        payload.insert(
            "mismatch_location".to_string(),
            serde_json::Value::String(location),
        );
    }
    payload.insert(
        "audit_hash".to_string(),
        serde_json::Value::String(audit.last_hash().to_string()),
    );
    succeed_run(
        &mut audit,
        &audit_path,
        serde_json::Value::Object(payload),
        false,
    )
}

fn resolve_run_and_capsule(
    args: &OperatorReplayVerifyArgs,
) -> Result<(String, String, Vec<serde_json::Value>), MutationError> {
    match (args.run_id.as_ref(), args.capsule_ref.as_ref()) {
        (Some(run_id), None) => {
            if !is_sha256_ref(run_id) {
                return Err(MutationError::new("run_id_invalid"));
            }
            let run_events = read_run_events(&args.runtime_root, run_id)?;
            let capsule_ref = resolve_capsule_ref(&run_events)?;
            Ok((run_id.clone(), capsule_ref, run_events))
        }
        (None, Some(capsule_ref)) => {
            if !is_sha256_ref(capsule_ref) {
                return Err(MutationError::new("capsule_ref_invalid"));
            }
            let capsule_bytes = read_capsule_bytes(&args.runtime_root, capsule_ref)?;
            let capsule: RunCapsule = serde_json::from_slice(&capsule_bytes)
                .map_err(|_| MutationError::new("replay_verify_capsule_invalid"))?;
            if !is_sha256_ref(&capsule.run.run_id) {
                return Err(MutationError::new("replay_verify_capsule_invalid"));
            }
            let run_events = read_run_events(&args.runtime_root, &capsule.run.run_id)?;
            let run_capsule_ref = resolve_capsule_ref(&run_events)?;
            if run_capsule_ref != *capsule_ref {
                return Err(MutationError::new("replay_verify_capsule_mismatch"));
            }
            Ok((capsule.run.run_id, capsule_ref.clone(), run_events))
        }
        _ => Err(MutationError::new("replay_verify_input_invalid")),
    }
}

fn read_run_events(
    runtime_root: &Path,
    run_id: &str,
) -> Result<Vec<serde_json::Value>, MutationError> {
    let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
    let events = read_audit_events_checked(&audit_path)?;
    let run_exists = events.iter().any(|event| {
        event.get("event_type").and_then(|v| v.as_str()) == Some("run_started")
            && event.get("run_id").and_then(|v| v.as_str()) == Some(run_id)
    });
    if !run_exists {
        return Err(MutationError::new("run_id_unknown"));
    }
    filter_events_for_run(&events, run_id).map_err(map_audit_read_error)
}

fn final_state_hash_for_run(run_events: &[serde_json::Value]) -> Result<String, MutationError> {
    for event in run_events.iter().rev() {
        if event.get("event_type").and_then(|v| v.as_str()) != Some("run_completed") {
            continue;
        }
        let final_state_hash = event
            .get("final_state_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MutationError::new("replay_verify_result_invalid"))?;
        if !is_sha256_ref(final_state_hash) {
            return Err(MutationError::new("replay_verify_result_invalid"));
        }
        return Ok(final_state_hash.to_string());
    }
    Err(MutationError::new("replay_verify_result_invalid"))
}

fn mark_mismatch(pass: &mut bool, mismatch_location: &mut Option<String>, location: &str) {
    *pass = false;
    if mismatch_location.is_none() {
        *mismatch_location = Some(location.to_string());
    }
}
