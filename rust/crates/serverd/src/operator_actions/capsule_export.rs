use crate::audit::{append_event, succeed_run, AuditEvent};
use crate::capsule::run_capsule::RunCapsule;
use crate::command::OperatorCapsuleExportArgs;
use crate::mutations::{
    read_capsule_bytes, resolve_capsule_ref, resolve_export_path, write_export_file, MutationError,
};
use crate::operator_actions::common::{
    emit_completed, emit_error, emit_refused_and_error, emit_requested, prepare_operator_audit,
    read_run_events_for_run_id, OperatorActionTarget, OPERATOR_CAPSULE_EXPORT_ACTION,
};
use crate::runtime::artifacts::is_sha256_ref;
use pie_common::sha256_bytes;

pub(crate) fn run_operator_capsule_export(
    args: OperatorCapsuleExportArgs,
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
    if emit_requested(&mut audit, OPERATOR_CAPSULE_EXPORT_ACTION, &target, None).is_err() {
        return emit_error("operator_audit_failed");
    }

    let (resolved_run_id, capsule_ref) = match resolve_capsule_target(&args) {
        Ok(value) => value,
        Err(err) => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_CAPSULE_EXPORT_ACTION,
                &target,
                err.reason(),
            )
        }
    };
    target.run_id = resolved_run_id.clone();
    target.target_ref = Some(capsule_ref.clone());

    let capsule_bytes = match read_capsule_bytes(&args.runtime_root, &capsule_ref) {
        Ok(value) => value,
        Err(err) => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_CAPSULE_EXPORT_ACTION,
                &target,
                err.reason(),
            )
        }
    };
    let (export_path, export_rel) =
        match resolve_export_path(&args.runtime_root, &capsule_ref, Some(&args.out)) {
            Ok(value) => value,
            Err(err) => {
                return emit_refused_and_error(
                    &mut audit,
                    &audit_path,
                    OPERATOR_CAPSULE_EXPORT_ACTION,
                    &target,
                    err.reason(),
                )
            }
        };
    if let Err(err) = write_export_file(&export_path, &capsule_bytes) {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_CAPSULE_EXPORT_ACTION,
            &target,
            err.reason(),
        );
    }
    let export_hash = sha256_bytes(&capsule_bytes);
    if append_event(
        &mut audit,
        AuditEvent::CapsuleExported {
            capsule_ref: capsule_ref.clone(),
            export_hash: export_hash.clone(),
            export_path: export_rel.clone(),
        },
    )
    .is_err()
    {
        return emit_error("operator_audit_failed");
    }
    if let Err(err) = emit_completed(
        &mut audit,
        OPERATOR_CAPSULE_EXPORT_ACTION,
        &target,
        Some(export_rel.clone()),
        Some(export_hash.clone()),
    ) {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_CAPSULE_EXPORT_ACTION,
            &target,
            err.reason(),
        );
    }
    let mut payload = serde_json::Map::new();
    payload.insert("ok".to_string(), serde_json::Value::Bool(true));
    payload.insert(
        "action".to_string(),
        serde_json::Value::String(OPERATOR_CAPSULE_EXPORT_ACTION.to_string()),
    );
    if let Some(run_id) = resolved_run_id {
        payload.insert("run_id".to_string(), serde_json::Value::String(run_id));
    }
    payload.insert(
        "capsule_ref".to_string(),
        serde_json::Value::String(capsule_ref),
    );
    payload.insert(
        "export_hash".to_string(),
        serde_json::Value::String(export_hash),
    );
    payload.insert(
        "export_path".to_string(),
        serde_json::Value::String(export_rel),
    );
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

fn resolve_capsule_target(
    args: &OperatorCapsuleExportArgs,
) -> Result<(Option<String>, String), MutationError> {
    match (args.run_id.as_ref(), args.capsule_ref.as_ref()) {
        (Some(run_id), None) => {
            if !is_sha256_ref(run_id) {
                return Err(MutationError::new("run_id_invalid"));
            }
            let run_events = read_run_events_for_run_id(&args.runtime_root, run_id)?;
            let capsule_ref = resolve_capsule_ref(&run_events)?;
            Ok((Some(run_id.clone()), capsule_ref))
        }
        (None, Some(capsule_ref)) => {
            if !is_sha256_ref(capsule_ref) {
                return Err(MutationError::new("capsule_ref_invalid"));
            }
            let capsule_bytes = read_capsule_bytes(&args.runtime_root, capsule_ref)?;
            let capsule: RunCapsule = serde_json::from_slice(&capsule_bytes)
                .map_err(|_| MutationError::new("capsule_ref_invalid"))?;
            if !is_sha256_ref(&capsule.run.run_id) {
                return Err(MutationError::new("capsule_ref_invalid"));
            }
            Ok((Some(capsule.run.run_id), capsule_ref.clone()))
        }
        _ => Err(MutationError::new("capsule_export_target_invalid")),
    }
}
