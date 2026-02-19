use crate::audit::succeed_run;
use crate::command::OperatorLearningsAppendArgs;
use crate::mutations::{normalize_line_endings, parse_tags, MAX_LEARNING_BYTES};
use crate::operator_actions::common::{
    emit_completed, emit_error, emit_refused_and_error, emit_requested, prepare_operator_audit,
    OperatorActionTarget, OPERATOR_LEARNINGS_APPEND_ACTION,
};
use crate::skills::{append_learning, SkillRegistry};

const OPERATOR_LEARNING_ENTRY_SCHEMA: &str = "serverd.operator_learning_entry.v1";
const MAX_LEARNING_TAGS: usize = 16;

pub(crate) fn run_operator_learnings_append(
    args: OperatorLearningsAppendArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut audit, audit_path) = match prepare_operator_audit(&args.runtime_root) {
        Ok(value) => value,
        Err(err) => return emit_error(err.reason()),
    };
    let target = OperatorActionTarget {
        run_id: None,
        target_id: Some(args.skill_id.clone()),
        target_ref: None,
    };
    if emit_requested(&mut audit, OPERATOR_LEARNINGS_APPEND_ACTION, &target, None).is_err() {
        return emit_error("operator_audit_failed");
    }

    let text = normalize_line_endings(&args.learning_text);
    if text.trim().is_empty() {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_LEARNINGS_APPEND_ACTION,
            &target,
            "learning_text_empty",
        );
    }
    if text.len() > MAX_LEARNING_BYTES {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_LEARNINGS_APPEND_ACTION,
            &target,
            "learning_text_too_large",
        );
    }
    let tags = match parse_tags(args.tags.as_deref()) {
        Ok(values) => values,
        Err(err) => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_LEARNINGS_APPEND_ACTION,
                &target,
                err.reason(),
            )
        }
    };
    if tags.len() > MAX_LEARNING_TAGS {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_LEARNINGS_APPEND_ACTION,
            &target,
            "learning_tags_too_many",
        );
    }
    let registry = match SkillRegistry::load(&args.runtime_root) {
        Ok(value) => value,
        Err(err) => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_LEARNINGS_APPEND_ACTION,
                &target,
                err.reason(),
            )
        }
    };
    if registry.get(&args.skill_id).is_none() {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_LEARNINGS_APPEND_ACTION,
            &target,
            "skill_id_unknown",
        );
    }
    let mut entry = serde_json::Map::new();
    entry.insert(
        "schema".to_string(),
        serde_json::Value::String(OPERATOR_LEARNING_ENTRY_SCHEMA.to_string()),
    );
    entry.insert("text".to_string(), serde_json::Value::String(text));
    if !tags.is_empty() {
        entry.insert(
            "tags".to_string(),
            serde_json::Value::Array(
                tags.into_iter()
                    .map(serde_json::Value::String)
                    .collect::<Vec<_>>(),
            ),
        );
    }
    let entry_hash = match append_learning(
        &args.runtime_root,
        &args.skill_id,
        serde_json::Value::Object(entry),
        &mut audit,
    ) {
        Ok(value) => value,
        Err(err) => {
            return emit_refused_and_error(
                &mut audit,
                &audit_path,
                OPERATOR_LEARNINGS_APPEND_ACTION,
                &target,
                err.reason(),
            )
        }
    };
    if let Err(err) = emit_completed(
        &mut audit,
        OPERATOR_LEARNINGS_APPEND_ACTION,
        &target,
        None,
        Some(entry_hash.clone()),
    ) {
        return emit_refused_and_error(
            &mut audit,
            &audit_path,
            OPERATOR_LEARNINGS_APPEND_ACTION,
            &target,
            err.reason(),
        );
    }
    let mut payload = serde_json::Map::new();
    payload.insert("ok".to_string(), serde_json::Value::Bool(true));
    payload.insert(
        "action".to_string(),
        serde_json::Value::String(OPERATOR_LEARNINGS_APPEND_ACTION.to_string()),
    );
    payload.insert(
        "skill_id".to_string(),
        serde_json::Value::String(args.skill_id),
    );
    payload.insert(
        "entry_hash".to_string(),
        serde_json::Value::String(entry_hash),
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
