use pie_audit_log::AuditAppender;
use pie_common::{canonical_json_bytes, sha256_bytes};
use serverd::skills::{
    append_learning, enforce_tool_call, load_skill_context, skill_manifest_hash, SkillRegistry,
    SKILL_MANIFEST_SCHEMA,
};
use serverd::tools::execute::{ToolCall, TOOL_CALL_SCHEMA, TOOL_INPUT_NOOP_SCHEMA};
use serverd::tools::ToolId;
use std::fs;
use std::path::Path;
use std::process::Command;
use uuid::Uuid;
mod common;

fn audit_appender(runtime_root: &Path) -> AuditAppender {
    let path = runtime_root.join("logs").join("audit_rust.jsonl");
    AuditAppender::open(path).expect("open audit log")
}

fn write_skill_manifest(
    runtime_root: &Path,
    skill_id: &str,
    allowed_tools: &[&str],
    tool_constraints: Vec<serde_json::Value>,
) {
    let dir = runtime_root.join("skills").join(skill_id);
    fs::create_dir_all(&dir).expect("create skills dir");
    let value = serde_json::json!({
        "schema": SKILL_MANIFEST_SCHEMA,
        "skill_id": skill_id,
        "allowed_tools": allowed_tools,
        "tool_constraints": tool_constraints,
        "prompt_template_refs": []
    });
    let bytes = serde_json::to_vec(&value).expect("serialize skill manifest");
    fs::write(dir.join("skill.json"), bytes).expect("write skill manifest");
}

fn write_tool_input(runtime_root: &Path, value: serde_json::Value) -> String {
    let dir = runtime_root.join("artifacts").join("tool_inputs");
    fs::create_dir_all(&dir).expect("create tool inputs dir");
    let bytes = canonical_json_bytes(&value).expect("canonical tool input");
    let hash = sha256_bytes(&bytes);
    let trimmed = hash.strip_prefix("sha256:").unwrap_or(&hash);
    let path = dir.join(format!("{}.json", trimmed));
    fs::write(path, bytes).expect("write tool input");
    hash
}

fn read_event_payloads(runtime_root: &Path) -> Vec<serde_json::Value> {
    common::read_event_payloads(runtime_root)
}

fn find_event(events: &[serde_json::Value], event_type: &str) -> serde_json::Value {
    common::find_event(events, event_type)
}

#[test]
fn skill_registry_deterministic_load_order() {
    let runtime_root = std::env::temp_dir().join(format!("pie_skills_order_{}", Uuid::new_v4()));
    write_skill_manifest(&runtime_root, "skill.a", &["tools.noop"], vec![]);
    write_skill_manifest(&runtime_root, "skill.z", &["tools.noop"], vec![]);
    write_skill_manifest(&runtime_root, "skill.m", &["tools.noop"], vec![]);

    let registry = SkillRegistry::load(&runtime_root).expect("load skills");
    assert_eq!(
        registry.skill_ids(),
        vec![
            "skill.a".to_string(),
            "skill.m".to_string(),
            "skill.z".to_string()
        ]
    );
}

#[test]
fn skill_manifest_hash_deterministic_across_runtimes() {
    let runtime_one = std::env::temp_dir().join(format!("pie_skill_hash_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_skill_hash_two_{}", Uuid::new_v4()));
    write_skill_manifest(&runtime_one, "demo", &["tools.noop"], vec![]);
    write_skill_manifest(&runtime_two, "demo", &["tools.noop"], vec![]);

    let reg_one = SkillRegistry::load(&runtime_one).expect("load skills one");
    let reg_two = SkillRegistry::load(&runtime_two).expect("load skills two");
    let hash_one =
        skill_manifest_hash(reg_one.get("demo").expect("manifest one")).expect("hash one");
    let hash_two =
        skill_manifest_hash(reg_two.get("demo").expect("manifest two")).expect("hash two");
    assert_eq!(hash_one, hash_two);
}

#[test]
fn skill_manifest_invalid_schema_fails_closed() {
    let runtime_root = std::env::temp_dir().join(format!("pie_skill_invalid_{}", Uuid::new_v4()));
    let dir = runtime_root.join("skills").join("bad");
    fs::create_dir_all(&dir).expect("create skills dir");
    let value = serde_json::json!({
        "schema": "wrong.schema",
        "skill_id": "bad",
        "allowed_tools": ["tools.noop"],
        "tool_constraints": [],
        "prompt_template_refs": []
    });
    let bytes = serde_json::to_vec(&value).expect("serialize skill manifest");
    fs::write(dir.join("skill.json"), bytes).expect("write skill manifest");

    let err = SkillRegistry::load(&runtime_root).expect_err("should fail");
    assert_eq!(err.reason(), "skill_manifest_invalid");
}

#[test]
fn skill_selected_emitted_on_skill_run() {
    let runtime_root = std::env::temp_dir().join(format!("pie_skill_run_{}", Uuid::new_v4()));
    write_skill_manifest(&runtime_root, "demo", &["tools.noop"], vec![]);

    let out = Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("--mode")
        .arg("route")
        .arg("--ticks")
        .arg("1")
        .arg("--delta")
        .arg("tick:0")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--skill")
        .arg("demo")
        .output()
        .expect("failed to run serverd");
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let registry = SkillRegistry::load(&runtime_root).expect("load skills");
    let expected_hash = skill_manifest_hash(registry.get("demo").expect("manifest")).expect("hash");
    let events = read_event_payloads(&runtime_root);
    let event = find_event(&events, "skill_selected");
    assert_eq!(event.get("skill_id").and_then(|v| v.as_str()), Some("demo"));
    assert_eq!(
        event.get("skill_manifest_hash").and_then(|v| v.as_str()),
        Some(expected_hash.as_str())
    );
}

#[test]
fn skill_blocks_disallowed_tool_even_when_policy_allows() {
    let runtime_root = std::env::temp_dir().join(format!("pie_skill_block_{}", Uuid::new_v4()));
    write_skill_manifest(&runtime_root, "demo", &["tools.allowed"], vec![]);
    let ctx = load_skill_context(&runtime_root, "demo").expect("load skill");
    let call = ToolCall {
        schema: TOOL_CALL_SCHEMA.to_string(),
        tool_id: ToolId::parse("tools.noop").expect("tool id"),
        input_ref: Some("sha256:input".to_string()),
        input: None,
        request_hash: "sha256:request".to_string(),
    };
    let mut audit = audit_appender(&runtime_root);
    let err = enforce_tool_call(&runtime_root, &ctx, &call, &mut audit).expect_err("should deny");
    assert_eq!(err.reason(), "skill_tool_not_allowed");

    let events = read_event_payloads(&runtime_root);
    let denied = find_event(&events, "tool_execution_denied");
    assert_eq!(
        denied.get("reason").and_then(|v| v.as_str()),
        Some("skill_tool_not_allowed")
    );
}

#[test]
fn skill_enforces_tool_constraints() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_skill_constraint_{}", Uuid::new_v4()));
    let constraint = serde_json::json!({
        "tool_id": "tools.noop",
        "require": { "schema": TOOL_INPUT_NOOP_SCHEMA }
    });
    write_skill_manifest(&runtime_root, "demo", &["tools.noop"], vec![constraint]);
    let input_ref = write_tool_input(
        &runtime_root,
        serde_json::json!({
            "schema": "serverd.tool_input.noop.v0"
        }),
    );
    let ctx = load_skill_context(&runtime_root, "demo").expect("load skill");
    let call = ToolCall {
        schema: TOOL_CALL_SCHEMA.to_string(),
        tool_id: ToolId::parse("tools.noop").expect("tool id"),
        input_ref: Some(input_ref),
        input: None,
        request_hash: "sha256:request".to_string(),
    };
    let mut audit = audit_appender(&runtime_root);
    let err = enforce_tool_call(&runtime_root, &ctx, &call, &mut audit).expect_err("should deny");
    assert_eq!(err.reason(), "skill_tool_constraint_failed");

    let events = read_event_payloads(&runtime_root);
    let denied = find_event(&events, "tool_execution_denied");
    assert_eq!(
        denied.get("reason").and_then(|v| v.as_str()),
        Some("skill_tool_constraint_failed")
    );
}

#[test]
fn skill_learning_appended_writes_and_audits() {
    let runtime_root = std::env::temp_dir().join(format!("pie_skill_learning_{}", Uuid::new_v4()));
    fs::create_dir_all(runtime_root.join("logs")).expect("create logs dir");
    let mut audit = audit_appender(&runtime_root);
    let entry = serde_json::json!({ "note": "hello" });
    let entry_hash =
        append_learning(&runtime_root, "demo", entry.clone(), &mut audit).expect("append");

    let path = runtime_root
        .join("skills")
        .join("demo")
        .join("learnings.jsonl");
    let contents = fs::read_to_string(path).expect("read learnings");
    let line = contents.lines().next().expect("missing entry");
    let expected = canonical_json_bytes(&entry).expect("canonical entry");
    assert_eq!(line.as_bytes(), expected.as_slice());

    let events = read_event_payloads(&runtime_root);
    let event = find_event(&events, "skill_learning_appended");
    assert_eq!(event.get("skill_id").and_then(|v| v.as_str()), Some("demo"));
    assert_eq!(
        event.get("entry_hash").and_then(|v| v.as_str()),
        Some(entry_hash.as_str())
    );
}
