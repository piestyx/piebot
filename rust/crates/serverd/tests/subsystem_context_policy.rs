#![cfg(feature = "bin")]

use pie_common::{canonical_json_bytes, sha256_bytes};
use serverd::{load_context_policy, CONTEXT_POLICY_SCHEMA};
use serverd::prompt::PROMPT_TEMPLATE_SCHEMA;
use serverd::skills::SKILL_MANIFEST_SCHEMA;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

fn run_serverd_route(runtime_root: &Path, ticks: u64, delta: &str, skill: Option<&str>) -> Output {
    let mut cmd = Command::new(common::serverd_exe());
    cmd.arg("--mode")
        .arg("route")
        .arg("--ticks")
        .arg(ticks.to_string())
        .arg("--delta")
        .arg(delta)
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(skill_id) = skill {
        cmd.arg("--skill").arg(skill_id);
    }
    cmd.output().expect("failed to run serverd")
}
fn write_prompt_template(runtime_root: &Path, template_text: &str) -> String {
    let value = serde_json::json!({
        "schema": PROMPT_TEMPLATE_SCHEMA,
        "template_text": template_text
    });
    let bytes = canonical_json_bytes(&value).expect("canonical prompt template");
    let hash = sha256_bytes(&bytes);
    let trimmed = hash.strip_prefix("sha256:").unwrap_or(&hash);
    let dir = runtime_root.join("artifacts").join("prompt_templates");
    fs::create_dir_all(&dir).expect("create prompt_templates dir");
    let path = dir.join(format!("{}.json", trimmed));
    fs::write(path, bytes).expect("write prompt template");
    format!("prompt_templates/{}", hash)
}

fn write_initial_state(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
}

fn write_skill_manifest(runtime_root: &Path, skill_id: &str, prompt_refs: &[String]) {
    let dir = runtime_root.join("skills").join(skill_id);
    fs::create_dir_all(&dir).expect("create skills dir");
    let value = serde_json::json!({
        "schema": SKILL_MANIFEST_SCHEMA,
        "skill_id": skill_id,
        "allowed_tools": [],
        "tool_constraints": [],
        "prompt_template_refs": prompt_refs
    });
    let bytes = serde_json::to_vec(&value).expect("serialize skill manifest");
    fs::write(dir.join("skill.json"), bytes).expect("write skill manifest");
}

fn write_context_policy(runtime_root: &Path, value: serde_json::Value) {
    let dir = runtime_root.join("context");
    fs::create_dir_all(&dir).expect("create context dir");
    let bytes = serde_json::to_vec(&value).expect("serialize policy");
    fs::write(dir.join("policy.json"), bytes).expect("write policy");
}

fn read_event_types(runtime_root: &Path) -> Vec<String> {
    let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
    let contents = fs::read_to_string(audit_path).expect("failed to read audit log");
    let mut types = Vec::new();

    for (i, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line {}: {}", i + 1, e));
        let envelope = record
            .get("event")
            .unwrap_or_else(|| panic!("line {} missing event", i + 1));
        let inner = envelope
            .get("event")
            .unwrap_or_else(|| panic!("line {} missing inner event", i + 1));
        let event_type = inner
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        types.push(event_type);
    }

    types
}

fn read_event_payloads(runtime_root: &Path) -> Vec<serde_json::Value> {
    common::read_event_payloads(runtime_root)
}

fn find_event(events: &[serde_json::Value], event_type: &str) -> serde_json::Value {
    common::find_event(events, event_type)
}

fn artifact_path(runtime_root: &Path, subdir: &str, artifact_ref: &str) -> PathBuf {
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    runtime_root
        .join("artifacts")
        .join(subdir)
        .join(format!("{}.json", trimmed))
}

#[test]
fn context_policy_defaults_when_missing() {
    let root = std::env::temp_dir().join(format!("pie_ctx_policy_default_{}", Uuid::new_v4()));
    let policy = load_context_policy(&root).expect("load policy");
    assert_eq!(policy.schema, CONTEXT_POLICY_SCHEMA);
    assert!(!policy.enabled);
}

#[test]
fn context_policy_invalid_schema_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_ctx_policy_bad_schema_{}", Uuid::new_v4()));
    write_context_policy(
        &runtime_root,
        serde_json::json!({
            "schema": "wrong.schema",
            "enabled": true,
            "max_items": 1,
            "max_bytes": 100,
            "allowed_namespaces": ["prompt_templates"],
            "ordering": "lexicographic",
            "allow_skill_overrides": false
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0", None);
    assert!(!out.status.success(), "run should fail");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("context_policy_invalid")
    );
    let events = read_event_types(&runtime_root);
    assert_eq!(
        events,
        vec!["run_started", "workspace_policy_loaded", "run_completed"]
    );
}
#[test]
fn context_policy_empty_allowlist_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_ctx_policy_empty_allowlist_{}", Uuid::new_v4()));
    write_context_policy(
        &runtime_root,
        serde_json::json!({
            "schema": CONTEXT_POLICY_SCHEMA,
            "enabled": true,
            "max_items": 1,
            "max_bytes": 100,
            "allowed_namespaces": [],
            "ordering": "lexicographic",
            "allow_skill_overrides": false
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0", None);
    assert!(!out.status.success(), "run should fail");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("context_policy_invalid")
    );
    let events = read_event_types(&runtime_root);
    assert_eq!(
        events,
        vec!["run_started", "workspace_policy_loaded", "run_completed"]
    );
}

#[test]
fn context_policy_rejects_disallowed_namespace() {
    let runtime_root = std::env::temp_dir().join(format!("pie_ctx_policy_ns_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_skill_manifest(
        &runtime_root,
        "demo",
        &[String::from("tools/sha256:template-a")],
    );
    write_context_policy(
        &runtime_root,
        serde_json::json!({
            "schema": CONTEXT_POLICY_SCHEMA,
            "enabled": true,
            "max_items": 5,
            "max_bytes": 1024,
            "allowed_namespaces": ["contexts"],
            "ordering": "stable_manifest_order",
            "allow_skill_overrides": false
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"));
    assert!(!out.status.success(), "run should fail");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("context_namespace_denied")
    );
    let events = read_event_types(&runtime_root);
    assert!(!events.iter().any(|e| e == "provider_request_written"));
}

#[test]
fn context_policy_enforces_item_cap() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_ctx_policy_items_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_skill_manifest(
        &runtime_root,
        "demo",
        &[
            String::from("prompt_templates/sha256:a"),
            String::from("prompt_templates/sha256:b"),
        ],
    );
    write_context_policy(
        &runtime_root,
        serde_json::json!({
            "schema": CONTEXT_POLICY_SCHEMA,
            "enabled": true,
            "max_items": 1,
            "max_bytes": 1024,
            "allowed_namespaces": ["prompt_templates"],
            "ordering": "stable_manifest_order",
            "allow_skill_overrides": false
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"));
    assert!(!out.status.success(), "run should fail");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("context_selection_exceeds_max_items")
    );
}

#[test]
fn context_policy_enforces_byte_cap() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_ctx_policy_bytes_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_skill_manifest(
        &runtime_root,
        "demo",
        &[
            String::from("prompt_templates/sha256:a"),
            String::from("prompt_templates/sha256:b"),
        ],
    );
    write_context_policy(
        &runtime_root,
        serde_json::json!({
            "schema": CONTEXT_POLICY_SCHEMA,
            "enabled": true,
            "max_items": 5,
            "max_bytes": 10,
            "allowed_namespaces": ["prompt_templates"],
            "ordering": "stable_manifest_order",
            "allow_skill_overrides": false
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"));
    assert!(!out.status.success(), "run should fail");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("context_selection_exceeds_max_bytes")
    );
}

#[test]
fn context_selection_deterministic_across_runtimes() {
    let runtime_one =
        std::env::temp_dir().join(format!("pie_ctx_policy_det_one_{}", Uuid::new_v4()));
    let runtime_two =
        std::env::temp_dir().join(format!("pie_ctx_policy_det_two_{}", Uuid::new_v4()));
    for runtime_root in [&runtime_one, &runtime_two] {
        write_initial_state(runtime_root);
        let template_b = write_prompt_template(runtime_root, "template-b");
        let template_a = write_prompt_template(runtime_root, "template-a");
        write_skill_manifest(runtime_root, "demo", &[template_b, template_a]);
        write_context_policy(
            runtime_root,
            serde_json::json!({
                "schema": CONTEXT_POLICY_SCHEMA,
                "enabled": true,
                "max_items": 5,
                "max_bytes": 1024,
                "allowed_namespaces": ["prompt_templates"],
                "ordering": "lexicographic",
                "allow_skill_overrides": false
            }),
        );
    }

    let out_one = run_serverd_route(&runtime_one, 1, "tick:0", Some("demo"));
    let out_two = run_serverd_route(&runtime_two, 1, "tick:0", Some("demo"));
    assert!(out_one.status.success(), "run one failed");
    assert!(out_two.status.success(), "run two failed");

    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let ctx_one = find_event(&events_one, "context_selected");
    let ctx_two = find_event(&events_two, "context_selected");
    let ctx_ref_one = ctx_one
        .get("context_ref")
        .and_then(|v| v.as_str())
        .expect("context_ref one missing");
    let ctx_ref_two = ctx_two
        .get("context_ref")
        .and_then(|v| v.as_str())
        .expect("context_ref two missing");

    let bytes_one =
        fs::read(artifact_path(&runtime_one, "contexts", ctx_ref_one)).expect("read ctx one");
    let bytes_two =
        fs::read(artifact_path(&runtime_two, "contexts", ctx_ref_two)).expect("read ctx two");
    assert_eq!(bytes_one, bytes_two);

    let value: serde_json::Value = serde_json::from_slice(&bytes_one).expect("ctx not json");
    let refs = value
        .get("context_refs")
        .and_then(|v| v.as_array())
        .expect("context_refs missing");
    let got: Vec<&str> = refs.iter().filter_map(|v| v.as_str()).collect();
    let mut expected: Vec<String> = refs
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    expected.sort();
    assert_eq!(got, expected.iter().map(|s| s.as_str()).collect::<Vec<_>>());
}
