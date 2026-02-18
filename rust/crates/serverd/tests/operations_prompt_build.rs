#![cfg(feature = "bin")]

use pie_common::{canonical_json_bytes, sha256_bytes};
use serverd::prompt::PROMPT_TEMPLATE_SCHEMA;
use serverd::skills::SKILL_MANIFEST_SCHEMA;
use serverd::CONTEXT_POLICY_SCHEMA;
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
fn prompt_artifact_deterministic_and_provider_request_uses_prompt_ref() {
    let runtime_one = std::env::temp_dir().join(format!("pie_prompt_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_prompt_two_{}", Uuid::new_v4()));

    for runtime_root in [&runtime_one, &runtime_two] {
        write_initial_state(runtime_root);
        let template_a = write_prompt_template(runtime_root, "secret-template");
        let template_b = write_prompt_template(runtime_root, "template-b");
        let prompt_refs = vec![template_a, template_b];
        write_skill_manifest(runtime_root, "demo", &prompt_refs);
        write_context_policy(
            runtime_root,
            serde_json::json!({
                "schema": CONTEXT_POLICY_SCHEMA,
                "enabled": true,
                "max_items": 5,
                "max_bytes": 2048,
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
    let prompt_one = find_event(&events_one, "prompt_built");
    let prompt_two = find_event(&events_two, "prompt_built");
    let prompt_ref_one = prompt_one
        .get("prompt_ref")
        .and_then(|v| v.as_str())
        .expect("prompt_ref one missing");
    let prompt_ref_two = prompt_two
        .get("prompt_ref")
        .and_then(|v| v.as_str())
        .expect("prompt_ref two missing");

    let bytes_one =
        fs::read(artifact_path(&runtime_one, "prompts", prompt_ref_one)).expect("read prompt one");
    let bytes_two =
        fs::read(artifact_path(&runtime_two, "prompts", prompt_ref_two)).expect("read prompt two");
    assert_eq!(bytes_one, bytes_two);

    let prompt_value: serde_json::Value =
        serde_json::from_slice(&bytes_one).expect("prompt not json");
    assert_eq!(
        prompt_value.get("schema").and_then(|v| v.as_str()),
        Some("serverd.prompt.v1")
    );
    let templates = prompt_value
        .get("template_texts")
        .and_then(|v| v.as_array())
        .expect("template_texts missing");
    assert_eq!(templates.len(), 2);
    let snippets = prompt_value
        .get("context_snippets")
        .and_then(|v| v.as_array())
        .expect("context_snippets missing");
    assert_eq!(snippets.len(), 2);
    let rendered = prompt_value
        .get("rendered")
        .and_then(|v| v.as_str())
        .expect("rendered missing");
    assert!(rendered.contains("secret-template"));

    let req_event = find_event(&events_one, "provider_request_written");
    let req_ref = req_event
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("request ref missing");
    let request_bytes =
        fs::read(artifact_path(&runtime_one, "requests", req_ref)).expect("read request");
    let request_value: serde_json::Value =
        serde_json::from_slice(&request_bytes).expect("request not json");
    let prompt_ref = request_value
        .get("prompt_ref")
        .and_then(|v| v.as_str())
        .expect("prompt_ref missing");
    assert_eq!(prompt_ref, prompt_ref_one);

    let audit_log = fs::read_to_string(runtime_one.join("logs").join("audit_rust.jsonl"))
        .expect("read audit log");
    assert!(!audit_log.contains("secret-template"));
}
