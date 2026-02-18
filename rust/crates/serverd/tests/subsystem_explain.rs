#![cfg(feature = "bin")]

use pie_common::{canonical_json_bytes, sha256_bytes};
use serverd::CONTEXT_POLICY_SCHEMA;
use serverd::EXPLAIN_SCHEMA;
use serverd::prompt::PROMPT_TEMPLATE_SCHEMA;
use serverd::skills::SKILL_MANIFEST_SCHEMA;
use std::collections::BTreeSet;
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

fn run_serverd_explain(runtime_root: &Path, capsule_ref: &str) -> Output {
    let mut cmd = Command::new(common::serverd_exe());
    cmd.arg("explain")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--capsule")
        .arg(capsule_ref)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.output().expect("failed to run explain")
}

fn run_serverd_explain_by_run(runtime_root: &Path, run_id: &str) -> Output {
    let mut cmd = Command::new(common::serverd_exe());
    cmd.arg("explain")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--run")
        .arg(run_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.output().expect("failed to run explain")
}

fn write_initial_state(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
}

fn write_context_policy(runtime_root: &Path) {
    let dir = runtime_root.join("context");
    fs::create_dir_all(&dir).expect("create context dir");
    let value = serde_json::json!({
        "schema": CONTEXT_POLICY_SCHEMA,
        "enabled": true,
        "max_items": 5,
        "max_bytes": 2048,
        "allowed_namespaces": ["prompt_templates"],
        "ordering": "lexicographic",
        "allow_skill_overrides": false
    });
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

fn write_router_config(runtime_root: &Path, default_provider: &str) {
    let dir = runtime_root.join("router");
    fs::create_dir_all(&dir).expect("create router dir");
    let value = serde_json::json!({
        "schema": "serverd.router.v1",
        "default_provider": default_provider,
        "routes": [],
        "policy": { "fail_if_unavailable": true }
    });
    let bytes = serde_json::to_vec(&value).expect("serialize router config");
    fs::write(dir.join("config.json"), bytes).expect("write router config");
}

fn read_event_payloads(runtime_root: &Path) -> Vec<serde_json::Value> {
    common::read_event_payloads(runtime_root)
}

fn find_event(events: &[serde_json::Value], event_type: &str) -> serde_json::Value {
    common::find_event(events, event_type)
}

fn find_events(events: &[serde_json::Value], event_type: &str) -> Vec<serde_json::Value> {
    events
        .iter()
        .filter(|event| event.get("event_type").and_then(|v| v.as_str()) == Some(event_type))
        .cloned()
        .collect()
}

fn find_explain_ref_for_capsule(events: &[serde_json::Value], capsule_ref: &str) -> String {
    let mut found: Option<String> = None;
    for event in events {
        if event.get("event_type").and_then(|v| v.as_str()) != Some("explain_written") {
            continue;
        }
        if event.get("capsule_ref").and_then(|v| v.as_str()) != Some(capsule_ref) {
            continue;
        }
        let explain_ref = event
            .get("explain_ref")
            .and_then(|v| v.as_str())
            .expect("explain_ref missing");
        found = Some(explain_ref.to_string());
    }
    found.expect("missing explain_written for capsule")
}

fn collect_related_hashes(explain_value: &serde_json::Value) -> BTreeSet<String> {
    let mut hashes = BTreeSet::new();
    if let Some(findings) = explain_value.get("findings").and_then(|v| v.as_array()) {
        for finding in findings {
            let related = match finding.get("related_hashes").and_then(|v| v.as_array()) {
                Some(values) => values,
                None => continue,
            };
            for value in related {
                if let Some(s) = value.as_str() {
                    hashes.insert(s.to_string());
                }
            }
        }
    }
    hashes
}

fn artifact_path(runtime_root: &Path, subdir: &str, artifact_ref: &str) -> PathBuf {
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    runtime_root
        .join("artifacts")
        .join(subdir)
        .join(format!("{}.json", trimmed))
}

#[test]
fn explain_writes_and_is_secrets_safe() {
    let runtime_root = std::env::temp_dir().join(format!("pie_explain_safe_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_context_policy(&runtime_root);
    write_router_config(&runtime_root, "mock");
    let template_ref = write_prompt_template(&runtime_root, "secret-template");
    write_skill_manifest(&runtime_root, "demo", &[template_ref]);

    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"));
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let events = read_event_payloads(&runtime_root);
    let capsule_event = find_event(&events, "run_capsule_written");
    let capsule_ref = capsule_event
        .get("capsule_ref")
        .and_then(|v| v.as_str())
        .expect("capsule_ref missing");

    let explain_out = run_serverd_explain(&runtime_root, capsule_ref);
    assert!(
        explain_out.status.success(),
        "explain failed: {}",
        String::from_utf8_lossy(&explain_out.stderr)
    );

    let events = read_event_payloads(&runtime_root);
    let explain_event = find_event(&events, "explain_written");
    let explain_ref = explain_event
        .get("explain_ref")
        .and_then(|v| v.as_str())
        .expect("explain_ref missing");
    assert_eq!(
        explain_event.get("capsule_ref").and_then(|v| v.as_str()),
        Some(capsule_ref)
    );
    let explain_path = artifact_path(&runtime_root, "explains", explain_ref);
    let explain_bytes = fs::read(&explain_path).expect("read explain");
    let explain_value: serde_json::Value =
        serde_json::from_slice(&explain_bytes).expect("explain not json");
    assert_eq!(
        explain_value.get("schema").and_then(|v| v.as_str()),
        Some(EXPLAIN_SCHEMA)
    );
    assert_eq!(
        explain_value.get("capsule_ref").and_then(|v| v.as_str()),
        Some(capsule_ref)
    );
    let audit_hash = explain_value
        .get("audit_head_hash")
        .and_then(|v| v.as_str())
        .expect("audit_head_hash missing");
    assert!(audit_hash.starts_with("sha256:"));
    let explain_text = String::from_utf8_lossy(&explain_bytes);
    assert!(
        !explain_text.contains("secret-template"),
        "explain must not contain template text"
    );
}

#[test]
fn explain_works_via_run_id() {
    let runtime_root = std::env::temp_dir().join(format!("pie_explain_run_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_context_policy(&runtime_root);
    write_router_config(&runtime_root, "mock");
    let template_ref = write_prompt_template(&runtime_root, "secret-template");
    write_skill_manifest(&runtime_root, "demo", &[template_ref]);

    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"));
    assert!(out.status.success(), "run failed");

    let events = read_event_payloads(&runtime_root);
    let capsule_event = find_event(&events, "run_capsule_written");
    let capsule_ref = capsule_event
        .get("capsule_ref")
        .and_then(|v| v.as_str())
        .expect("capsule_ref missing");
    let capsule_bytes =
        fs::read(artifact_path(&runtime_root, "run_capsules", capsule_ref)).expect("read capsule");
    let capsule_value: serde_json::Value =
        serde_json::from_slice(&capsule_bytes).expect("capsule not json");
    let run_id = capsule_value
        .get("run")
        .and_then(|v| v.get("run_id"))
        .and_then(|v| v.as_str())
        .expect("run_id missing");

    let explain_out = run_serverd_explain_by_run(&runtime_root, run_id);
    assert!(
        explain_out.status.success(),
        "explain failed: {}",
        String::from_utf8_lossy(&explain_out.stderr)
    );

    let events = read_event_payloads(&runtime_root);
    let explain_ref = find_explain_ref_for_capsule(&events, capsule_ref);
    let explain_bytes =
        fs::read(artifact_path(&runtime_root, "explains", &explain_ref)).expect("read explain");
    let explain_value: serde_json::Value =
        serde_json::from_slice(&explain_bytes).expect("explain not json");
    assert_eq!(
        explain_value.get("schema").and_then(|v| v.as_str()),
        Some(EXPLAIN_SCHEMA)
    );
    assert_eq!(
        explain_value.get("run_id").and_then(|v| v.as_str()),
        Some(run_id)
    );
    let explain_text = String::from_utf8_lossy(&explain_bytes);
    assert!(
        !explain_text.contains("secret-template"),
        "explain must not contain template text"
    );
}

#[test]
fn explain_is_deterministic_across_runtimes() {
    let runtime_one = std::env::temp_dir().join(format!("pie_explain_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_explain_two_{}", Uuid::new_v4()));

    for runtime_root in [&runtime_one, &runtime_two] {
        write_initial_state(runtime_root);
        write_context_policy(runtime_root);
        write_router_config(runtime_root, "mock");
        let template_ref = write_prompt_template(runtime_root, "secret-template");
        write_skill_manifest(runtime_root, "demo", &[template_ref]);
    }

    let out_one = run_serverd_route(&runtime_one, 1, "tick:0", Some("demo"));
    let out_two = run_serverd_route(&runtime_two, 1, "tick:0", Some("demo"));
    assert!(out_one.status.success(), "run one failed");
    assert!(out_two.status.success(), "run two failed");

    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let capsule_one = find_event(&events_one, "run_capsule_written");
    let capsule_two = find_event(&events_two, "run_capsule_written");
    let capsule_ref_one = capsule_one
        .get("capsule_ref")
        .and_then(|v| v.as_str())
        .expect("capsule_ref one missing");
    let capsule_ref_two = capsule_two
        .get("capsule_ref")
        .and_then(|v| v.as_str())
        .expect("capsule_ref two missing");
    assert_eq!(capsule_ref_one, capsule_ref_two);

    let explain_out_one = run_serverd_explain(&runtime_one, capsule_ref_one);
    let explain_out_two = run_serverd_explain(&runtime_two, capsule_ref_two);
    assert!(explain_out_one.status.success(), "explain one failed");
    assert!(explain_out_two.status.success(), "explain two failed");

    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let explain_one = find_event(&events_one, "explain_written");
    let explain_two = find_event(&events_two, "explain_written");
    let explain_ref_one = explain_one
        .get("explain_ref")
        .and_then(|v| v.as_str())
        .expect("explain_ref one missing");
    let explain_ref_two = explain_two
        .get("explain_ref")
        .and_then(|v| v.as_str())
        .expect("explain_ref two missing");
    assert_eq!(explain_ref_one, explain_ref_two);

    let bytes_one = fs::read(artifact_path(&runtime_one, "explains", explain_ref_one))
        .expect("read explain one");
    let bytes_two = fs::read(artifact_path(&runtime_two, "explains", explain_ref_two))
        .expect("read explain two");
    assert_eq!(bytes_one, bytes_two);
}

#[test]
fn explain_does_not_mix_runs_in_same_runtime_root() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_explain_multirun_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_context_policy(&runtime_root);
    write_router_config(&runtime_root, "mock");
    let template_ref = write_prompt_template(&runtime_root, "secret-template");
    write_skill_manifest(&runtime_root, "demo", &[template_ref]);

    let out_one = run_serverd_route(&runtime_root, 1, "tick:1", Some("demo"));
    assert!(out_one.status.success(), "run one failed");
    let out_two = run_serverd_route(&runtime_root, 1, "tick:1", Some("demo"));
    assert!(out_two.status.success(), "run two failed");

    let events = read_event_payloads(&runtime_root);
    let capsule_events = find_events(&events, "run_capsule_written");
    assert_eq!(capsule_events.len(), 2, "expected two run capsules");
    let capsule_ref_one = capsule_events[0]
        .get("capsule_ref")
        .and_then(|v| v.as_str())
        .expect("capsule_ref one missing");
    let capsule_ref_two = capsule_events[1]
        .get("capsule_ref")
        .and_then(|v| v.as_str())
        .expect("capsule_ref two missing");
    assert_ne!(
        capsule_ref_one, capsule_ref_two,
        "capsule refs should differ"
    );

    let capsule_one_bytes = fs::read(artifact_path(
        &runtime_root,
        "run_capsules",
        capsule_ref_one,
    ))
    .expect("read capsule one");
    let capsule_two_bytes = fs::read(artifact_path(
        &runtime_root,
        "run_capsules",
        capsule_ref_two,
    ))
    .expect("read capsule two");
    let capsule_one: serde_json::Value =
        serde_json::from_slice(&capsule_one_bytes).expect("capsule one not json");
    let capsule_two: serde_json::Value =
        serde_json::from_slice(&capsule_two_bytes).expect("capsule two not json");

    let run_id_one = capsule_one
        .get("run")
        .and_then(|v| v.get("run_id"))
        .and_then(|v| v.as_str())
        .expect("run_id one missing");
    let run_id_two = capsule_two
        .get("run")
        .and_then(|v| v.get("run_id"))
        .and_then(|v| v.as_str())
        .expect("run_id two missing");
    let audit_hash_one = capsule_one
        .get("audit")
        .and_then(|v| v.get("audit_head_hash"))
        .and_then(|v| v.as_str())
        .expect("audit_head_hash one missing");
    let audit_hash_two = capsule_two
        .get("audit")
        .and_then(|v| v.get("audit_head_hash"))
        .and_then(|v| v.as_str())
        .expect("audit_head_hash two missing");

    let explain_out_one = run_serverd_explain_by_run(&runtime_root, run_id_one);
    assert!(
        explain_out_one.status.success(),
        "explain one failed: {}",
        String::from_utf8_lossy(&explain_out_one.stderr)
    );
    let explain_out_two = run_serverd_explain_by_run(&runtime_root, run_id_two);
    assert!(
        explain_out_two.status.success(),
        "explain two failed: {}",
        String::from_utf8_lossy(&explain_out_two.stderr)
    );

    let events = read_event_payloads(&runtime_root);
    let explain_ref_one = find_explain_ref_for_capsule(&events, capsule_ref_one);
    let explain_ref_two = find_explain_ref_for_capsule(&events, capsule_ref_two);

    let explain_one_bytes = fs::read(artifact_path(&runtime_root, "explains", &explain_ref_one))
        .expect("read explain one");
    let explain_two_bytes = fs::read(artifact_path(&runtime_root, "explains", &explain_ref_two))
        .expect("read explain two");
    let explain_one: serde_json::Value =
        serde_json::from_slice(&explain_one_bytes).expect("explain one not json");
    let explain_two: serde_json::Value =
        serde_json::from_slice(&explain_two_bytes).expect("explain two not json");

    assert_eq!(
        explain_one.get("run_id").and_then(|v| v.as_str()),
        Some(run_id_one)
    );
    assert_eq!(
        explain_two.get("run_id").and_then(|v| v.as_str()),
        Some(run_id_two)
    );
    assert_eq!(
        explain_one.get("audit_head_hash").and_then(|v| v.as_str()),
        Some(audit_hash_one)
    );
    assert_eq!(
        explain_two.get("audit_head_hash").and_then(|v| v.as_str()),
        Some(audit_hash_two)
    );

    let hashes_one = collect_related_hashes(&explain_one);
    let hashes_two = collect_related_hashes(&explain_two);
    assert!(!hashes_one.is_empty(), "missing related hashes for run one");
    assert!(!hashes_two.is_empty(), "missing related hashes for run two");
    assert!(
        hashes_one.is_disjoint(&hashes_two),
        "explain should not mix request hashes across runs"
    );
}
