#![cfg(feature = "bin")]

use pie_common::{canonical_json_bytes, sha256_bytes};
use serverd::lenses::LENS_CONFIG_SCHEMA;
use serverd::modes::{MODE_CONFIG_SCHEMA, MODE_PROFILE_SCHEMA, MODE_ROUTE_SCHEMA};
use serverd::output_contract::OUTPUT_CONTRACT_SCHEMA;
use serverd::prompt::PROMPT_TEMPLATE_SCHEMA;
use serverd::retrieval::RETRIEVAL_CONFIG_SCHEMA;
use serverd::skills::SKILL_MANIFEST_SCHEMA;
use serverd::tools::execute::{TOOL_INPUT_NOOP_SCHEMA, TOOL_OUTPUT_NOOP_SCHEMA};
use serverd::tools::policy::TOOL_POLICY_SCHEMA;
use serverd::tools::TOOL_SPEC_SCHEMA;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use uuid::Uuid;
mod common;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn run_serverd_route(
    runtime_root: &Path,
    ticks: u64,
    delta: &str,
    skill: Option<&str>,
    mode_profile: Option<&str>,
    envs: &[(&str, &str)],
) -> Output {
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
    if let Some(mode_profile) = mode_profile {
        cmd.arg("--mode-profile").arg(mode_profile);
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run serverd")
}

fn write_initial_state(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
}

fn write_mode_config(runtime_root: &Path, value: serde_json::Value) {
    let dir = runtime_root.join("modes");
    fs::create_dir_all(&dir).expect("create modes dir");
    let bytes = serde_json::to_vec(&value).expect("serialize mode config");
    fs::write(dir.join("config.json"), bytes).expect("write mode config");
}

fn write_mode_profile(runtime_root: &Path, mode_id: &str, value: serde_json::Value) {
    let dir = runtime_root.join("modes").join("profiles");
    fs::create_dir_all(&dir).expect("create mode profiles dir");
    let bytes = serde_json::to_vec(&value).expect("serialize mode profile");
    fs::write(dir.join(format!("{}.json", mode_id)), bytes).expect("write mode profile");
}

fn write_mode_route(runtime_root: &Path, value: serde_json::Value) {
    let dir = runtime_root.join("modes");
    fs::create_dir_all(&dir).expect("create modes dir");
    let bytes = serde_json::to_vec(&value).expect("serialize mode route");
    fs::write(dir.join("route.json"), bytes).expect("write mode route");
}

fn write_retrieval_config(runtime_root: &Path, value: serde_json::Value) {
    let dir = runtime_root.join("retrieval");
    fs::create_dir_all(&dir).expect("create retrieval dir");
    let bytes = serde_json::to_vec(&value).expect("serialize retrieval config");
    fs::write(dir.join("config.json"), bytes).expect("write retrieval config");
}

fn write_lens_config(runtime_root: &Path, value: serde_json::Value) {
    let dir = runtime_root.join("lenses");
    fs::create_dir_all(&dir).expect("create lenses dir");
    let bytes = serde_json::to_vec(&value).expect("serialize lens config");
    fs::write(dir.join("config.json"), bytes).expect("write lens config");
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

fn write_skill_manifest(
    runtime_root: &Path,
    skill_id: &str,
    allowed_tools: &[&str],
    prompt_template_refs: &[String],
    output_contract: Option<&str>,
) {
    let dir = runtime_root.join("skills").join(skill_id);
    fs::create_dir_all(&dir).expect("create skills dir");
    let value = serde_json::json!({
        "schema": SKILL_MANIFEST_SCHEMA,
        "skill_id": skill_id,
        "allowed_tools": allowed_tools,
        "tool_constraints": [],
        "prompt_template_refs": prompt_template_refs,
        "output_contract": output_contract
    });
    let bytes = serde_json::to_vec(&value).expect("serialize skill manifest");
    fs::write(dir.join("skill.json"), bytes).expect("write skill manifest");
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

fn write_output_contract(runtime_root: &Path, value: serde_json::Value) {
    let dir = runtime_root.join("contracts");
    fs::create_dir_all(&dir).expect("create contracts dir");
    let contract_id = value
        .get("contract_id")
        .and_then(|v| v.as_str())
        .unwrap_or("contract");
    let bytes = serde_json::to_vec(&value).expect("serialize contract");
    fs::write(dir.join(format!("{}.json", contract_id)), bytes).expect("write contract");
}

fn write_noop_tool_spec(runtime_root: &Path) {
    let dir = runtime_root.join("tools");
    fs::create_dir_all(&dir).expect("create tools dir");
    let value = serde_json::json!({
        "schema": TOOL_SPEC_SCHEMA,
        "id": "tools.noop",
        "input_schema": TOOL_INPUT_NOOP_SCHEMA,
        "output_schema": TOOL_OUTPUT_NOOP_SCHEMA,
        "deterministic": true,
        "risk_level": "low",
        "requires_approval": false,
        "requires_arming": false,
        "filesystem": false,
        "version": "v1"
    });
    let bytes = serde_json::to_vec(&value).expect("serialize tool spec");
    fs::write(dir.join("noop.json"), bytes).expect("write tool spec");
}

fn write_tool_policy(runtime_root: &Path, allowed_tools: &[&str]) {
    let dir = runtime_root.join("tools");
    fs::create_dir_all(&dir).expect("create tools dir");
    let value = serde_json::json!({
        "schema": TOOL_POLICY_SCHEMA,
        "allowed_tools": allowed_tools,
        "default_allow": false
    });
    let bytes = serde_json::to_vec(&value).expect("serialize tool policy");
    fs::write(dir.join("policy.json"), bytes).expect("write tool policy");
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

fn base_mode_config(mode_id: &str) -> serde_json::Value {
    serde_json::json!({
        "schema": MODE_CONFIG_SCHEMA,
        "enabled": true,
        "default_mode": mode_id,
        "allowed_modes": [mode_id],
        "max_profile_bytes": 65536
    })
}

fn base_mode_profile(mode_id: &str) -> serde_json::Value {
    serde_json::json!({
        "schema": MODE_PROFILE_SCHEMA,
        "mode_id": mode_id,
        "bias": {}
    })
}

#[test]
fn modes_disabled_no_events() {
    let runtime_root = std::env::temp_dir().join(format!("pie_modes_disabled_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    let out = run_serverd_route(&runtime_root, 1, "tick:0", None, None, &[]);
    assert!(out.status.success(), "run should succeed");
    let events = read_event_payloads(&runtime_root);
    let mode_events: Vec<String> = events
        .iter()
        .filter_map(|event| event.get("event_type").and_then(|v| v.as_str()))
        .filter(|event_type| event_type.starts_with("mode_"))
        .map(|event_type| event_type.to_string())
        .collect();
    assert!(
        mode_events.is_empty(),
        "unexpected mode events: {:?}",
        mode_events
    );
}

#[test]
fn mode_invalid_config_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_modes_invalid_config_{}", Uuid::new_v4()));
    write_mode_config(
        &runtime_root,
        serde_json::json!({
            "schema": "wrong.schema",
            "enabled": true,
            "default_mode": "strict",
            "allowed_modes": ["strict"],
            "max_profile_bytes": 1024
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0", None, None, &[]);
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("mode_config_invalid")
    );
}

#[test]
fn mode_not_allowed_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_modes_not_allowed_{}", Uuid::new_v4()));
    write_mode_config(&runtime_root, base_mode_config("safe"));
    write_mode_profile(&runtime_root, "safe", base_mode_profile("safe"));
    let out = run_serverd_route(&runtime_root, 1, "tick:0", None, Some("strict"), &[]);
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("mode_not_allowed")
    );
}

#[test]
fn mode_route_by_skill_selects_mode() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_modes_route_select_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_skill_manifest(&runtime_root, "demo", &[], &[], None);
    write_mode_config(
        &runtime_root,
        serde_json::json!({
            "schema": MODE_CONFIG_SCHEMA,
            "enabled": true,
            "default_mode": "default",
            "allowed_modes": ["default", "strict"],
            "max_profile_bytes": 65536
        }),
    );
    write_mode_profile(&runtime_root, "default", base_mode_profile("default"));
    write_mode_profile(&runtime_root, "strict", base_mode_profile("strict"));
    write_mode_route(
        &runtime_root,
        serde_json::json!({
            "schema": MODE_ROUTE_SCHEMA,
            "by_skill": {
                "demo": "strict"
            }
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"), None, &[]);
    assert!(out.status.success(), "run should succeed");
    let events = read_event_payloads(&runtime_root);
    let mode_applied = find_event(&events, "mode_applied");
    assert_eq!(
        mode_applied.get("mode_id").and_then(|v| v.as_str()),
        Some("strict")
    );
    let mode_routed = find_event(&events, "mode_routed");
    assert_eq!(
        mode_routed.get("skill_id").and_then(|v| v.as_str()),
        Some("demo")
    );
    assert_eq!(
        mode_routed.get("mode_id").and_then(|v| v.as_str()),
        Some("strict")
    );
    let route_ref = mode_routed
        .get("route_ref")
        .and_then(|v| v.as_str())
        .expect("route_ref");
    let route_artifact = artifact_path(&runtime_root, "mode_routes", route_ref);
    assert!(route_artifact.is_file(), "missing route artifact");
}

#[test]
fn mode_route_rejects_unallowed_mode() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_modes_route_unallowed_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_skill_manifest(&runtime_root, "demo", &[], &[], None);
    write_mode_config(
        &runtime_root,
        serde_json::json!({
            "schema": MODE_CONFIG_SCHEMA,
            "enabled": true,
            "default_mode": "default",
            "allowed_modes": ["default", "strict"],
            "max_profile_bytes": 65536
        }),
    );
    write_mode_profile(&runtime_root, "default", base_mode_profile("default"));
    write_mode_profile(&runtime_root, "strict", base_mode_profile("strict"));
    write_mode_route(
        &runtime_root,
        serde_json::json!({
            "schema": MODE_ROUTE_SCHEMA,
            "by_skill": {
                "demo": "evil"
            }
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"), None, &[]);
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("mode_not_allowed")
    );
}

#[test]
fn mode_profile_override_beats_route() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_modes_route_override_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_skill_manifest(&runtime_root, "demo", &[], &[], None);
    write_mode_config(
        &runtime_root,
        serde_json::json!({
            "schema": MODE_CONFIG_SCHEMA,
            "enabled": true,
            "default_mode": "default",
            "allowed_modes": ["default", "strict"],
            "max_profile_bytes": 65536
        }),
    );
    write_mode_profile(&runtime_root, "default", base_mode_profile("default"));
    write_mode_profile(&runtime_root, "strict", base_mode_profile("strict"));
    write_mode_route(
        &runtime_root,
        serde_json::json!({
            "schema": MODE_ROUTE_SCHEMA,
            "by_skill": {
                "demo": "strict"
            }
        }),
    );
    let out = run_serverd_route(
        &runtime_root,
        1,
        "tick:0",
        Some("demo"),
        Some("default"),
        &[],
    );
    assert!(out.status.success(), "run should succeed");
    let events = read_event_payloads(&runtime_root);
    let mode_applied = find_event(&events, "mode_applied");
    assert_eq!(
        mode_applied.get("mode_id").and_then(|v| v.as_str()),
        Some("default")
    );
    assert!(
        !events
            .iter()
            .any(|event| event.get("event_type").and_then(|v| v.as_str()) == Some("mode_routed")),
        "mode_routed should not be emitted when explicit override is provided"
    );
}

#[test]
fn mode_route_invalid_schema_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_modes_route_invalid_schema_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_skill_manifest(&runtime_root, "demo", &[], &[], None);
    write_mode_config(
        &runtime_root,
        serde_json::json!({
            "schema": MODE_CONFIG_SCHEMA,
            "enabled": true,
            "default_mode": "default",
            "allowed_modes": ["default", "strict"],
            "max_profile_bytes": 65536
        }),
    );
    write_mode_profile(&runtime_root, "default", base_mode_profile("default"));
    write_mode_profile(&runtime_root, "strict", base_mode_profile("strict"));
    write_mode_route(
        &runtime_root,
        serde_json::json!({
            "schema": "wrong.schema",
            "by_skill": {
                "demo": "strict"
            }
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"), None, &[]);
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("mode_route_invalid")
    );
}

#[test]
fn mode_route_unsafe_token_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_modes_route_unsafe_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_skill_manifest(&runtime_root, "demo", &[], &[], None);
    write_mode_config(
        &runtime_root,
        serde_json::json!({
            "schema": MODE_CONFIG_SCHEMA,
            "enabled": true,
            "default_mode": "default",
            "allowed_modes": ["default", "strict"],
            "max_profile_bytes": 65536
        }),
    );
    write_mode_profile(&runtime_root, "default", base_mode_profile("default"));
    write_mode_profile(&runtime_root, "strict", base_mode_profile("strict"));
    write_mode_route(
        &runtime_root,
        serde_json::json!({
            "schema": MODE_ROUTE_SCHEMA,
            "by_skill": {
                "demo/unsafe": "strict"
            }
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"), None, &[]);
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("mode_route_invalid")
    );
}

#[test]
fn mode_profile_missing_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_modes_missing_profile_{}", Uuid::new_v4()));
    write_mode_config(&runtime_root, base_mode_config("safe"));
    let out = run_serverd_route(&runtime_root, 1, "tick:0", None, None, &[]);
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("mode_profile_missing")
    );
}

#[test]
fn mode_overlay_retrieval_intersection_empty_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_modes_retrieval_empty_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_retrieval_config(
        &runtime_root,
        serde_json::json!({
            "schema": RETRIEVAL_CONFIG_SCHEMA,
            "enabled": true,
            "sources": ["working"],
            "namespaces_allowlist": ["contexts"],
            "max_items": 32,
            "max_bytes": 65536,
            "default_recency_ticks": 32,
            "default_tags": []
        }),
    );
    write_mode_config(&runtime_root, base_mode_config("strict"));
    write_mode_profile(
        &runtime_root,
        "strict",
        serde_json::json!({
            "schema": MODE_PROFILE_SCHEMA,
            "mode_id": "strict",
            "bias": {
                "retrieval": {
                    "namespaces_allowlist": ["working"]
                }
            }
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0", None, None, &[]);
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("mode_retrieval_empty_allowlist")
    );
}

#[test]
fn mode_profile_deterministic_across_two_runtimes() {
    let runtime_one = std::env::temp_dir().join(format!("pie_modes_det_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_modes_det_two_{}", Uuid::new_v4()));
    for runtime_root in [&runtime_one, &runtime_two] {
        write_initial_state(runtime_root);
        write_retrieval_config(
            runtime_root,
            serde_json::json!({
                "schema": RETRIEVAL_CONFIG_SCHEMA,
                "enabled": true,
                "sources": ["working", "episodic"],
                "namespaces_allowlist": ["contexts", "working"],
                "max_items": 32,
                "max_bytes": 65536,
                "default_recency_ticks": 32,
                "default_tags": []
            }),
        );
        write_lens_config(
            runtime_root,
            serde_json::json!({
                "schema": LENS_CONFIG_SCHEMA,
                "enabled": true,
                "allowed_lenses": ["salience_v1", "dedup_v1", "recency_v1"],
                "max_output_bytes": 65536,
                "max_candidates": 64,
                "recency_ticks": 8,
                "top_per_group": 3
            }),
        );
        write_mode_config(runtime_root, base_mode_config("strict"));
        write_mode_profile(
            runtime_root,
            "strict",
            serde_json::json!({
                "schema": MODE_PROFILE_SCHEMA,
                "mode_id": "strict",
                "bias": {
                    "retrieval": {
                        "sources": ["working"],
                        "namespaces_allowlist": ["contexts"]
                    },
                    "lenses": {
                        "allowed_lenses": ["salience_v1", "dedup_v1"],
                        "max_candidates": 16
                    }
                }
            }),
        );
    }
    let out_one = run_serverd_route(&runtime_one, 1, "tick:0", None, None, &[]);
    let out_two = run_serverd_route(&runtime_two, 1, "tick:0", None, None, &[]);
    assert!(out_one.status.success(), "run one failed");
    assert!(out_two.status.success(), "run two failed");
    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let mode_applied_one = find_event(&events_one, "mode_applied");
    let mode_applied_two = find_event(&events_two, "mode_applied");
    let mode_hash_one = mode_applied_one
        .get("mode_hash")
        .and_then(|v| v.as_str())
        .expect("mode hash one");
    let mode_hash_two = mode_applied_two
        .get("mode_hash")
        .and_then(|v| v.as_str())
        .expect("mode hash two");
    assert_eq!(mode_hash_one, mode_hash_two);

    let mut one_files: Vec<String> =
        fs::read_dir(runtime_one.join("artifacts").join("mode_applied"))
            .expect("mode_applied one")
            .filter_map(|entry| {
                entry
                    .ok()
                    .and_then(|entry| entry.file_name().to_str().map(|s| s.to_string()))
            })
            .collect();
    let mut two_files: Vec<String> =
        fs::read_dir(runtime_two.join("artifacts").join("mode_applied"))
            .expect("mode_applied two")
            .filter_map(|entry| {
                entry
                    .ok()
                    .and_then(|entry| entry.file_name().to_str().map(|s| s.to_string()))
            })
            .collect();
    one_files.sort();
    two_files.sort();
    assert_eq!(one_files, two_files);
    assert_eq!(one_files.len(), 1);
    let bytes_one = fs::read(
        runtime_one
            .join("artifacts")
            .join("mode_applied")
            .join(&one_files[0]),
    )
    .expect("read mode_applied one");
    let bytes_two = fs::read(
        runtime_two
            .join("artifacts")
            .join("mode_applied")
            .join(&two_files[0]),
    )
    .expect("read mode_applied two");
    assert_eq!(bytes_one, bytes_two);
}

#[test]
fn mode_applies_prompt_template() {
    let runtime_root = std::env::temp_dir().join(format!("pie_modes_prompt_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    let template_a = write_prompt_template(&runtime_root, "template-a");
    let template_b = write_prompt_template(&runtime_root, "template-b");
    write_skill_manifest(
        &runtime_root,
        "demo",
        &[],
        &[template_a.clone(), template_b.clone()],
        None,
    );
    write_mode_config(&runtime_root, base_mode_config("prompt_only"));
    write_mode_profile(
        &runtime_root,
        "prompt_only",
        serde_json::json!({
            "schema": MODE_PROFILE_SCHEMA,
            "mode_id": "prompt_only",
            "bias": {
                "prompt": {
                    "template_id": template_b
                }
            }
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0", Some("demo"), None, &[]);
    assert!(out.status.success(), "run should succeed");

    let events = read_event_payloads(&runtime_root);
    let prompt_built = find_event(&events, "prompt_built");
    let prompt_ref = prompt_built
        .get("prompt_ref")
        .and_then(|v| v.as_str())
        .expect("prompt_ref");
    let prompt_bytes =
        fs::read(artifact_path(&runtime_root, "prompts", prompt_ref)).expect("prompt bytes");
    let prompt_value: serde_json::Value =
        serde_json::from_slice(&prompt_bytes).expect("prompt json");
    let prompt_templates: Vec<String> = prompt_value
        .get("prompt_template_refs")
        .and_then(|v| v.as_array())
        .expect("prompt_template_refs")
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert_eq!(prompt_templates, vec![template_b.clone()]);
    let template_texts: Vec<String> = prompt_value
        .get("template_texts")
        .and_then(|v| v.as_array())
        .expect("template_texts")
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert_eq!(template_texts, vec!["template-b".to_string()]);

    let context_selected = find_event(&events, "context_selected");
    let context_ref = context_selected
        .get("context_ref")
        .and_then(|v| v.as_str())
        .expect("context_ref");
    let context_bytes =
        fs::read(artifact_path(&runtime_root, "contexts", context_ref)).expect("context bytes");
    let context_value: serde_json::Value =
        serde_json::from_slice(&context_bytes).expect("context json");
    let context_refs: Vec<String> = context_value
        .get("context_refs")
        .and_then(|v| v.as_array())
        .expect("context_refs")
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert_eq!(context_refs, vec![template_a, template_b]);
}

#[test]
fn mode_tool_tightening_denies_execution() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let runtime_root = std::env::temp_dir().join(format!("pie_modes_tool_deny_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_router_config(&runtime_root, "mock_tool");
    write_noop_tool_spec(&runtime_root);
    write_tool_policy(&runtime_root, &["tools.noop"]);
    write_skill_manifest(
        &runtime_root,
        "demo",
        &["tools.noop"],
        &[],
        Some("demo.contract"),
    );
    write_output_contract(
        &runtime_root,
        serde_json::json!({
            "schema": OUTPUT_CONTRACT_SCHEMA,
            "contract_id": "demo.contract",
            "allowed_tool_calls": ["tools.noop"],
            "allowed_fields": ["schema", "output", "tool_call"],
            "required_fields": ["schema", "output", "tool_call"],
            "field_constraints": {
                "schema": { "type": "string" },
                "output": { "type": "string" },
                "tool_call.tool_id": { "type": "string" },
                "tool_call.input_ref": { "type": "string" }
            }
        }),
    );
    write_mode_config(&runtime_root, base_mode_config("deny_tools"));
    write_mode_profile(
        &runtime_root,
        "deny_tools",
        serde_json::json!({
            "schema": MODE_PROFILE_SCHEMA,
            "mode_id": "deny_tools",
            "bias": {
                "tools": {
                    "deny_tools": ["tools.noop"]
                }
            }
        }),
    );

    let out = run_serverd_route(
        &runtime_root,
        1,
        "tick:0",
        Some("demo"),
        None,
        &[("TOOLS_ENABLE", "1"), ("TOOLS_ARM", "1")],
    );
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("tool_not_allowed")
    );
    let events = read_event_payloads(&runtime_root);
    let denied = find_event(&events, "tool_execution_denied");
    assert_eq!(
        denied.get("reason").and_then(|v| v.as_str()),
        Some("tool_not_allowed")
    );
}

#[test]
fn mode_keeps_lens_requires_retrieval_fail_closed() {
    let runtime_root = std::env::temp_dir().join(format!(
        "pie_modes_lens_requires_retrieval_{}",
        Uuid::new_v4()
    ));
    write_initial_state(&runtime_root);
    write_lens_config(
        &runtime_root,
        serde_json::json!({
            "schema": LENS_CONFIG_SCHEMA,
            "enabled": true,
            "allowed_lenses": ["dedup_v1"],
            "max_output_bytes": 65536,
            "max_candidates": 16
        }),
    );
    write_mode_config(&runtime_root, base_mode_config("safe"));
    write_mode_profile(&runtime_root, "safe", base_mode_profile("safe"));
    let out = run_serverd_route(&runtime_root, 1, "tick:0", None, None, &[]);
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("lens_requires_retrieval")
    );
}
