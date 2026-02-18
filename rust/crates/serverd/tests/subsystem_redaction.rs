use serverd::redaction::{load_redaction_config, REDACTION_CONFIG_SCHEMA};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

fn run_serverd_route(runtime_root: &Path, ticks: u64, delta: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("--mode")
        .arg("route")
        .arg("--ticks")
        .arg(ticks.to_string())
        .arg("--delta")
        .arg(delta)
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run serverd")
}

fn write_initial_state(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
}

fn write_redaction_config(runtime_root: &Path, value: serde_json::Value) {
    let dir = runtime_root.join("redaction");
    fs::create_dir_all(&dir).expect("create redaction dir");
    let bytes = serde_json::to_vec(&value).expect("serialize config");
    fs::write(dir.join("config.json"), bytes).expect("write config");
}

fn read_event_payloads(runtime_root: &Path) -> Vec<serde_json::Value> {
    common::read_event_payloads(runtime_root)
}

fn read_event_types(runtime_root: &Path) -> Vec<String> {
    read_event_payloads(runtime_root)
        .iter()
        .map(|event| {
            event
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string()
        })
        .collect()
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
fn redaction_config_defaults_when_missing() {
    let root = std::env::temp_dir().join(format!("pie_redaction_default_{}", Uuid::new_v4()));
    let config = load_redaction_config(&root).expect("load config");
    assert_eq!(config.schema, REDACTION_CONFIG_SCHEMA);
    assert!(!config.enabled);
    assert!(config.max_provider_input_bytes > 0);
    assert!(config.strategies.drop_fields.is_empty());
    assert!(config.strategies.redact_fields.is_empty());
    assert!(config.strategies.regex_redactions.is_empty());
}

#[test]
fn redaction_config_invalid_schema_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_redaction_bad_schema_{}", Uuid::new_v4()));
    write_redaction_config(
        &runtime_root,
        serde_json::json!({
            "schema": "wrong.schema",
            "enabled": true,
            "max_provider_input_bytes": 1024,
            "strategies": {
                "drop_fields": [],
                "redact_fields": [],
                "regex_redactions": [],
                "allow_raw_artifacts": false
            }
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(!out.status.success(), "run should fail");

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("redaction_config_invalid")
    );

    let events = read_event_types(&runtime_root);
    assert_eq!(
        events,
        vec!["run_started", "workspace_policy_loaded", "run_completed"]
    );
}
#[test]
fn redaction_config_rejects_deep_field_paths() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_redaction_deep_path_{}", Uuid::new_v4()));
    write_redaction_config(
        &runtime_root,
        serde_json::json!({
            "schema": REDACTION_CONFIG_SCHEMA,
            "enabled": true,
            "max_provider_input_bytes": 1024,
            "strategies": {
                "drop_fields": ["a.b.c"],
                "redact_fields": [],
                "regex_redactions": [],
                "allow_raw_artifacts": false
            }
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(!out.status.success(), "run should fail");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("redaction_config_invalid")
    );
    let events = read_event_types(&runtime_root);
    assert_eq!(
        events,
        vec!["run_started", "workspace_policy_loaded", "run_completed"]
    );
}

#[test]
fn provider_input_is_redacted_and_minimized_deterministically() {
    let runtime_one = std::env::temp_dir().join(format!("pie_redaction_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_redaction_two_{}", Uuid::new_v4()));

    for runtime_root in [&runtime_one, &runtime_two] {
        write_initial_state(runtime_root);
        write_redaction_config(
            runtime_root,
            serde_json::json!({
                "schema": REDACTION_CONFIG_SCHEMA,
                "enabled": true,
                "max_provider_input_bytes": 1024 * 1024,
                "strategies": {
                    "drop_fields": ["observation_hash"],
                    "redact_fields": ["state_hash"],
                    "regex_redactions": [
                        {
                            "name": "intent_kind",
                            "pattern": "no_op",
                            "replace": "noop"
                        }
                    ],
                    "allow_raw_artifacts": false
                }
            }),
        );
    }

    let out_one = run_serverd_route(&runtime_one, 1, "tick:0");
    let out_two = run_serverd_route(&runtime_two, 1, "tick:0");
    assert!(
        out_one.status.success(),
        "run one failed: {}",
        String::from_utf8_lossy(&out_one.stderr)
    );
    assert!(
        out_two.status.success(),
        "run two failed: {}",
        String::from_utf8_lossy(&out_two.stderr)
    );

    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let types_one = read_event_types(&runtime_one);
    let types_two = read_event_types(&runtime_two);
    assert_eq!(types_one, types_two);
    assert!(types_one.iter().any(|e| e == "redaction_config_loaded"));
    assert!(types_one.iter().any(|e| e == "provider_input_redacted"));
    let config_event = find_event(&events_one, "redaction_config_loaded");
    assert!(config_event
        .get("run_id")
        .and_then(|v| v.as_str())
        .is_some());

    let redacted_one = find_event(&events_one, "provider_input_redacted");
    let redacted_two = find_event(&events_two, "provider_input_redacted");
    let input_ref_one = redacted_one
        .get("input_ref")
        .and_then(|v| v.as_str())
        .expect("input_ref one missing");
    let input_ref_two = redacted_two
        .get("input_ref")
        .and_then(|v| v.as_str())
        .expect("input_ref two missing");

    let bytes_one =
        fs::read(artifact_path(&runtime_one, "inputs", input_ref_one)).expect("read input one");
    let bytes_two =
        fs::read(artifact_path(&runtime_two, "inputs", input_ref_two)).expect("read input two");
    assert_eq!(bytes_one, bytes_two);

    let redacted_value: serde_json::Value =
        serde_json::from_slice(&bytes_one).expect("input not json");
    assert!(redacted_value.get("observation_hash").is_none());
    assert_eq!(
        redacted_value
            .get("state_hash")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        "__REDACTED__"
    );
    let intent_kind = redacted_value
        .get("intent")
        .and_then(|v| v.get("kind"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(intent_kind, "noop");
}

#[test]
fn redaction_limit_exceeded_fails_closed() {
    let runtime_root = std::env::temp_dir().join(format!("pie_redaction_limit_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_redaction_config(
        &runtime_root,
        serde_json::json!({
            "schema": REDACTION_CONFIG_SCHEMA,
            "enabled": true,
            "max_provider_input_bytes": 10,
            "strategies": {
                "drop_fields": [],
                "redact_fields": [],
                "regex_redactions": [],
                "allow_raw_artifacts": false
            }
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(!out.status.success(), "run should fail");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("run output not json");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("redaction_limit_exceeded")
    );

    let events = read_event_types(&runtime_root);
    assert!(!events.iter().any(|e| e == "provider_request_written"));
}
