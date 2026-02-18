#![cfg(feature = "bin")]

use pie_common::{canonical_json_bytes, sha256_bytes};
use std::fs;
use std::path::Path;
use std::process::Command;
use uuid::Uuid;
mod common;

const LEARNING_SCHEMA: &str = "serverd.learning_entry.v1";

fn run_learn(
    runtime_root: &Path,
    text: &str,
    tags: Option<&str>,
    source: Option<&str>,
) -> std::process::Output {
    let mut cmd = Command::new(common::serverd_exe());
    cmd.arg("learn")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--text")
        .arg(text);
    if let Some(tags) = tags {
        cmd.arg("--tags").arg(tags);
    }
    if let Some(source) = source {
        cmd.arg("--source").arg(source);
    }
    cmd.output().expect("failed to run serverd learn")
}

fn read_event_payloads(runtime_root: &Path) -> Vec<serde_json::Value> {
    common::read_event_payloads_stage15(runtime_root)
}

fn find_events(events: &[serde_json::Value], event_type: &str) -> Vec<serde_json::Value> {
    events
        .iter()
        .filter(|event| event.get("event_type").and_then(|v| v.as_str()) == Some(event_type))
        .cloned()
        .collect()
}

#[test]
fn learn_appends_canonical_entries_and_audits() {
    let runtime_root = std::env::temp_dir().join(format!("pie_stage15_learn_{}", Uuid::new_v4()));
    fs::create_dir_all(&runtime_root).expect("create runtime root");

    let out = run_learn(
        &runtime_root,
        "hello\r\nworld",
        Some("b, a, a"),
        Some("operator"),
    );
    assert!(
        out.status.success(),
        "learn failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("learn output not json");
    assert_eq!(v.get("ok").and_then(|v| v.as_bool()), Some(true));
    let entry_hash = v
        .get("entry_hash")
        .and_then(|v| v.as_str())
        .expect("missing entry_hash");

    let path = runtime_root.join("learnings").join("learnings.jsonl");
    let contents = fs::read_to_string(&path).expect("missing learnings.jsonl");
    let mut lines = contents.lines();
    let first = lines.next().expect("missing first entry");
    let value: serde_json::Value = serde_json::from_str(first).expect("entry not json");
    assert_eq!(
        value.get("schema").and_then(|v| v.as_str()),
        Some(LEARNING_SCHEMA)
    );
    assert_eq!(
        value.get("text").and_then(|v| v.as_str()),
        Some("hello\nworld")
    );
    let tags = value
        .get("tags")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let tags: Vec<String> = tags
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert_eq!(tags, vec!["a".to_string(), "b".to_string()]);
    assert_eq!(
        value.get("source").and_then(|v| v.as_str()),
        Some("operator")
    );
    let canonical = canonical_json_bytes(&value).expect("canonical entry");
    assert_eq!(first.as_bytes(), canonical.as_slice());
    let expected_hash = sha256_bytes(&canonical);
    assert_eq!(entry_hash, expected_hash.as_str());

    let out2 = run_learn(&runtime_root, "second", None, None);
    assert!(out2.status.success());
    let v2: serde_json::Value =
        serde_json::from_slice(&out2.stdout).expect("learn output not json");
    let entry_hash2 = v2
        .get("entry_hash")
        .and_then(|v| v.as_str())
        .expect("missing entry_hash");

    let contents = fs::read_to_string(&path).expect("missing learnings.jsonl");
    let all: Vec<&str> = contents.lines().collect();
    assert_eq!(all.len(), 2);
    let second_value: serde_json::Value =
        serde_json::from_str(all[1]).expect("second entry not json");
    let canonical2 = canonical_json_bytes(&second_value).expect("canonical entry");
    let expected_hash2 = sha256_bytes(&canonical2);
    assert_eq!(entry_hash2, expected_hash2.as_str());

    let events = read_event_payloads(&runtime_root);
    let learn_events = find_events(&events, "learning_appended");
    assert_eq!(learn_events.len(), 2);
    let event_hash = learn_events[0]
        .get("entry_hash")
        .and_then(|v| v.as_str())
        .expect("event missing entry_hash");
    assert_eq!(event_hash, expected_hash.as_str());
}
