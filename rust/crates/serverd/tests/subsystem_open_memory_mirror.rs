#![cfg(feature = "bin")]

use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

fn run_serverd(runtime_root: &Path, open_memory: Option<&str>) -> Output {
    let mut cmd = Command::new(common::serverd_exe());
    cmd.arg("--mode")
        .arg("null")
        .arg("--ticks")
        .arg("1")
        .arg("--delta")
        .arg("tick:0")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(value) = open_memory {
        cmd.env("OPEN_MEMORY_ENABLE", value);
    }
    cmd.output().expect("failed to run serverd")
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

#[test]
fn open_memory_requires_enable_flag_and_is_audited() {
    let runtime_root = std::env::temp_dir().join(format!("pie_open_mem_off_{}", Uuid::new_v4()));
    let out = run_serverd(&runtime_root, None);
    assert!(out.status.success(), "run failed");
    let events = read_event_types(&runtime_root);
    assert!(!events.iter().any(|e| e == "open_memory_mirror_written"));

    let runtime_root = std::env::temp_dir().join(format!("pie_open_mem_on_{}", Uuid::new_v4()));
    let out = run_serverd(&runtime_root, Some("1"));
    assert!(out.status.success(), "run failed");
    let events = read_event_types(&runtime_root);
    assert!(events.iter().any(|e| e == "open_memory_mirror_written"));
}
