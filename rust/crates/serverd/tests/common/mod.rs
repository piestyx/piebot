#![allow(dead_code)] // Shared across many integration test crates; each crate uses only a subset.
use pie_kernel_state::{save, KernelState};
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub fn serverd_exe() -> std::path::PathBuf {
    // This forces Cargo to provide the path to the built binary.
    // If it isn't provided, that means the binary target wasn't built for this test invocation.
    let p = option_env!("CARGO_BIN_EXE_serverd")
        .expect("CARGO_BIN_EXE_serverd not set. Ensure the serverd binary target is built for tests (bin feature/defaults).");
    std::path::PathBuf::from(p)
}

pub(crate) fn write_initial_state(runtime_root: &Path) {
    let state_dir = runtime_root.join("state");
    fs::create_dir_all(&state_dir).expect("create state dir");
    let state_path = state_dir.join("kernel_state.json");
    let mut state = KernelState::default();
    state.state_id = Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap();
    save(&state_path, &state).expect("write initial state");
}

pub(crate) fn read_event_payloads(runtime_root: &Path) -> Vec<serde_json::Value> {
    let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
    let contents = fs::read_to_string(audit_path).expect("failed to read audit log");
    let mut events = Vec::new();

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
        events.push(inner.clone());
    }

    events
}

pub(crate) fn read_event_payloads_stage15(runtime_root: &Path) -> Vec<serde_json::Value> {
    let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
    let contents = fs::read_to_string(audit_path).expect("failed to read audit log");
    let mut events = Vec::new();
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
        events.push(inner.clone());
    }
    events
}

pub(crate) fn find_event(events: &[serde_json::Value], event_type: &str) -> serde_json::Value {
    for event in events {
        if event.get("event_type").and_then(|v| v.as_str()) == Some(event_type) {
            return event.clone();
        }
    }
    panic!("missing {}", event_type);
}
