use pie_common::{canonical_json_bytes, sha256_bytes};
use serverd::tools::policy::{TOOL_APPROVAL_REQUEST_SCHEMA, TOOL_APPROVAL_SCHEMA};
use std::fs;
use std::path::Path;
use std::process::Command;
use uuid::Uuid;
mod common;

fn write_approval_request(
    runtime_root: &Path,
    tool_id: &str,
    request_hash: &str,
    input_ref: &str,
) -> String {
    let value = serde_json::json!({
        "schema": TOOL_APPROVAL_REQUEST_SCHEMA,
        "tool_id": tool_id,
        "request_hash": request_hash,
        "input_ref": input_ref
    });
    let bytes = canonical_json_bytes(&value).expect("canonical request");
    let approval_ref = sha256_bytes(&bytes);
    let dir = runtime_root.join("artifacts").join("approvals");
    fs::create_dir_all(&dir).expect("create approvals dir");
    let trimmed = approval_ref
        .strip_prefix("sha256:")
        .unwrap_or(&approval_ref);
    let path = dir.join(format!("{}.json", trimmed));
    fs::write(path, bytes).expect("write approval request");
    approval_ref
}

fn read_event_payloads(runtime_root: &Path) -> Vec<serde_json::Value> {
    common::read_event_payloads_stage15(runtime_root)
}

fn find_event(events: &[serde_json::Value], event_type: &str) -> serde_json::Value {
    common::find_event(events, event_type)
}

#[test]
fn approve_creates_file_and_audits() {
    let runtime_root = std::env::temp_dir().join(format!("pie_stage15_approve_{}", Uuid::new_v4()));
    let tool_id = "tools.noop";
    let request_hash = sha256_bytes(b"request");
    let input_ref = sha256_bytes(b"input");
    let approval_ref = write_approval_request(&runtime_root, tool_id, &request_hash, &input_ref);

    let out = Command::new(env!("CARGO_BIN_EXE_serverd"))
        .arg("approve")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .arg("--tool")
        .arg(tool_id)
        .arg("--input-ref")
        .arg(&input_ref)
        .output()
        .expect("failed to run serverd approve");
    assert!(
        out.status.success(),
        "approve failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("approve output not json");
    assert_eq!(v.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        v.get("approval_ref").and_then(|v| v.as_str()),
        Some(approval_ref.as_str())
    );

    let trimmed = approval_ref
        .strip_prefix("sha256:")
        .unwrap_or(&approval_ref);
    let approval_path = runtime_root
        .join("approvals")
        .join(format!("{}.approved.json", trimmed));
    let approval_bytes = fs::read(&approval_path).expect("approval file missing");
    let approval_value: serde_json::Value =
        serde_json::from_slice(&approval_bytes).expect("approval file not json");
    assert_eq!(
        approval_value.get("schema").and_then(|v| v.as_str()),
        Some(TOOL_APPROVAL_SCHEMA)
    );
    assert_eq!(
        approval_value.get("approval_ref").and_then(|v| v.as_str()),
        Some(approval_ref.as_str())
    );
    assert_eq!(
        approval_value.get("tool_id").and_then(|v| v.as_str()),
        Some(tool_id)
    );
    assert_eq!(
        approval_value.get("input_ref").and_then(|v| v.as_str()),
        Some(input_ref.as_str())
    );
    assert_eq!(
        approval_value.get("request_hash").and_then(|v| v.as_str()),
        Some(request_hash.as_str())
    );

    let events = read_event_payloads(&runtime_root);
    let event = find_event(&events, "approval_created");
    assert_eq!(event.get("tool_id").and_then(|v| v.as_str()), Some(tool_id));
    assert_eq!(
        event.get("approval_ref").and_then(|v| v.as_str()),
        Some(approval_ref.as_str())
    );
    assert_eq!(
        event.get("input_ref").and_then(|v| v.as_str()),
        Some(input_ref.as_str())
    );
    assert_eq!(
        event.get("request_hash").and_then(|v| v.as_str()),
        Some(request_hash.as_str())
    );
}
