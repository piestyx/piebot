use pie_audit_log::AuditAppender;
use pie_common::{canonical_json_bytes, sha256_bytes};
use serverd::skills::SKILL_MANIFEST_SCHEMA;
use serverd::tools::policy::TOOL_APPROVAL_REQUEST_SCHEMA;
use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

fn run_serverd_null(runtime_root: &Path) -> Output {
    Command::new(common::serverd_exe())
        .arg("--mode")
        .arg("null")
        .arg("--ticks")
        .arg("1")
        .arg("--delta")
        .arg("tick:0")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run serverd null")
}

fn run_serverd_operator(runtime_root: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(common::serverd_exe());
    cmd.arg("operator")
        .args(args)
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.output().expect("failed to run serverd operator")
}

fn read_event_payloads(runtime_root: &Path) -> Vec<serde_json::Value> {
    common::read_event_payloads_stage15(runtime_root)
}

fn find_event(events: &[serde_json::Value], event_type: &str) -> serde_json::Value {
    common::find_event(events, event_type)
}

fn count_events(events: &[serde_json::Value], event_type: &str) -> usize {
    events
        .iter()
        .filter(|event| event.get("event_type").and_then(|v| v.as_str()) == Some(event_type))
        .count()
}

fn write_skill_manifest(runtime_root: &Path, skill_id: &str) {
    let dir = runtime_root.join("skills").join(skill_id);
    fs::create_dir_all(&dir).expect("create skills dir");
    let manifest = serde_json::json!({
        "schema": SKILL_MANIFEST_SCHEMA,
        "skill_id": skill_id,
        "allowed_tools": [],
        "tool_constraints": [],
        "prompt_template_refs": []
    });
    let bytes = serde_json::to_vec(&manifest).expect("serialize skill manifest");
    fs::write(dir.join("skill.json"), bytes).expect("write skill manifest");
}

fn write_run_with_tool_approval(
    runtime_root: &Path,
    run_id: &str,
    tool_id: &str,
    approval_ref: &str,
    request_hash: &str,
) {
    let logs = runtime_root.join("logs");
    fs::create_dir_all(&logs).expect("create logs dir");
    let audit_path = logs.join("audit_rust.jsonl");
    let mut audit = AuditAppender::open(&audit_path).expect("open audit");
    let final_state_hash =
        "sha256:abababababababababababababababababababababababababababababababab";
    let events = vec![
        serde_json::json!({
            "schema": "serverd.audit.v1",
            "event": {
                "event_type": "run_started",
                "run_id": run_id
            }
        }),
        serde_json::json!({
            "schema": "serverd.audit.v1",
            "event": {
                "event_type": "tool_approval_required",
                "tool_id": tool_id,
                "approval_ref": approval_ref,
                "request_hash": request_hash
            }
        }),
        serde_json::json!({
            "schema": "serverd.audit.v1",
            "event": {
                "event_type": "run_completed",
                "run_id": run_id,
                "final_state_hash": final_state_hash
            }
        }),
    ];
    for event in events {
        audit.append(&event).expect("append audit event");
    }
}

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
    let bytes = canonical_json_bytes(&value).expect("canonical approval request");
    let approval_ref = sha256_bytes(&bytes);
    let dir = runtime_root.join("artifacts").join("approvals");
    fs::create_dir_all(&dir).expect("create approvals artifact dir");
    let trimmed = approval_ref
        .strip_prefix("sha256:")
        .unwrap_or(approval_ref.as_str());
    fs::write(dir.join(format!("{}.json", trimmed)), bytes).expect("write approval request");
    approval_ref
}

#[test]
fn operator_approve_creates_approval_and_audits_lifecycle() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_operator_approve_{}", Uuid::new_v4()));
    fs::create_dir_all(&runtime_root).expect("create runtime root");
    let run_id = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let tool_id = "tools.noop";
    let request_hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let input_ref = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    let approval_ref = write_approval_request(&runtime_root, tool_id, request_hash, input_ref);
    write_run_with_tool_approval(&runtime_root, run_id, tool_id, &approval_ref, request_hash);

    let out = run_serverd_operator(
        &runtime_root,
        &[
            "approve",
            "--run-id",
            run_id,
            "--tool-id",
            tool_id,
            "--reason",
            "operator confirmed request",
        ],
    );
    assert!(
        out.status.success(),
        "operator approve failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("operator approve output not json");
    assert_eq!(value.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        value.get("approval_ref").and_then(|v| v.as_str()),
        Some(approval_ref.as_str())
    );

    let out_repeat = run_serverd_operator(
        &runtime_root,
        &[
            "approve",
            "--run-id",
            run_id,
            "--tool-id",
            tool_id,
            "--reason",
            "operator confirmed request",
        ],
    );
    assert!(out_repeat.status.success(), "repeat approve failed");
    let repeat_value: serde_json::Value =
        serde_json::from_slice(&out_repeat.stdout).expect("repeat output not json");
    assert_eq!(
        repeat_value.get("approval_ref").and_then(|v| v.as_str()),
        Some(approval_ref.as_str())
    );

    let trimmed = approval_ref
        .strip_prefix("sha256:")
        .unwrap_or(approval_ref.as_str());
    let approved_path = runtime_root
        .join("approvals")
        .join(format!("{}.approved.json", trimmed));
    assert!(approved_path.is_file(), "missing approval file");

    let events = read_event_payloads(&runtime_root);
    let completed_event = find_event(&events, "operator_action_completed");
    let completed_artifact_ref = completed_event
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("missing completed artifact_ref");
    let completed_artifact_hash = completed_event
        .get("artifact_hash")
        .and_then(|v| v.as_str())
        .expect("missing completed artifact_hash");
    assert_eq!(completed_artifact_ref, approval_ref.as_str());
    assert_ne!(
        completed_artifact_hash, completed_artifact_ref,
        "artifact_hash should be hash of file bytes, not approval ref"
    );
    let approval_bytes = fs::read(&approved_path).expect("read approval file");
    let expected_approval_bytes_hash = sha256_bytes(&approval_bytes);
    assert_eq!(
        completed_artifact_hash,
        expected_approval_bytes_hash.as_str()
    );
    assert!(count_events(&events, "operator_action_requested") >= 1);
    assert!(count_events(&events, "approval_created") >= 1);
    assert!(count_events(&events, "operator_action_completed") >= 1);
}

#[test]
fn operator_approve_unknown_run_refuses_fail_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_operator_approve_refuse_{}", Uuid::new_v4()));
    fs::create_dir_all(runtime_root.join("logs")).expect("create logs");
    let out = run_serverd_operator(
        &runtime_root,
        &[
            "approve",
            "--run-id",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--tool-id",
            "tools.noop",
            "--reason",
            "approve unknown run",
            "--input-ref",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ],
    );
    assert!(!out.status.success(), "approve should fail");
    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("operator approve output not json");
    assert_eq!(value.get("ok").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(
        value.get("error").and_then(|v| v.as_str()),
        Some("run_id_unknown")
    );
    let events = read_event_payloads(&runtime_root);
    assert_eq!(count_events(&events, "operator_action_requested"), 1);
    assert_eq!(count_events(&events, "operator_action_refused"), 1);
}

#[test]
fn operator_learnings_append_deterministic_hash_across_runtimes() {
    let runtime_one =
        std::env::temp_dir().join(format!("pie_operator_learning_one_{}", Uuid::new_v4()));
    let runtime_two =
        std::env::temp_dir().join(format!("pie_operator_learning_two_{}", Uuid::new_v4()));
    write_skill_manifest(&runtime_one, "demo");
    write_skill_manifest(&runtime_two, "demo");

    let out_one = run_serverd_operator(
        &runtime_one,
        &[
            "learnings",
            "append",
            "--skill-id",
            "demo",
            "--learning-text",
            "keep responses deterministic",
            "--tags",
            "ops, deterministic, ops",
        ],
    );
    let out_two = run_serverd_operator(
        &runtime_two,
        &[
            "learnings",
            "append",
            "--skill-id",
            "demo",
            "--learning-text",
            "keep responses deterministic",
            "--tags",
            "ops, deterministic, ops",
        ],
    );
    assert!(out_one.status.success(), "learning append one failed");
    assert!(out_two.status.success(), "learning append two failed");
    let one_value: serde_json::Value =
        serde_json::from_slice(&out_one.stdout).expect("learning output one not json");
    let two_value: serde_json::Value =
        serde_json::from_slice(&out_two.stdout).expect("learning output two not json");
    let hash_one = one_value
        .get("entry_hash")
        .and_then(|v| v.as_str())
        .expect("missing hash one");
    let hash_two = two_value
        .get("entry_hash")
        .and_then(|v| v.as_str())
        .expect("missing hash two");
    assert_eq!(hash_one, hash_two);

    let learnings_path = runtime_one
        .join("skills")
        .join("demo")
        .join("learnings.jsonl");
    let line = fs::read_to_string(learnings_path)
        .expect("read learnings")
        .lines()
        .next()
        .expect("missing learning line")
        .to_string();
    let value: serde_json::Value = serde_json::from_str(&line).expect("learning line not json");
    assert_eq!(
        value.get("schema").and_then(|v| v.as_str()),
        Some("serverd.operator_learning_entry.v1")
    );
    let events = read_event_payloads(&runtime_one);
    let skill_event = find_event(&events, "skill_learning_appended");
    assert_eq!(
        skill_event.get("skill_id").and_then(|v| v.as_str()),
        Some("demo")
    );
    assert_eq!(
        count_events(&events, "operator_action_completed"),
        1,
        "expected one completed operator event"
    );
}

#[test]
fn operator_replay_verify_stable_for_fixture_run_and_reports_mismatch() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_operator_replay_verify_{}", Uuid::new_v4()));
    let out_run = run_serverd_null(&runtime_root);
    assert!(
        out_run.status.success(),
        "null run failed: {}",
        String::from_utf8_lossy(&out_run.stderr)
    );
    let run_value: serde_json::Value =
        serde_json::from_slice(&out_run.stdout).expect("run output not json");
    let run_id = run_value
        .get("run_id")
        .and_then(|v| v.as_str())
        .expect("missing run_id")
        .to_string();

    let out_verify_one = run_serverd_operator(
        &runtime_root,
        &["replay-verify", "--run-id", run_id.as_str()],
    );
    assert!(out_verify_one.status.success(), "verify one failed");
    let verify_one: serde_json::Value =
        serde_json::from_slice(&out_verify_one.stdout).expect("verify one output not json");
    assert_eq!(verify_one.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(verify_one.get("pass").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(
        verify_one
            .get("mismatch_location")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        Some("audit_head_hash".to_string())
    );
    let verification_ref = verify_one
        .get("verification_ref")
        .and_then(|v| v.as_str())
        .expect("missing verification_ref");
    let verification_trimmed = verification_ref
        .strip_prefix("sha256:")
        .unwrap_or(verification_ref);
    let verification_path = runtime_root
        .join("artifacts")
        .join("operator_replay_verify")
        .join(format!("{}.json", verification_trimmed));
    let verification_value: serde_json::Value =
        serde_json::from_slice(&fs::read(&verification_path).expect("read verification artifact"))
            .expect("verification artifact not json");
    let compared_hashes = verification_value
        .get("compared_hashes")
        .and_then(|v| v.as_object())
        .expect("missing compared_hashes");
    assert!(
        compared_hashes
            .get("current_audit_head_hash")
            .and_then(|v| v.as_str())
            .is_some(),
        "missing compared_hashes.current_audit_head_hash"
    );
    assert!(
        compared_hashes
            .get("capsule_audit_head_hash")
            .and_then(|v| v.as_str())
            .is_some(),
        "missing compared_hashes.capsule_audit_head_hash"
    );
    assert_eq!(
        verification_value.get("pass").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert!(
        verification_value
            .get("compared_hashes")
            .and_then(|v| v.get("current_audit_head_hash"))
            .and_then(|v| v.as_str())
            .is_some(),
        "expected compared_hashes.current_audit_head_hash"
    );
    assert_eq!(
        verification_value
            .get("mismatch_location")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        Some("audit_head_hash".to_string())
    );
}

#[test]
fn operator_capsule_export_deterministic_and_validates_destination() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_operator_capsule_export_{}", Uuid::new_v4()));
    let out_run = run_serverd_null(&runtime_root);
    assert!(
        out_run.status.success(),
        "null run failed: {}",
        String::from_utf8_lossy(&out_run.stderr)
    );
    let run_value: serde_json::Value =
        serde_json::from_slice(&out_run.stdout).expect("run output not json");
    let run_id = run_value
        .get("run_id")
        .and_then(|v| v.as_str())
        .expect("missing run_id")
        .to_string();

    let out_export_one = run_serverd_operator(
        &runtime_root,
        &[
            "capsule-export",
            "--run-id",
            run_id.as_str(),
            "--out",
            "operator_bundle.json",
        ],
    );
    let out_export_two = run_serverd_operator(
        &runtime_root,
        &[
            "capsule-export",
            "--run-id",
            run_id.as_str(),
            "--out",
            "exports/operator_bundle.json",
        ],
    );
    assert!(out_export_one.status.success(), "export one failed");
    assert!(out_export_two.status.success(), "export two failed");
    let export_one: serde_json::Value =
        serde_json::from_slice(&out_export_one.stdout).expect("export one output not json");
    let export_two: serde_json::Value =
        serde_json::from_slice(&out_export_two.stdout).expect("export two output not json");
    assert_eq!(
        export_one.get("export_hash").and_then(|v| v.as_str()),
        export_two.get("export_hash").and_then(|v| v.as_str())
    );
    assert_eq!(
        export_one.get("export_path").and_then(|v| v.as_str()),
        Some("exports/operator_bundle.json")
    );

    let out_invalid = run_serverd_operator(
        &runtime_root,
        &[
            "capsule-export",
            "--run-id",
            run_id.as_str(),
            "--out",
            "../escape.json",
        ],
    );
    assert!(!out_invalid.status.success(), "invalid export must fail");
    let invalid_value: serde_json::Value =
        serde_json::from_slice(&out_invalid.stdout).expect("invalid export output not json");
    assert_eq!(
        invalid_value.get("error").and_then(|v| v.as_str()),
        Some("export_path_invalid")
    );
    let events = read_event_payloads(&runtime_root);
    assert!(count_events(&events, "operator_action_refused") >= 1);
}
