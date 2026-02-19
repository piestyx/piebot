use pie_audit_log::AuditAppender;
use pie_common::{canonical_json_bytes, sha256_bytes};
use pie_kernel_state::{apply_delta, state_hash, KernelState, StateDelta};
use serverd::state_delta_artifact::{
    apply_delta_from_artifact, write_delta_artifact, STATE_DELTA_ARTIFACT_SCHEMA,
};
use serverd::tools::execute::{
    execute_tool, TOOL_INPUT_NOOP_SCHEMA, TOOL_OUTPUT_NOOP_SCHEMA, TOOL_OUTPUT_SCHEMA,
};
use serverd::tools::policy::{
    PolicyConfig, PolicyOutcome, ToolPolicy, ToolPolicyInput, TOOL_APPROVAL_SCHEMA,
    TOOL_POLICY_SCHEMA,
};
use serverd::tools::{
    RiskLevel, ToolId, ToolRegistry, ToolSpec, TOOL_REGISTRY_SCHEMA, TOOL_SPEC_SCHEMA,
};
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use uuid::Uuid;

fn write_tool_spec(runtime_root: &Path, filename: &str, tool_id: &str) {
    let dir = runtime_root.join("tools");
    fs::create_dir_all(&dir).expect("create tools dir");
    let value = serde_json::json!({
        "schema": TOOL_SPEC_SCHEMA,
        "id": tool_id,
        "input_schema": "serverd.tool_input.noop.v1",
        "output_schema": "serverd.tool_output.noop.v1",
        "deterministic": true,
        "risk_level": "low",
        "requires_approval": false,
        "requires_arming": false,
        "filesystem": false,
        "version": "v1"
    });
    let bytes = serde_json::to_vec(&value).expect("serialize tool spec");
    fs::write(dir.join(filename), bytes).expect("write tool spec");
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

fn registry_hash(registry: &ToolRegistry) -> String {
    let value = registry.as_registry_value();
    let schema = value.get("schema").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(schema, TOOL_REGISTRY_SCHEMA);
    let bytes = canonical_json_bytes(&value).expect("canonical json");
    sha256_bytes(&bytes)
}

fn sample_spec() -> ToolSpec {
    ToolSpec {
        schema: TOOL_SPEC_SCHEMA.to_string(),
        id: ToolId::parse("tool.noop").expect("tool id"),
        input_schema: "serverd.tool_input.noop.v1".to_string(),
        output_schema: "serverd.tool_output.noop.v1".to_string(),
        deterministic: true,
        risk_level: RiskLevel::Low,
        requires_approval: false,
        requires_arming: false,
        filesystem: false,
        version: "v1".to_string(),
    }
}

fn policy_input<'a>(spec: &'a ToolSpec) -> ToolPolicyInput<'a> {
    ToolPolicyInput {
        tool_id: &spec.id,
        spec,
        mode: "route",
        request_hash: "sha256:request",
        input_ref: "sha256:input",
    }
}

fn policy_input_for_tool<'a>(
    spec: &'a ToolSpec,
    input_ref: &'a str,
    request_hash: &'a str,
) -> ToolPolicyInput<'a> {
    ToolPolicyInput {
        tool_id: &spec.id,
        spec,
        mode: "route",
        request_hash,
        input_ref,
    }
}
fn audit_appender(runtime_root: &Path) -> AuditAppender {
    let path = runtime_root.join("logs").join("audit_rust.jsonl");
    AuditAppender::open(path).expect("open audit log")
}

fn write_approval_file(runtime_root: &Path, approval_ref: &str, input: &ToolPolicyInput<'_>) {
    let value = serde_json::json!({
        "schema": TOOL_APPROVAL_SCHEMA,
        "approval_ref": approval_ref,
        "tool_id": input.tool_id.as_str(),
        "request_hash": input.request_hash,
        "input_ref": input.input_ref
    });
    let dir = runtime_root.join("approvals");
    fs::create_dir_all(&dir).expect("create approvals dir");
    let trimmed = approval_ref.strip_prefix("sha256:").unwrap_or(approval_ref);
    let path = dir.join(format!("{}.approved.json", trimmed));
    let bytes = serde_json::to_vec(&value).expect("serialize approval");
    fs::write(path, bytes).expect("write approval");
}

fn write_tool_input(runtime_root: &Path) -> String {
    let dir = runtime_root.join("artifacts").join("tool_inputs");
    fs::create_dir_all(&dir).expect("create tool inputs dir");
    let value = serde_json::json!({
        "schema": TOOL_INPUT_NOOP_SCHEMA
    });
    let bytes = canonical_json_bytes(&value).expect("canonical tool input");
    let hash = sha256_bytes(&bytes);
    let trimmed = hash.strip_prefix("sha256:").unwrap_or(&hash);
    let path = dir.join(format!("{}.json", trimmed));
    fs::write(path, bytes).expect("write tool input");
    hash
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

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn tool_registry_deterministic_load_order() {
    let runtime_root = std::env::temp_dir().join(format!("pie_tools_order_{}", Uuid::new_v4()));
    write_tool_spec(&runtime_root, "a.json", "tool.a");
    write_tool_spec(&runtime_root, "z.json", "tool.z");
    write_tool_spec(&runtime_root, "m.json", "tool.m");

    let registry = ToolRegistry::load_tools(&runtime_root).expect("load tools");
    assert_eq!(
        registry.tool_ids(),
        vec![
            "tool.a".to_string(),
            "tool.m".to_string(),
            "tool.z".to_string()
        ]
    );
}

#[test]
fn tool_registry_hash_deterministic_across_runtimes() {
    let runtime_one = std::env::temp_dir().join(format!("pie_tools_hash_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_tools_hash_two_{}", Uuid::new_v4()));

    write_tool_spec(&runtime_one, "z.json", "tool.z");
    write_tool_spec(&runtime_one, "a.json", "tool.a");
    write_tool_spec(&runtime_one, "m.json", "tool.m");

    write_tool_spec(&runtime_two, "m.json", "tool.m");
    write_tool_spec(&runtime_two, "z.json", "tool.z");
    write_tool_spec(&runtime_two, "a.json", "tool.a");

    let reg_one = ToolRegistry::load_tools(&runtime_one).expect("load tools one");
    let reg_two = ToolRegistry::load_tools(&runtime_two).expect("load tools two");

    assert_eq!(registry_hash(&reg_one), registry_hash(&reg_two));
}

#[test]
fn tool_registry_fails_closed_on_invalid_spec() {
    let runtime_root = std::env::temp_dir().join(format!("pie_tools_invalid_{}", Uuid::new_v4()));
    let dir = runtime_root.join("tools");
    fs::create_dir_all(&dir).expect("create tools dir");
    let value = serde_json::json!({
        "schema": "wrong.schema",
        "id": "tool.noop",
        "input_schema": "serverd.tool_input.noop.v1",
        "output_schema": "serverd.tool_output.noop.v1",
        "deterministic": true,
        "risk_level": "low",
        "requires_approval": false,
        "requires_arming": false,
        "filesystem": false,
        "version": "v1"
    });
    let bytes = serde_json::to_vec(&value).expect("serialize tool spec");
    fs::write(dir.join("bad.json"), bytes).expect("write tool spec");

    let err = ToolRegistry::load_tools(&runtime_root).expect_err("should fail");
    assert_eq!(err.reason(), "tool_spec_invalid");
}

#[test]
fn tool_registry_ignores_policy_json() {
    let runtime_root = std::env::temp_dir().join(format!("pie_tools_policy_{}", Uuid::new_v4()));
    write_noop_tool_spec(&runtime_root);
    write_tool_policy(&runtime_root, &["tools.noop"]);

    let registry = ToolRegistry::load_tools(&runtime_root).expect("load tools");
    assert!(registry
        .get(&ToolId::parse("tools.noop").expect("tool id"))
        .is_some());
}

#[test]
fn tool_policy_denies_when_tools_disabled() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("TOOLS_ENABLE");
    std::env::remove_var("TOOLS_ARM");
    let runtime_root = std::env::temp_dir().join(format!("pie_policy_disabled_{}", Uuid::new_v4()));
    let mut audit = audit_appender(&runtime_root);
    let spec = sample_spec();
    let input = policy_input(&spec);
    let config = PolicyConfig {
        schema: TOOL_POLICY_SCHEMA.to_string(),
        allowed_tools: vec![spec.id.as_str().to_string()],
        default_allow: false,
    };
    let outcome = ToolPolicy::check(&input, &config, &runtime_root, &mut audit).expect("check");
    assert!(matches!(
        outcome,
        PolicyOutcome::Denied {
            reason: "tools_disabled"
        }
    ));
    std::env::remove_var("TOOLS_ENABLE");
    std::env::remove_var("TOOLS_ARM");
}

#[test]
fn delta_artifact_ref_deterministic_across_runtimes() {
    let runtime_one = std::env::temp_dir().join(format!("pie_delta_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_delta_two_{}", Uuid::new_v4()));
    let delta = StateDelta::SetTag {
        key: "k".to_string(),
        value: "v".to_string(),
    };
    let ref_one = write_delta_artifact(&runtime_one, &delta).expect("write delta one");
    let ref_two = write_delta_artifact(&runtime_two, &delta).expect("write delta two");
    assert_eq!(ref_one, ref_two);
    let trimmed = ref_one.strip_prefix("sha256:").unwrap_or(&ref_one);
    let path_one = runtime_one
        .join("artifacts")
        .join("state_deltas")
        .join(format!("{}.json", trimmed));
    let path_two = runtime_two
        .join("artifacts")
        .join("state_deltas")
        .join(format!("{}.json", trimmed));
    let bytes_one = fs::read(path_one).expect("read delta one");
    let bytes_two = fs::read(path_two).expect("read delta two");
    assert_eq!(bytes_one, bytes_two);
    let value: serde_json::Value = serde_json::from_slice(&bytes_one).expect("parse delta");
    assert_eq!(
        value.get("schema").and_then(|v| v.as_str()),
        Some(STATE_DELTA_ARTIFACT_SCHEMA)
    );
}

#[test]
fn replay_equivalence_from_delta_artifact() {
    let runtime_root = std::env::temp_dir().join(format!("pie_delta_replay_{}", Uuid::new_v4()));
    let delta = StateDelta::TickAdvance { by: 2 };
    let delta_ref = write_delta_artifact(&runtime_root, &delta).expect("write delta");
    let mut base = KernelState::default();
    base.state_id = Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap();
    let from_artifact =
        apply_delta_from_artifact(&runtime_root, &delta_ref, base.clone()).expect("apply artifact");
    let direct = apply_delta(base, &delta);
    assert_eq!(state_hash(&from_artifact), state_hash(&direct));
}

#[test]
fn noop_tool_executes_and_writes_output() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("TOOLS_ENABLE", "1");
    std::env::remove_var("TOOLS_ARM");
    let runtime_root = std::env::temp_dir().join(format!("pie_tool_noop_{}", Uuid::new_v4()));
    write_noop_tool_spec(&runtime_root);
    let registry = ToolRegistry::load_tools(&runtime_root).expect("load tools");
    let spec = registry
        .get(&ToolId::parse("tools.noop").expect("tool id"))
        .expect("spec");
    let input_ref = write_tool_input(&runtime_root);
    let input = policy_input_for_tool(spec, &input_ref, "sha256:request");
    let config = PolicyConfig {
        schema: TOOL_POLICY_SCHEMA.to_string(),
        allowed_tools: vec![spec.id.as_str().to_string()],
        default_allow: false,
    };
    let mut audit = audit_appender(&runtime_root);
    let output_ref =
        execute_tool(&runtime_root, &registry, &config, &input, None, &mut audit).expect("execute");
    let trimmed = output_ref.strip_prefix("sha256:").unwrap_or(&output_ref);
    let path = runtime_root
        .join("artifacts")
        .join("tool_outputs")
        .join(format!("{}.json", trimmed));
    assert!(path.exists());
    let bytes = fs::read(path).expect("read tool output");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("parse tool output");
    assert_eq!(
        value.get("schema").and_then(|v| v.as_str()),
        Some(TOOL_OUTPUT_SCHEMA)
    );
    let output = value.get("output").expect("output");
    assert_eq!(
        output.get("schema").and_then(|v| v.as_str()),
        Some(TOOL_OUTPUT_NOOP_SCHEMA)
    );
    std::env::remove_var("TOOLS_ENABLE");
    std::env::remove_var("TOOLS_ARM");
}

#[test]
fn tool_execution_deterministic_across_runtimes() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("TOOLS_ENABLE", "1");
    std::env::remove_var("TOOLS_ARM");
    let runtime_one = std::env::temp_dir().join(format!("pie_tool_det_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_tool_det_two_{}", Uuid::new_v4()));
    write_noop_tool_spec(&runtime_one);
    write_noop_tool_spec(&runtime_two);
    let registry_one = ToolRegistry::load_tools(&runtime_one).expect("load tools one");
    let registry_two = ToolRegistry::load_tools(&runtime_two).expect("load tools two");
    let spec_one = registry_one
        .get(&ToolId::parse("tools.noop").expect("tool id"))
        .expect("spec one");
    let spec_two = registry_two
        .get(&ToolId::parse("tools.noop").expect("tool id"))
        .expect("spec two");
    let input_ref_one = write_tool_input(&runtime_one);
    let input_ref_two = write_tool_input(&runtime_two);
    assert_eq!(input_ref_one, input_ref_two);
    let config_one = PolicyConfig {
        schema: TOOL_POLICY_SCHEMA.to_string(),
        allowed_tools: vec![spec_one.id.as_str().to_string()],
        default_allow: false,
    };
    let config_two = PolicyConfig {
        schema: TOOL_POLICY_SCHEMA.to_string(),
        allowed_tools: vec![spec_two.id.as_str().to_string()],
        default_allow: false,
    };
    let mut audit_one = audit_appender(&runtime_one);
    let mut audit_two = audit_appender(&runtime_two);
    let input_one = policy_input_for_tool(spec_one, &input_ref_one, "sha256:request");
    let input_two = policy_input_for_tool(spec_two, &input_ref_two, "sha256:request");
    let output_one = execute_tool(
        &runtime_one,
        &registry_one,
        &config_one,
        &input_one,
        None,
        &mut audit_one,
    )
    .expect("exec one");
    let output_two = execute_tool(
        &runtime_two,
        &registry_two,
        &config_two,
        &input_two,
        None,
        &mut audit_two,
    )
    .expect("exec two");
    assert_eq!(output_one, output_two);
    let bytes_one = fs::read(
        runtime_one
            .join("artifacts")
            .join("tool_outputs")
            .join(format!(
                "{}.json",
                output_one.strip_prefix("sha256:").unwrap_or(&output_one)
            )),
    )
    .expect("read output one");
    let bytes_two = fs::read(
        runtime_two
            .join("artifacts")
            .join("tool_outputs")
            .join(format!(
                "{}.json",
                output_two.strip_prefix("sha256:").unwrap_or(&output_two)
            )),
    )
    .expect("read output two");
    assert_eq!(bytes_one, bytes_two);
    std::env::remove_var("TOOLS_ENABLE");
    std::env::remove_var("TOOLS_ARM");
}

#[test]
fn tool_execution_denied_without_tools_enable() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("TOOLS_ENABLE");
    std::env::remove_var("TOOLS_ARM");
    let runtime_root = std::env::temp_dir().join(format!("pie_tool_denied_{}", Uuid::new_v4()));
    write_noop_tool_spec(&runtime_root);
    let registry = ToolRegistry::load_tools(&runtime_root).expect("load tools");
    let spec = registry
        .get(&ToolId::parse("tools.noop").expect("tool id"))
        .expect("spec");
    let input_ref = write_tool_input(&runtime_root);
    let input = policy_input_for_tool(spec, &input_ref, "sha256:request");
    let config = PolicyConfig {
        schema: TOOL_POLICY_SCHEMA.to_string(),
        allowed_tools: vec![spec.id.as_str().to_string()],
        default_allow: false,
    };
    let mut audit = audit_appender(&runtime_root);
    let err = execute_tool(&runtime_root, &registry, &config, &input, None, &mut audit)
        .expect_err("should deny");
    assert_eq!(err.reason(), "tools_disabled");
    std::env::remove_var("TOOLS_ENABLE");
    std::env::remove_var("TOOLS_ARM");
}

#[test]
fn tool_policy_needs_approval_until_file_present() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("TOOLS_ENABLE", "1");
    std::env::set_var("TOOLS_ARM", "1");
    let runtime_root = std::env::temp_dir().join(format!("pie_policy_approval_{}", Uuid::new_v4()));
    let mut audit = audit_appender(&runtime_root);
    let mut spec = sample_spec();
    spec.requires_approval = true;
    let input = policy_input(&spec);
    let config = PolicyConfig {
        schema: TOOL_POLICY_SCHEMA.to_string(),
        allowed_tools: vec![spec.id.as_str().to_string()],
        default_allow: false,
    };
    let outcome = ToolPolicy::check(&input, &config, &runtime_root, &mut audit).expect("check");
    let approval_ref = match outcome {
        PolicyOutcome::NeedsApproval { approval_ref } => approval_ref,
        _ => panic!("expected approval required"),
    };
    let request_path = runtime_root
        .join("artifacts")
        .join("approvals")
        .join(format!(
            "{}.json",
            approval_ref
                .strip_prefix("sha256:")
                .unwrap_or(&approval_ref)
        ));
    assert!(request_path.exists());
    write_approval_file(&runtime_root, &approval_ref, &input);
    let outcome = ToolPolicy::check(&input, &config, &runtime_root, &mut audit).expect("check");
    assert!(matches!(outcome, PolicyOutcome::Allowed));
    std::env::remove_var("TOOLS_ENABLE");
    std::env::remove_var("TOOLS_ARM");
}

#[test]
fn tool_policy_denies_when_tool_not_allowed() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("TOOLS_ENABLE", "1");
    std::env::remove_var("TOOLS_ARM");
    let runtime_root = std::env::temp_dir().join(format!("pie_policy_deny_{}", Uuid::new_v4()));
    let mut audit = audit_appender(&runtime_root);
    let spec = sample_spec();
    let input = policy_input(&spec);
    let config = PolicyConfig {
        schema: TOOL_POLICY_SCHEMA.to_string(),
        allowed_tools: Vec::new(),
        default_allow: false,
    };
    let outcome = ToolPolicy::check(&input, &config, &runtime_root, &mut audit).expect("check");
    assert!(matches!(
        outcome,
        PolicyOutcome::Denied {
            reason: "tool_not_allowed"
        }
    ));
    std::env::remove_var("TOOLS_ENABLE");
    std::env::remove_var("TOOLS_ARM");
}

#[test]
fn tool_policy_needs_arming_when_high_risk_and_missing_arm() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("TOOLS_ENABLE", "1");
    std::env::remove_var("TOOLS_ARM");
    let runtime_root = std::env::temp_dir().join(format!("pie_policy_arm_{}", Uuid::new_v4()));
    let mut audit = audit_appender(&runtime_root);
    let mut spec = sample_spec();
    spec.risk_level = RiskLevel::High;
    let input = policy_input(&spec);
    let config = PolicyConfig {
        schema: TOOL_POLICY_SCHEMA.to_string(),
        allowed_tools: vec![spec.id.as_str().to_string()],
        default_allow: false,
    };
    let outcome = ToolPolicy::check(&input, &config, &runtime_root, &mut audit).expect("check");
    assert!(matches!(
        outcome,
        PolicyOutcome::NeedsArming {
            reason: "tool_requires_arming"
        }
    ));
    std::env::remove_var("TOOLS_ENABLE");
    std::env::remove_var("TOOLS_ARM");
}
