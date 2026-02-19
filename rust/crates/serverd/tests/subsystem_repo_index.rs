#![cfg(feature = "bin")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

const WORKSPACE_POLICY_SCHEMA: &str = "serverd.workspace_policy.v1";
const REPO_INDEX_CONFIG_SCHEMA: &str = "serverd.repo_index_config.v1";
const REPO_IDENTITY_SCHEMA: &str = "serverd.repo_identity.v1";
const REPO_INDEX_SNAPSHOT_SCHEMA: &str = "serverd.repo_index_snapshot.v1";

fn run_serverd_route(runtime_root: &Path) -> Output {
    let mut cmd = Command::new(common::serverd_exe());
    cmd.arg("--mode")
        .arg("route")
        .arg("--ticks")
        .arg("1")
        .arg("--delta")
        .arg("tick:0")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.output().expect("failed to run serverd")
}

fn write_initial_state(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
}

fn write_workspace_policy(runtime_root: &Path) {
    let dir = runtime_root.join("workspace");
    fs::create_dir_all(&dir).expect("create workspace policy dir");
    let value = serde_json::json!({
        "schema": WORKSPACE_POLICY_SCHEMA,
        "enabled": true,
        "workspace_root": "workspace_data",
        "allow_repo_root": false,
        "per_run_dir": false
    });
    let bytes = serde_json::to_vec(&value).expect("serialize workspace policy");
    fs::write(dir.join("policy.json"), bytes).expect("write workspace policy");
}

fn write_repo_index_config(runtime_root: &Path) {
    let dir = runtime_root.join("repo_index");
    fs::create_dir_all(&dir).expect("create repo index dir");
    let value = serde_json::json!({
        "schema": REPO_INDEX_CONFIG_SCHEMA,
        "enabled": true,
        "max_file_bytes": 1024 * 1024,
        "max_total_bytes": 4 * 1024 * 1024,
        "chunk_mode": "fixed_size",
        "fixed_chunk_bytes": 8,
        "ignore_globs": ["ignored_prefix/"]
    });
    let bytes = serde_json::to_vec(&value).expect("serialize repo index config");
    fs::write(dir.join("config.json"), bytes).expect("write repo index config");
}

fn write_workspace_contents(runtime_root: &Path) {
    let workspace = runtime_root.join("workspace_data");
    fs::create_dir_all(workspace.join("nested").join("deeper")).expect("create nested workspace");
    fs::create_dir_all(workspace.join("ignored_prefix")).expect("create ignored dir");
    fs::create_dir_all(workspace.join("target")).expect("create target dir");
    fs::create_dir_all(workspace.join(".git")).expect("create git dir");
    fs::write(workspace.join("small.txt"), b"alpha\n").expect("write small file");
    fs::write(workspace.join("nested").join("multi_chunk.txt"), b"0123456789abcdef")
        .expect("write chunked file");
    fs::write(
        workspace.join("nested").join("deeper").join("notes.md"),
        b"# deterministic\ncontent\n",
    )
    .expect("write deep file");
    fs::write(
        workspace.join("ignored_prefix").join("skip.txt"),
        b"ignored by repo_index config",
    )
    .expect("write ignored file");
    fs::write(workspace.join("target").join("skip.txt"), b"ignored baseline target")
        .expect("write target ignored file");
    fs::write(workspace.join(".git").join("skip.txt"), b"ignored baseline git")
        .expect("write git ignored file");
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

fn assert_canonical_relative_path(value: &str) {
    assert!(!value.is_empty(), "path cannot be empty");
    assert!(!value.starts_with('/'), "path must be relative");
    assert!(!value.starts_with("./"), "path must not start with ./");
    assert!(!value.contains('\\'), "path must use forward slashes");
    for segment in value.split('/') {
        assert!(!segment.is_empty(), "path segment cannot be empty");
        assert_ne!(segment, "..", "path segment cannot traverse");
    }
}

fn assert_no_nondeterministic_fields(value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                assert!(
                    !matches!(
                        key.as_str(),
                        "timestamp"
                            | "created_at"
                            | "updated_at"
                            | "mtime"
                            | "ctime"
                            | "inode"
                            | "absolute_path"
                    ),
                    "unexpected nondeterministic key: {}",
                    key
                );
                assert_no_nondeterministic_fields(inner);
            }
        }
        serde_json::Value::Array(list) => {
            for item in list {
                assert_no_nondeterministic_fields(item);
            }
        }
        _ => {}
    }
}

fn setup_runtime(runtime_root: &Path) {
    write_initial_state(runtime_root);
    write_workspace_policy(runtime_root);
    write_repo_index_config(runtime_root);
    write_workspace_contents(runtime_root);
}

#[test]
fn repo_identity_and_snapshot_are_deterministic_across_runtime_roots() {
    let runtime_one = std::env::temp_dir().join(format!("pie_repo_index_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_repo_index_two_{}", Uuid::new_v4()));
    setup_runtime(&runtime_one);
    setup_runtime(&runtime_two);

    let out_one = run_serverd_route(&runtime_one);
    let out_two = run_serverd_route(&runtime_two);
    assert!(
        out_one.status.success(),
        "runtime one failed: {}",
        String::from_utf8_lossy(&out_one.stderr)
    );
    assert!(
        out_two.status.success(),
        "runtime two failed: {}",
        String::from_utf8_lossy(&out_two.stderr)
    );

    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let identity_one = find_event(&events_one, "repo_identity_written");
    let identity_two = find_event(&events_two, "repo_identity_written");
    let snapshot_one = find_event(&events_one, "repo_index_snapshot_written");
    let snapshot_two = find_event(&events_two, "repo_index_snapshot_written");

    let identity_root_one = identity_one
        .get("root_hash")
        .and_then(|v| v.as_str())
        .expect("identity root hash one");
    let identity_root_two = identity_two
        .get("root_hash")
        .and_then(|v| v.as_str())
        .expect("identity root hash two");
    assert_eq!(identity_root_one, identity_root_two);

    let snapshot_root_one = snapshot_one
        .get("root_hash")
        .and_then(|v| v.as_str())
        .expect("snapshot root hash one");
    let snapshot_root_two = snapshot_two
        .get("root_hash")
        .and_then(|v| v.as_str())
        .expect("snapshot root hash two");
    assert_eq!(snapshot_root_one, snapshot_root_two);

    let identity_ref_one = identity_one
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("identity ref one");
    let identity_ref_two = identity_two
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("identity ref two");
    let identity_bytes_one =
        fs::read(artifact_path(&runtime_one, "repo_identity", identity_ref_one)).expect("read one");
    let identity_bytes_two =
        fs::read(artifact_path(&runtime_two, "repo_identity", identity_ref_two)).expect("read two");
    assert_eq!(identity_bytes_one, identity_bytes_two);

    let snapshot_ref_one = snapshot_one
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("snapshot ref one");
    let snapshot_ref_two = snapshot_two
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("snapshot ref two");
    let snapshot_bytes_one = fs::read(artifact_path(
        &runtime_one,
        "repo_index_snapshot",
        snapshot_ref_one,
    ))
    .expect("read snapshot one");
    let snapshot_bytes_two = fs::read(artifact_path(
        &runtime_two,
        "repo_index_snapshot",
        snapshot_ref_two,
    ))
    .expect("read snapshot two");
    assert_eq!(snapshot_bytes_one, snapshot_bytes_two);

    let identity_value: serde_json::Value =
        serde_json::from_slice(&identity_bytes_one).expect("identity json");
    assert_eq!(
        identity_value.get("schema").and_then(|v| v.as_str()),
        Some(REPO_IDENTITY_SCHEMA)
    );
    assert_eq!(
        identity_value.get("root_hash").and_then(|v| v.as_str()),
        Some(identity_root_one)
    );
    let files = identity_value
        .get("files")
        .and_then(|v| v.as_array())
        .expect("identity files");
    assert_eq!(files.len(), 3, "ignored dirs/prefix files should be excluded");
    let mut path_order = Vec::new();
    for file in files {
        let path = file
            .get("path")
            .and_then(|v| v.as_str())
            .expect("identity file path");
        assert_canonical_relative_path(path);
        path_order.push(path.to_string());
    }
    let mut sorted = path_order.clone();
    sorted.sort();
    assert_eq!(path_order, sorted, "identity file list must be sorted");
    assert_eq!(
        identity_one.get("file_count").and_then(|v| v.as_u64()),
        Some(files.len() as u64)
    );

    let snapshot_value: serde_json::Value =
        serde_json::from_slice(&snapshot_bytes_one).expect("snapshot json");
    assert_eq!(
        snapshot_value.get("schema").and_then(|v| v.as_str()),
        Some(REPO_INDEX_SNAPSHOT_SCHEMA)
    );
    assert_eq!(
        snapshot_value.get("root_hash").and_then(|v| v.as_str()),
        Some(snapshot_root_one)
    );
    let chunks = snapshot_value
        .get("chunks")
        .and_then(|v| v.as_array())
        .expect("snapshot chunks");
    assert!(!chunks.is_empty(), "snapshot chunks should not be empty");
    for chunk in chunks {
        let path = chunk
            .get("path")
            .and_then(|v| v.as_str())
            .expect("chunk path");
        assert_canonical_relative_path(path);
    }
    assert_eq!(
        snapshot_one.get("file_count").and_then(|v| v.as_u64()),
        Some(files.len() as u64)
    );
}

#[test]
fn repo_index_artifacts_are_audited_and_not_hidden_state() {
    let runtime_root = std::env::temp_dir().join(format!("pie_repo_index_audit_{}", Uuid::new_v4()));
    setup_runtime(&runtime_root);

    let out = run_serverd_route(&runtime_root);
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let events = read_event_payloads(&runtime_root);
    let identity_event = find_event(&events, "repo_identity_written");
    let snapshot_event = find_event(&events, "repo_index_snapshot_written");

    let identity_ref = identity_event
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("identity_ref");
    let snapshot_ref = snapshot_event
        .get("artifact_ref")
        .and_then(|v| v.as_str())
        .expect("snapshot_ref");
    let identity_path = artifact_path(&runtime_root, "repo_identity", identity_ref);
    let snapshot_path = artifact_path(&runtime_root, "repo_index_snapshot", snapshot_ref);
    assert!(identity_path.is_file(), "identity artifact missing on disk");
    assert!(snapshot_path.is_file(), "snapshot artifact missing on disk");

    let identity_value: serde_json::Value =
        serde_json::from_slice(&fs::read(&identity_path).expect("identity bytes"))
            .expect("identity json");
    let snapshot_value: serde_json::Value =
        serde_json::from_slice(&fs::read(&snapshot_path).expect("snapshot bytes"))
            .expect("snapshot json");
    assert_no_nondeterministic_fields(&identity_value);
    assert_no_nondeterministic_fields(&snapshot_value);

    assert_eq!(
        identity_value.get("root_hash").and_then(|v| v.as_str()),
        identity_event.get("root_hash").and_then(|v| v.as_str())
    );
    assert_eq!(
        snapshot_value.get("root_hash").and_then(|v| v.as_str()),
        snapshot_event.get("root_hash").and_then(|v| v.as_str())
    );

    assert!(
        !runtime_root.join("repo_index").join("cache").exists(),
        "repo_index subsystem must not create cache directories"
    );
}
