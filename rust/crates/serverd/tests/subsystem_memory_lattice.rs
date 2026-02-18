#![cfg(feature = "bin")]

use pie_common::sha256_bytes;
use serverd::memory::{append_episode, write_working_snapshot, EpisodePayload, WorkingMemoryEntry};
use serverd::memory_lattice::{MEMORY_LATTICE_CONFIG_SCHEMA, MEMORY_LATTICE_SCHEMA};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

fn run_serverd_route(runtime_root: &Path, ticks: u64, delta: &str) -> Output {
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
    cmd.output().expect("failed to run serverd")
}

fn write_initial_state(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
}

fn write_memory_lattice_config(runtime_root: &Path, value: serde_json::Value) {
    let dir = runtime_root.join("memory");
    fs::create_dir_all(&dir).expect("create memory dir");
    let bytes = serde_json::to_vec(&value).expect("serialize memory lattice config");
    fs::write(dir.join("lattice_config.json"), bytes).expect("write memory lattice config");
}

fn seed_memory(runtime_root: &Path) -> String {
    let payload = EpisodePayload {
        tick_index: 0,
        intent_kind: "no_op".to_string(),
        request_hash: "sha256:request0000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        state_delta_ref: "sha256:delta000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        artifact_refs: vec![],
    };
    let episode_hash = append_episode(runtime_root, None, payload).expect("append episode");
    let entries = vec![WorkingMemoryEntry {
        key: "req-1".to_string(),
        value_ref: episode_hash.clone(),
        last_touched_tick: 0,
    }];
    write_working_snapshot(runtime_root, 0, &entries).expect("write working snapshot");
    episode_hash
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

#[test]
fn memory_lattice_disabled_emits_no_events() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage16_disabled_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(out.status.success(), "run should succeed");
    let events = read_event_payloads(&runtime_root);
    assert!(
        !events
            .iter()
            .any(|event| event.get("event_type").and_then(|v| v.as_str())
                == Some("memory_lattice_built")),
        "memory_lattice_built should not be emitted when disabled"
    );
}

#[test]
fn memory_lattice_builds_and_is_deterministic_across_two_runtimes() {
    let runtime_one = std::env::temp_dir().join(format!("pie_stage16_det_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_stage16_det_two_{}", Uuid::new_v4()));
    for runtime_root in [&runtime_one, &runtime_two] {
        write_initial_state(runtime_root);
        seed_memory(runtime_root);
        write_memory_lattice_config(
            runtime_root,
            serde_json::json!({
                "schema": MEMORY_LATTICE_CONFIG_SCHEMA,
                "enabled": true,
                "max_items": 256,
                "max_bytes": 262144
            }),
        );
    }

    let out_one = run_serverd_route(&runtime_one, 1, "tick:0");
    let out_two = run_serverd_route(&runtime_two, 1, "tick:0");
    assert!(out_one.status.success(), "run one should succeed");
    assert!(out_two.status.success(), "run two should succeed");

    let events_one = read_event_payloads(&runtime_one);
    let events_two = read_event_payloads(&runtime_two);
    let lattice_one = find_event(&events_one, "memory_lattice_built");
    let lattice_two = find_event(&events_two, "memory_lattice_built");
    let hash_one = lattice_one
        .get("lattice_hash")
        .and_then(|v| v.as_str())
        .expect("lattice_hash one");
    let hash_two = lattice_two
        .get("lattice_hash")
        .and_then(|v| v.as_str())
        .expect("lattice_hash two");
    assert_eq!(hash_one, hash_two);

    let ref_one = lattice_one
        .get("lattice_ref")
        .and_then(|v| v.as_str())
        .expect("lattice_ref one");
    let ref_two = lattice_two
        .get("lattice_ref")
        .and_then(|v| v.as_str())
        .expect("lattice_ref two");
    let bytes_one = fs::read(artifact_path(&runtime_one, "memory_lattices", ref_one))
        .expect("read lattice one");
    let bytes_two = fs::read(artifact_path(&runtime_two, "memory_lattices", ref_two))
        .expect("read lattice two");
    assert_eq!(bytes_one, bytes_two);

    let lattice_value: serde_json::Value =
        serde_json::from_slice(&bytes_one).expect("lattice artifact json");
    assert_eq!(
        lattice_value.get("schema").and_then(|v| v.as_str()),
        Some(MEMORY_LATTICE_SCHEMA)
    );
    let items = lattice_value
        .get("items")
        .and_then(|v| v.as_array())
        .expect("items array");
    assert!(!items.is_empty(), "lattice items should not be empty");
    for (idx, item) in items.iter().enumerate() {
        assert_eq!(
            item.get("ts_order").and_then(|v| v.as_u64()),
            Some(idx as u64),
            "ts_order must be deterministic ordinal"
        );
    }
}

#[test]
fn memory_lattice_invalid_config_fails_closed() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage16_bad_config_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    write_memory_lattice_config(
        &runtime_root,
        serde_json::json!({
            "schema": "wrong.schema",
            "enabled": true,
            "max_items": 256,
            "max_bytes": 262144
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(!out.status.success(), "run should fail");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert_eq!(
        payload.get("error").and_then(|v| v.as_str()),
        Some("memory_lattice_config_invalid")
    );
}

#[test]
fn memory_lattice_caps_fail_closed() {
    let runtime_items =
        std::env::temp_dir().join(format!("pie_stage16_cap_items_{}", Uuid::new_v4()));
    write_initial_state(&runtime_items);
    let first_episode = append_episode(
        &runtime_items,
        None,
        EpisodePayload {
            tick_index: 0,
            intent_kind: "no_op".to_string(),
            request_hash:
                "sha256:first000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            state_delta_ref:
                "sha256:delta000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            artifact_refs: vec![],
        },
    )
    .expect("append first episode");
    let second_episode = append_episode(
        &runtime_items,
        Some(first_episode),
        EpisodePayload {
            tick_index: 1,
            intent_kind: "no_op".to_string(),
            request_hash: "sha256:second0000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            state_delta_ref:
                "sha256:delta111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            artifact_refs: vec![],
        },
    )
    .expect("append second episode");
    write_working_snapshot(
        &runtime_items,
        1,
        &[WorkingMemoryEntry {
            key: "req-last".to_string(),
            value_ref: second_episode,
            last_touched_tick: 1,
        }],
    )
    .expect("write working snapshot");
    write_memory_lattice_config(
        &runtime_items,
        serde_json::json!({
            "schema": MEMORY_LATTICE_CONFIG_SCHEMA,
            "enabled": true,
            "max_items": 1,
            "max_bytes": 262144
        }),
    );
    let out_items = run_serverd_route(&runtime_items, 1, "tick:0");
    assert!(!out_items.status.success(), "max_items run should fail");
    let payload_items: serde_json::Value =
        serde_json::from_slice(&out_items.stdout).expect("stdout json items");
    assert_eq!(
        payload_items.get("error").and_then(|v| v.as_str()),
        Some("memory_lattice_exceeds_max_items")
    );

    let runtime_bytes =
        std::env::temp_dir().join(format!("pie_stage16_cap_bytes_{}", Uuid::new_v4()));
    write_initial_state(&runtime_bytes);
    seed_memory(&runtime_bytes);
    write_memory_lattice_config(
        &runtime_bytes,
        serde_json::json!({
            "schema": MEMORY_LATTICE_CONFIG_SCHEMA,
            "enabled": true,
            "max_items": 256,
            "max_bytes": 64
        }),
    );
    let out_bytes = run_serverd_route(&runtime_bytes, 1, "tick:0");
    assert!(!out_bytes.status.success(), "max_bytes run should fail");
    let payload_bytes: serde_json::Value =
        serde_json::from_slice(&out_bytes.stdout).expect("stdout json bytes");
    assert_eq!(
        payload_bytes.get("error").and_then(|v| v.as_str()),
        Some("memory_lattice_exceeds_max_bytes")
    );
}

#[test]
fn memory_lattice_hashes_match_source_bytes() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage16_hash_match_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    let seeded_episode = seed_memory(&runtime_root);
    write_memory_lattice_config(
        &runtime_root,
        serde_json::json!({
            "schema": MEMORY_LATTICE_CONFIG_SCHEMA,
            "enabled": true,
            "max_items": 256,
            "max_bytes": 262144
        }),
    );
    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(out.status.success(), "run should succeed");

    let events = read_event_payloads(&runtime_root);
    let lattice_event = find_event(&events, "memory_lattice_built");
    let lattice_ref = lattice_event
        .get("lattice_ref")
        .and_then(|v| v.as_str())
        .expect("lattice_ref");
    let lattice_bytes = fs::read(artifact_path(&runtime_root, "memory_lattices", lattice_ref))
        .expect("lattice bytes");
    let lattice_value: serde_json::Value =
        serde_json::from_slice(&lattice_bytes).expect("lattice json");
    let items = lattice_value
        .get("items")
        .and_then(|v| v.as_array())
        .expect("items");
    let episode_item = items
        .iter()
        .find(|item| {
            item.get("kind").and_then(|v| v.as_str()) == Some("episode")
                && item.get("ref").and_then(|v| v.as_str()) == Some(seeded_episode.as_str())
        })
        .expect("episode item");
    let item_hash = episode_item
        .get("hash")
        .and_then(|v| v.as_str())
        .expect("item hash");
    let episode_file = runtime_root.join("memory").join("episodes").join(format!(
        "{}.json",
        seeded_episode
            .strip_prefix("sha256:")
            .unwrap_or(seeded_episode.as_str())
    ));
    let source_bytes = fs::read(&episode_file).expect("read episode bytes");
    assert_eq!(item_hash, sha256_bytes(source_bytes.as_slice()));
    assert_eq!(
        episode_item
            .get("summary")
            .and_then(|v| v.get("bytes"))
            .and_then(|v| v.as_u64()),
        Some(source_bytes.len() as u64)
    );
}

#[test]
fn memory_lattice_uses_hash_source_fields_and_dedupes_duplicate_refs() {
    let runtime_root =
        std::env::temp_dir().join(format!("pie_stage16_dedupe_hash_fields_{}", Uuid::new_v4()));
    write_initial_state(&runtime_root);
    let payload = EpisodePayload {
        tick_index: 0,
        intent_kind: "no_op".to_string(),
        request_hash: "sha256:request0000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        state_delta_ref: "sha256:delta000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        artifact_refs: vec![],
    };
    let episode_hash = append_episode(&runtime_root, None, payload).expect("append episode");
    let entries = vec![
        WorkingMemoryEntry {
            key: "dup-a".to_string(),
            value_ref: episode_hash.clone(),
            last_touched_tick: 0,
        },
        WorkingMemoryEntry {
            key: "dup-b".to_string(),
            value_ref: format!("episodes/{}", episode_hash),
            last_touched_tick: 0,
        },
    ];
    write_working_snapshot(&runtime_root, 0, &entries).expect("write working snapshot");
    write_memory_lattice_config(
        &runtime_root,
        serde_json::json!({
            "schema": MEMORY_LATTICE_CONFIG_SCHEMA,
            "enabled": true,
            "max_items": 1,
            "max_bytes": 262144
        }),
    );

    let out = run_serverd_route(&runtime_root, 1, "tick:0");
    assert!(out.status.success(), "run should succeed");
    let events = read_event_payloads(&runtime_root);
    let lattice_event = find_event(&events, "memory_lattice_built");
    let lattice_ref = lattice_event
        .get("lattice_ref")
        .and_then(|v| v.as_str())
        .expect("lattice_ref");
    let lattice_bytes = fs::read(artifact_path(&runtime_root, "memory_lattices", lattice_ref))
        .expect("lattice bytes");
    let lattice_value: serde_json::Value =
        serde_json::from_slice(&lattice_bytes).expect("lattice json");
    let sources = lattice_value
        .get("sources")
        .and_then(|v| v.as_object())
        .expect("sources object");
    assert!(
        sources
            .get("working_snapshot_hash")
            .and_then(|v| v.as_str())
            .is_some(),
        "working_snapshot_hash should be present"
    );
    assert_eq!(
        sources.get("episodic_head_hash").and_then(|v| v.as_str()),
        Some(episode_hash.as_str())
    );
    assert!(
        sources.get("working_snapshot_ref").is_none(),
        "legacy *_ref field must not be present"
    );
    assert!(
        sources.get("episodic_head_ref").is_none(),
        "legacy *_ref field must not be present"
    );
    let items = lattice_value
        .get("items")
        .and_then(|v| v.as_array())
        .expect("items");
    assert_eq!(items.len(), 1, "duplicate refs should be collapsed");
    assert_eq!(
        items[0].get("ref").and_then(|v| v.as_str()),
        Some(episode_hash.as_str())
    );
}
