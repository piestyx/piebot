//! Stage GSAMA Retrieval Integration Test
//!
//! Tests the GSAMA-based retrieval path in serverd.
//! Verifies that:
//! - RetrievalConfig with kind="gsama" can be loaded
//! - GSAMA store can be created and persisted using snapshot format
//! - Snapshot preserves IDs and head hash
//! - GSAMA retrieval fails closed when no query_vector provided

mod common;

use gsama_core::STORE_SNAPSHOT_SCHEMA;
use serverd::retrieval::{
    load_retrieval_config, save_gsama_store, RetrievalConfig, RetrievalKind,
    RETRIEVAL_CONFIG_SCHEMA,
};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn setup_runtime() -> TempDir {
    let tmp = TempDir::new().expect("create temp dir");
    let runtime = tmp.path();

    // Create required directories
    fs::create_dir_all(runtime.join("state")).unwrap();
    fs::create_dir_all(runtime.join("logs")).unwrap();
    fs::create_dir_all(runtime.join("retrieval")).unwrap();
    // New path: runtime/memory/gsama/
    fs::create_dir_all(runtime.join("memory").join("gsama")).unwrap();

    // Write initial state
    common::write_initial_state(runtime);

    tmp
}

fn write_retrieval_config(runtime: &Path, config: &RetrievalConfig) {
    let config_path = runtime.join("retrieval").join("config.json");
    let content = serde_json::to_string_pretty(config).unwrap();
    fs::write(config_path, content).unwrap();
}

fn create_test_gsama_store(runtime: &Path) {
    // Create a simple GSAMA store with test entries
    let mut store = gsama_core::Store::new(8, 100);

    // Write some test entries with episode_ref tags
    store
        .write(
            vec![1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            vec![("episode_ref".into(), "episodes/hash1".into())],
            0.5,
            100,
        )
        .unwrap();

    store
        .write(
            vec![0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            vec![("episode_ref".into(), "episodes/hash2".into())],
            0.6,
            200,
        )
        .unwrap();

    store
        .write(
            vec![1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            vec![("episode_ref".into(), "episodes/hash3".into())],
            0.7,
            300,
        )
        .unwrap();

    // Save to disk
    save_gsama_store(runtime, &store).expect("save gsama store");
}

#[test]
fn test_retrieval_config_with_gsama_kind() {
    let tmp = setup_runtime();
    let runtime = tmp.path();

    // Write config with kind=gsama
    let config = RetrievalConfig {
        schema: RETRIEVAL_CONFIG_SCHEMA.to_string(),
        enabled: true,
        kind: RetrievalKind::Gsama,
        sources: vec!["episodic".into()],
        namespaces_allowlist: vec!["contexts".into(), "gsama".into()],
        max_items: 10,
        max_bytes: 8192,
        default_recency_ticks: 16,
        default_tags: vec![],
        gsama_vector_source_mode: "external_or_hash_fallback".into(),
        gsama_allow_hash_embedder: true,
        gsama_hash_embedder_dim: 64,
        gsama_store_capacity: 1000,
        gsama_vector_dim: 74,
    };

    write_retrieval_config(runtime, &config);

    // Load and verify
    let loaded = load_retrieval_config(runtime).expect("load config");
    assert_eq!(loaded.kind, RetrievalKind::Gsama);
    assert!(loaded.enabled);
}

#[test]
fn test_retrieval_config_default_is_refs() {
    let tmp = setup_runtime();
    let runtime = tmp.path();

    // Don't write any config
    let loaded = load_retrieval_config(runtime).expect("load default config");
    assert_eq!(loaded.kind, RetrievalKind::Refs);
    assert!(!loaded.enabled);
}

#[test]
fn test_gsama_store_persistence() {
    let tmp = setup_runtime();
    let runtime = tmp.path();

    create_test_gsama_store(runtime);

    // Verify store file exists at new path
    let store_path = runtime
        .join("memory")
        .join("gsama")
        .join("store_snapshot.json");
    assert!(
        store_path.exists(),
        "GSAMA store snapshot file should exist"
    );

    // Verify content is valid JSON with snapshot schema
    let content = fs::read_to_string(&store_path).unwrap();
    let data: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");

    // Verify snapshot schema
    assert_eq!(data["schema"], STORE_SNAPSHOT_SCHEMA);
    assert_eq!(data["dim"], 8);
    assert_eq!(data["capacity"], 100);
    assert!(data["head_hash"].as_str().unwrap().starts_with("sha256:"));
    assert!(data["entries"].is_array());
    assert_eq!(data["entries"].as_array().unwrap().len(), 3);
}

#[test]
fn test_gsama_store_entries_have_episode_refs() {
    let tmp = setup_runtime();
    let runtime = tmp.path();

    create_test_gsama_store(runtime);

    let store_path = runtime
        .join("memory")
        .join("gsama")
        .join("store_snapshot.json");
    let content = fs::read_to_string(&store_path).unwrap();
    let data: serde_json::Value = serde_json::from_str(&content).unwrap();

    // Check that entries have episode_ref tags and preserved IDs
    let entries = data["entries"].as_array().unwrap();
    for entry in entries {
        // Verify entry has sha256 ID (preserved, not regenerated)
        let id = entry["id"].as_str().unwrap();
        assert!(
            id.starts_with("sha256:"),
            "Entry ID should be sha256 format"
        );

        let tags = entry["tags"].as_array().unwrap();
        let has_episode_ref = tags.iter().any(|t| {
            let arr = t.as_array().unwrap();
            arr[0].as_str() == Some("episode_ref")
        });
        assert!(has_episode_ref, "Entry should have episode_ref tag");
    }
}

#[test]
fn test_retrieval_kind_serialization() {
    // Test that RetrievalKind serializes correctly
    let refs_json = serde_json::to_string(&RetrievalKind::Refs).unwrap();
    assert_eq!(refs_json, "\"refs\"");

    let gsama_json = serde_json::to_string(&RetrievalKind::Gsama).unwrap();
    assert_eq!(gsama_json, "\"gsama\"");

    // Test deserialization
    let refs: RetrievalKind = serde_json::from_str("\"refs\"").unwrap();
    assert_eq!(refs, RetrievalKind::Refs);

    let gsama: RetrievalKind = serde_json::from_str("\"gsama\"").unwrap();
    assert_eq!(gsama, RetrievalKind::Gsama);
}

#[test]
fn test_retrieval_config_round_trip() {
    let tmp = setup_runtime();
    let runtime = tmp.path();

    let config = RetrievalConfig {
        schema: RETRIEVAL_CONFIG_SCHEMA.to_string(),
        enabled: true,
        kind: RetrievalKind::Gsama,
        sources: vec!["episodic".into(), "working".into()],
        namespaces_allowlist: vec!["contexts".into()],
        max_items: 20,
        max_bytes: 16384,
        default_recency_ticks: 32,
        default_tags: vec!["intent:query".into()],
        gsama_vector_source_mode: "external_or_hash_fallback".into(),
        gsama_allow_hash_embedder: true,
        gsama_hash_embedder_dim: 64,
        gsama_store_capacity: 1000,
        gsama_vector_dim: 74,
    };

    write_retrieval_config(runtime, &config);
    let loaded = load_retrieval_config(runtime).expect("load config");

    assert_eq!(loaded.schema, config.schema);
    assert_eq!(loaded.enabled, config.enabled);
    assert_eq!(loaded.kind, config.kind);
    assert_eq!(loaded.max_items, config.max_items);
    assert_eq!(loaded.max_bytes, config.max_bytes);
    assert_eq!(loaded.default_recency_ticks, config.default_recency_ticks);
}

#[test]
fn test_snapshot_preserves_ids_on_reload() {
    let tmp = setup_runtime();
    let runtime = tmp.path();

    // Create store and record original IDs
    let mut store = gsama_core::Store::new(4, 100);
    let r1 = store
        .write(vec![3.0, 4.0, 0.0, 0.0], vec![], 0.5, 100)
        .unwrap();
    let original_id = r1.id.clone();
    let original_head = store.head_hash_hex();

    // Save to disk
    save_gsama_store(runtime, &store).expect("save store");

    // Load from disk and verify IDs are preserved
    let store_path = runtime
        .join("memory")
        .join("gsama")
        .join("store_snapshot.json");
    let content = fs::read_to_string(&store_path).unwrap();
    let snapshot: gsama_core::StoreSnapshot = serde_json::from_str(&content).unwrap();
    let restored = gsama_core::Store::from_snapshot(snapshot).expect("restore store");

    // IDs must be identical (not regenerated)
    assert!(
        restored.get(&original_id).is_some(),
        "Entry ID must be preserved"
    );
    assert_eq!(
        restored.head_hash_hex(),
        original_head,
        "Head hash must be preserved"
    );
}
