use crate::memory::{list_episode_chain, load_episode_head};
use pie_common::{canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const MEMORY_LATTICE_CONFIG_SCHEMA: &str = "serverd.memory_lattice_config.v1";
pub const MEMORY_LATTICE_SCHEMA: &str = "serverd.memory_lattice.v1";

const DEFAULT_MAX_ITEMS: usize = 256;
const DEFAULT_MAX_BYTES: usize = 262_144;
const WORKING_SNAPSHOT_SCHEMA: &str = "serverd.working_memory.v1";

#[derive(Debug)]
pub struct MemoryLatticeError {
    reason: &'static str,
    detail: Option<String>,
}

impl MemoryLatticeError {
    pub fn new(reason: &'static str) -> Self {
        Self {
            reason,
            detail: None,
        }
    }

    pub fn with_detail(reason: &'static str, detail: String) -> Self {
        Self {
            reason,
            detail: Some(detail),
        }
    }

    pub fn reason(&self) -> &'static str {
        self.reason
    }

    #[allow(dead_code)]
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl std::fmt::Display for MemoryLatticeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for MemoryLatticeError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct MemoryLatticeConfig {
    pub schema: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_items")]
    pub max_items: usize,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,
}

impl Default for MemoryLatticeConfig {
    fn default() -> Self {
        Self {
            schema: MEMORY_LATTICE_CONFIG_SCHEMA.to_string(),
            enabled: false,
            max_items: default_max_items(),
            max_bytes: default_max_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct MemoryLatticeSources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_snapshot_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub episodic_head_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct MemoryLatticeItemSummary {
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct MemoryLatticeItem {
    pub kind: String,
    pub r#ref: String,
    pub hash: String,
    pub ts_order: u64,
    pub summary: MemoryLatticeItemSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct MemoryLatticeArtifact {
    pub schema: String,
    pub built_at_tick: u64,
    pub sources: MemoryLatticeSources,
    pub items: Vec<MemoryLatticeItem>,
}

#[derive(Debug, Clone)]
pub struct MemoryLatticeBuildOutput {
    pub artifact: MemoryLatticeArtifact,
    pub lattice_hash: String,
    pub item_count: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct WorkingSnapshotEntry {
    key: String,
    value_ref: String,
    last_touched_tick: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct WorkingSnapshot {
    schema: String,
    #[serde(rename = "tick_index")]
    _tick_index: u64,
    entries: Vec<WorkingSnapshotEntry>,
}

pub fn load_memory_lattice_config(
    runtime_root: &Path,
) -> Result<MemoryLatticeConfig, MemoryLatticeError> {
    let path = memory_lattice_config_path(runtime_root);
    if !path.exists() {
        return Ok(MemoryLatticeConfig::default());
    }
    let bytes = fs::read(&path).map_err(|e| {
        MemoryLatticeError::with_detail("memory_lattice_config_invalid", e.to_string())
    })?;
    let mut config: MemoryLatticeConfig = serde_json::from_slice(&bytes).map_err(|e| {
        MemoryLatticeError::with_detail("memory_lattice_config_invalid", e.to_string())
    })?;
    if config.schema != MEMORY_LATTICE_CONFIG_SCHEMA {
        return Err(MemoryLatticeError::new("memory_lattice_config_invalid"));
    }
    normalize_memory_lattice_config(&mut config)?;
    Ok(config)
}

pub fn build_memory_lattice(
    runtime_root: &Path,
    tick_index: u64,
    config: &MemoryLatticeConfig,
) -> Result<Option<MemoryLatticeBuildOutput>, MemoryLatticeError> {
    if !config.enabled {
        return Ok(None);
    }
    let episodic_head_hash = load_episode_head(runtime_root)
        .map_err(|_| MemoryLatticeError::new("memory_lattice_source_missing"))?;
    let episode_chain = list_episode_chain(runtime_root)
        .map_err(|_| MemoryLatticeError::new("memory_lattice_source_missing"))?;

    let working_snapshot = load_working_snapshot(runtime_root)?;
    let working_snapshot_hash = working_snapshot
        .as_ref()
        .map(|snapshot| sha256_bytes(snapshot.bytes.as_slice()));

    let mut items = Vec::new();
    let mut seen_refs = BTreeSet::new();

    for episode_hash in &episode_chain {
        if seen_refs.contains(episode_hash) {
            continue;
        }
        let bytes = read_episode_bytes(runtime_root, episode_hash)?;
        let hash = sha256_bytes(bytes.as_slice());
        seen_refs.insert(episode_hash.clone());
        items.push(MemoryLatticeItem {
            kind: "episode".to_string(),
            r#ref: episode_hash.clone(),
            hash,
            ts_order: 0,
            summary: MemoryLatticeItemSummary {
                bytes: bytes.len() as u64,
            },
        });
    }

    if let Some(snapshot) = working_snapshot.as_ref() {
        let mut entries = snapshot.snapshot.entries.clone();
        entries.sort_by(|left, right| {
            left.key
                .cmp(&right.key)
                .then(left.value_ref.cmp(&right.value_ref))
                .then(left.last_touched_tick.cmp(&right.last_touched_tick))
        });
        for entry in entries {
            let normalized_ref = normalize_episode_ref(&entry.value_ref)?;
            if seen_refs.contains(&normalized_ref) {
                continue;
            }
            let bytes = read_episode_bytes_from_ref(runtime_root, &normalized_ref)?;
            let hash = sha256_bytes(bytes.as_slice());
            seen_refs.insert(normalized_ref.clone());
            items.push(MemoryLatticeItem {
                kind: "working".to_string(),
                r#ref: normalized_ref,
                hash,
                ts_order: 0,
                summary: MemoryLatticeItemSummary {
                    bytes: bytes.len() as u64,
                },
            });
        }
    }

    if items.len() > config.max_items {
        return Err(MemoryLatticeError::new("memory_lattice_exceeds_max_items"));
    }

    for (idx, item) in items.iter_mut().enumerate() {
        item.ts_order = idx as u64;
    }

    let artifact = MemoryLatticeArtifact {
        schema: MEMORY_LATTICE_SCHEMA.to_string(),
        built_at_tick: tick_index,
        sources: MemoryLatticeSources {
            working_snapshot_hash,
            episodic_head_hash,
        },
        items,
    };

    let value = serde_json::to_value(&artifact)
        .map_err(|_| MemoryLatticeError::new("memory_lattice_build_failed"))?;
    let bytes = canonical_json_bytes(&value)
        .map_err(|_| MemoryLatticeError::new("memory_lattice_build_failed"))?;
    if bytes.len() > config.max_bytes {
        return Err(MemoryLatticeError::new("memory_lattice_exceeds_max_bytes"));
    }
    let lattice_hash = sha256_bytes(bytes.as_slice());
    Ok(Some(MemoryLatticeBuildOutput {
        artifact,
        lattice_hash,
        item_count: value
            .get("items")
            .and_then(|items| items.as_array())
            .map(|items| items.len() as u64)
            .unwrap_or(0),
        bytes: bytes.len() as u64,
    }))
}

#[derive(Debug, Clone)]
struct LoadedWorkingSnapshot {
    snapshot: WorkingSnapshot,
    bytes: Vec<u8>,
}

fn load_working_snapshot(
    runtime_root: &Path,
) -> Result<Option<LoadedWorkingSnapshot>, MemoryLatticeError> {
    let path = runtime_root.join("memory").join("working.json");
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).map_err(|e| {
        MemoryLatticeError::with_detail("memory_lattice_source_missing", e.to_string())
    })?;
    let snapshot: WorkingSnapshot = serde_json::from_slice(&bytes)
        .map_err(|_| MemoryLatticeError::new("memory_lattice_source_missing"))?;
    if snapshot.schema != WORKING_SNAPSHOT_SCHEMA {
        return Err(MemoryLatticeError::new("memory_lattice_source_missing"));
    }
    Ok(Some(LoadedWorkingSnapshot { snapshot, bytes }))
}

fn read_episode_bytes(
    runtime_root: &Path,
    episode_hash: &str,
) -> Result<Vec<u8>, MemoryLatticeError> {
    if !is_sha256_ref(episode_hash) {
        return Err(MemoryLatticeError::new("memory_lattice_source_missing"));
    }
    let path = episode_path(runtime_root, episode_hash);
    fs::read(path).map_err(|_| MemoryLatticeError::new("memory_lattice_source_missing"))
}

fn read_episode_bytes_from_ref(
    runtime_root: &Path,
    value_ref: &str,
) -> Result<Vec<u8>, MemoryLatticeError> {
    let normalized_ref = normalize_episode_ref(value_ref)?;
    read_episode_bytes(runtime_root, &normalized_ref)
}

fn normalize_episode_ref(value_ref: &str) -> Result<String, MemoryLatticeError> {
    if is_sha256_ref(value_ref) {
        return Ok(value_ref.to_string());
    }
    if let Some(rest) = value_ref.strip_prefix("episodes/") {
        if is_sha256_ref(rest) {
            return Ok(rest.to_string());
        }
    }
    Err(MemoryLatticeError::new("memory_lattice_source_missing"))
}

fn episode_path(runtime_root: &Path, episode_hash: &str) -> PathBuf {
    let trimmed = episode_hash.strip_prefix("sha256:").unwrap_or(episode_hash);
    runtime_root
        .join("memory")
        .join("episodes")
        .join(format!("{}.json", trimmed))
}

fn memory_lattice_config_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join("memory").join("lattice_config.json")
}

fn normalize_memory_lattice_config(
    config: &mut MemoryLatticeConfig,
) -> Result<(), MemoryLatticeError> {
    if config.max_items == 0 || config.max_bytes == 0 {
        return Err(MemoryLatticeError::new("memory_lattice_config_invalid"));
    }
    Ok(())
}

fn default_max_items() -> usize {
    DEFAULT_MAX_ITEMS
}

fn default_max_bytes() -> usize {
    DEFAULT_MAX_BYTES
}

fn is_sha256_ref(value: &str) -> bool {
    if let Some(rest) = value.strip_prefix("sha256:") {
        if rest.len() != 64 {
            return false;
        }
        return rest.chars().all(|c| c.is_ascii_hexdigit());
    }
    false
}
