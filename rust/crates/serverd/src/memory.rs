use pie_common::{canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const EPISODE_SCHEMA: &str = "serverd.episode.v1";
const WORKING_SNAPSHOT_SCHEMA: &str = "serverd.working_memory.v1";
const DEFAULT_WORKING_CAPACITY: usize = 64;
const DEFAULT_WORKING_TTL_TICKS: u64 = 8;

#[derive(Debug)]
pub struct MemoryError {
    reason: &'static str,
    source: Option<std::io::Error>,
}

impl MemoryError {
    pub(crate) fn new(reason: &'static str) -> Self {
        Self {
            reason,
            source: None,
        }
    }

    pub(crate) fn with_source(reason: &'static str, source: std::io::Error) -> Self {
        Self {
            reason,
            source: Some(source),
        }
    }

    pub fn reason(&self) -> &'static str {
        self.reason
    }
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for MemoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e as _)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct MemoryConfig {
    pub working_capacity: usize,
    pub working_ttl_ticks: u64,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            working_capacity: DEFAULT_WORKING_CAPACITY,
            working_ttl_ticks: DEFAULT_WORKING_TTL_TICKS,
        }
    }
}

fn memory_config_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join("memory").join("config.json")
}

pub fn load_memory_config(runtime_root: &Path) -> Result<MemoryConfig, MemoryError> {
    let path = memory_config_path(runtime_root);
    if !path.exists() {
        return Ok(MemoryConfig::default());
    }
    let bytes =
        fs::read(&path).map_err(|e| MemoryError::with_source("memory_config_read_failed", e))?;
    let config: MemoryConfig =
        serde_json::from_slice(&bytes).map_err(|_| MemoryError::new("memory_config_invalid"))?;
    Ok(config)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct EpisodePayload {
    pub tick_index: u64,
    pub intent_kind: String,
    pub request_hash: String,
    pub state_delta_ref: String,
    pub artifact_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) struct EpisodeRecord {
    pub(crate) schema: String,
    pub(crate) episode_hash: String,
    pub(crate) prev_episode_hash: Option<String>,
    pub(crate) payload: EpisodePayload,
}

fn episodes_dir(runtime_root: &Path) -> PathBuf {
    runtime_root.join("memory").join("episodes")
}

fn episode_head_path(runtime_root: &Path) -> PathBuf {
    episodes_dir(runtime_root).join("head")
}

fn episode_filename(episode_hash: &str) -> String {
    let trimmed = episode_hash.strip_prefix("sha256:").unwrap_or(episode_hash);
    format!("{}.json", trimmed)
}

fn episode_path(runtime_root: &Path, episode_hash: &str) -> PathBuf {
    episodes_dir(runtime_root).join(episode_filename(episode_hash))
}

fn compute_episode_hash(
    prev_episode_hash: &Option<String>,
    payload: &EpisodePayload,
) -> Result<String, MemoryError> {
    let value = serde_json::json!({
        "schema": EPISODE_SCHEMA,
        "prev_episode_hash": prev_episode_hash,
        "payload": payload
    });
    let bytes =
        canonical_json_bytes(&value).map_err(|_| MemoryError::new("episode_hash_failed"))?;
    Ok(sha256_bytes(&bytes))
}

pub(crate) fn load_episode_head(runtime_root: &Path) -> Result<Option<String>, MemoryError> {
    let head_path = episode_head_path(runtime_root);
    if !head_path.exists() {
        return Ok(None);
    }
    let bytes =
        fs::read(&head_path).map_err(|e| MemoryError::with_source("episode_read_failed", e))?;
    let head = String::from_utf8(bytes).map_err(|_| MemoryError::new("invalid_episode"))?;
    let head = head.trim().to_string();
    if head.is_empty() {
        return Err(MemoryError::new("invalid_episode"));
    }
    let _ = read_episode(runtime_root, &head)?;
    Ok(Some(head))
}

pub(crate) fn read_episode(
    runtime_root: &Path,
    episode_hash: &str,
) -> Result<EpisodeRecord, MemoryError> {
    let path = episode_path(runtime_root, episode_hash);
    if !path.exists() {
        return Err(MemoryError::new("episode_not_found"));
    }
    let bytes = fs::read(&path).map_err(|e| MemoryError::with_source("episode_read_failed", e))?;
    let record: EpisodeRecord =
        serde_json::from_slice(&bytes).map_err(|_| MemoryError::new("invalid_episode"))?;
    if record.schema != EPISODE_SCHEMA {
        return Err(MemoryError::new("invalid_episode"));
    }
    let expected = compute_episode_hash(&record.prev_episode_hash, &record.payload)?;
    if expected != record.episode_hash {
        return Err(MemoryError::new("invalid_episode"));
    }
    Ok(record)
}

pub fn append_episode(
    runtime_root: &Path,
    prev_episode_hash: Option<String>,
    payload: EpisodePayload,
) -> Result<String, MemoryError> {
    if let Some(prev) = &prev_episode_hash {
        let _ = read_episode(runtime_root, prev)?;
    }
    let episode_hash = compute_episode_hash(&prev_episode_hash, &payload)?;
    let record = EpisodeRecord {
        schema: EPISODE_SCHEMA.to_string(),
        episode_hash: episode_hash.clone(),
        prev_episode_hash,
        payload,
    };
    let value =
        serde_json::to_value(&record).map_err(|_| MemoryError::new("episode_write_failed"))?;
    let bytes =
        canonical_json_bytes(&value).map_err(|_| MemoryError::new("episode_write_failed"))?;

    let dir = episodes_dir(runtime_root);
    fs::create_dir_all(&dir).map_err(|e| MemoryError::with_source("episode_write_failed", e))?;
    let path = episode_path(runtime_root, &episode_hash);
    if path.exists() {
        let existing = read_episode(runtime_root, &episode_hash)?;
        if existing != record {
            return Err(MemoryError::new("invalid_episode"));
        }
    } else {
        let tmp_path = dir.join(format!("{}.tmp", episode_filename(&episode_hash)));
        let mut file = fs::File::create(&tmp_path)
            .map_err(|e| MemoryError::with_source("episode_write_failed", e))?;
        file.write_all(&bytes)
            .map_err(|e| MemoryError::with_source("episode_write_failed", e))?;
        file.sync_all()
            .map_err(|e| MemoryError::with_source("episode_write_failed", e))?;
        if let Err(e) = fs::rename(&tmp_path, &path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(MemoryError::with_source("episode_write_failed", e));
        }
    }

    fs::write(episode_head_path(runtime_root), episode_hash.as_bytes())
        .map_err(|e| MemoryError::with_source("episode_write_failed", e))?;
    Ok(episode_hash)
}

pub fn list_episode_chain(runtime_root: &Path) -> Result<Vec<String>, MemoryError> {
    let head = match load_episode_head(runtime_root)? {
        Some(head) => head,
        None => return Ok(Vec::new()),
    };
    let mut chain = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current = head;
    loop {
        if !seen.insert(current.clone()) {
            return Err(MemoryError::new("episode_cycle_detected"));
        }
        let record = read_episode(runtime_root, &current)?;
        chain.push(current.clone());
        match record.prev_episode_hash {
            Some(prev) => current = prev,
            None => break,
        }
    }
    chain.reverse();
    Ok(chain)
}

#[derive(Debug, Clone)]
pub struct WorkingMemoryEntry {
    pub key: String,
    pub value_ref: String,
    pub last_touched_tick: u64,
}

#[derive(Debug, Clone)]
pub struct WorkingMemory {
    capacity: usize,
    ttl_ticks: u64,
    entries: Vec<WorkingMemoryEntry>,
}

#[derive(Debug, Clone)]
pub struct WorkingMemoryUpdate {
    pub keys_added: u64,
    pub keys_evicted: u64,
}

impl WorkingMemory {
    pub fn new(capacity: usize, ttl_ticks: u64) -> Self {
        Self {
            capacity,
            ttl_ticks,
            entries: Vec::new(),
        }
    }

    pub fn from_entries(
        capacity: usize,
        ttl_ticks: u64,
        mut entries: Vec<WorkingMemoryEntry>,
    ) -> Self {
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        let mut memory = Self {
            capacity,
            ttl_ticks,
            entries,
        };
        memory.enforce_capacity();
        memory
    }

    pub fn insert(
        &mut self,
        key: String,
        value_ref: String,
        tick_index: u64,
    ) -> WorkingMemoryUpdate {
        let mut keys_evicted = 0;
        if self.ttl_ticks == 0 {
            keys_evicted = self.entries.len() as u64;
            self.entries.clear();
        } else {
            let before = self.entries.len();
            self.entries
                .retain(|e| tick_index.saturating_sub(e.last_touched_tick) < self.ttl_ticks);
            keys_evicted += (before - self.entries.len()) as u64;
        }

        let mut keys_added = 0;
        if let Some(entry) = self.entries.iter_mut().find(|e| e.key == key) {
            entry.value_ref = value_ref;
            entry.last_touched_tick = tick_index;
        } else {
            self.entries.push(WorkingMemoryEntry {
                key,
                value_ref,
                last_touched_tick: tick_index,
            });
            keys_added = 1;
        }

        while self.entries.len() > self.capacity {
            self.remove_oldest();
            keys_evicted += 1;
        }

        WorkingMemoryUpdate {
            keys_added,
            keys_evicted,
        }
    }

    pub fn entries(&self) -> &[WorkingMemoryEntry] {
        &self.entries
    }

    fn remove_oldest(&mut self) {
        let mut oldest_idx = 0;
        let mut oldest_tick = self.entries[0].last_touched_tick;
        for (idx, entry) in self.entries.iter().enumerate().skip(1) {
            if entry.last_touched_tick < oldest_tick {
                oldest_tick = entry.last_touched_tick;
                oldest_idx = idx;
            }
        }
        self.entries.remove(oldest_idx);
    }

    fn enforce_capacity(&mut self) {
        while self.entries.len() > self.capacity {
            self.remove_oldest();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
struct WorkingSnapshotEntry {
    key: String,
    value_ref: String,
    last_touched_tick: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
struct WorkingSnapshot {
    schema: String,
    tick_index: u64,
    entries: Vec<WorkingSnapshotEntry>,
}

fn working_snapshot_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join("memory").join("working.json")
}

fn load_working_snapshot(runtime_root: &Path) -> Result<Option<WorkingSnapshot>, MemoryError> {
    // Single-writer runtime_root is assumed; concurrent writers may clobber working.json.tmp.
    let path = working_snapshot_path(runtime_root);
    if !path.exists() {
        return Ok(None);
    }
    let bytes =
        fs::read(&path).map_err(|e| MemoryError::with_source("working_snapshot_read_failed", e))?;
    let snapshot: WorkingSnapshot =
        serde_json::from_slice(&bytes).map_err(|_| MemoryError::new("working_snapshot_invalid"))?;
    if snapshot.schema != WORKING_SNAPSHOT_SCHEMA {
        return Err(MemoryError::new("working_snapshot_invalid"));
    }
    Ok(Some(snapshot))
}

pub fn load_working_memory(
    runtime_root: &Path,
    config: &MemoryConfig,
) -> Result<WorkingMemory, MemoryError> {
    match load_working_snapshot(runtime_root)? {
        Some(snapshot) => {
            let entries = snapshot
                .entries
                .into_iter()
                .map(|entry| WorkingMemoryEntry {
                    key: entry.key,
                    value_ref: entry.value_ref,
                    last_touched_tick: entry.last_touched_tick,
                })
                .collect();
            Ok(WorkingMemory::from_entries(
                config.working_capacity,
                config.working_ttl_ticks,
                entries,
            ))
        }
        None => Ok(WorkingMemory::new(
            config.working_capacity,
            config.working_ttl_ticks,
        )),
    }
}

pub fn write_working_snapshot(
    runtime_root: &Path,
    tick_index: u64,
    entries: &[WorkingMemoryEntry],
) -> Result<(), MemoryError> {
    let dir = runtime_root.join("memory");
    fs::create_dir_all(&dir)
        .map_err(|e| MemoryError::with_source("working_snapshot_write_failed", e))?;
    let mut snapshot_entries: Vec<WorkingSnapshotEntry> = entries
        .iter()
        .map(|entry| WorkingSnapshotEntry {
            key: entry.key.clone(),
            value_ref: entry.value_ref.clone(),
            last_touched_tick: entry.last_touched_tick,
        })
        .collect();
    snapshot_entries.sort_by(|a, b| a.key.cmp(&b.key));
    let snapshot = WorkingSnapshot {
        schema: WORKING_SNAPSHOT_SCHEMA.to_string(),
        tick_index,
        entries: snapshot_entries,
    };
    let value = serde_json::to_value(&snapshot)
        .map_err(|_| MemoryError::new("working_snapshot_write_failed"))?;
    let bytes = canonical_json_bytes(&value)
        .map_err(|_| MemoryError::new("working_snapshot_write_failed"))?;

    let path = working_snapshot_path(runtime_root);
    // Single-writer runtime_root is assumed; concurrent writers may clobber working.json.tmp.
    let tmp_path = dir.join("working.json.tmp");
    let mut file = fs::File::create(&tmp_path)
        .map_err(|e| MemoryError::with_source("working_snapshot_write_failed", e))?;
    file.write_all(&bytes)
        .map_err(|e| MemoryError::with_source("working_snapshot_write_failed", e))?;
    file.sync_all()
        .map_err(|e| MemoryError::with_source("working_snapshot_write_failed", e))?;
    if let Err(e) = fs::rename(&tmp_path, &path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(MemoryError::with_source("working_snapshot_write_failed", e));
    }
    Ok(())
}

pub fn open_memory_enabled() -> bool {
    std::env::var("OPEN_MEMORY_ENABLE")
        .map(|v| v == "1")
        .unwrap_or(false)
}

pub fn write_open_memory_mirror(
    runtime_root: &Path,
    episode_hashes: &[String],
) -> Result<u64, MemoryError> {
    let dir = runtime_root.join("memory");
    fs::create_dir_all(&dir)
        .map_err(|e| MemoryError::with_source("open_memory_write_failed", e))?;
    let path = dir.join("open_memory_mirror.jsonl");
    let value = serde_json::json!({ "episode_hashes": episode_hashes });
    let bytes =
        canonical_json_bytes(&value).map_err(|_| MemoryError::new("open_memory_write_failed"))?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| MemoryError::with_source("open_memory_write_failed", e))?;
    file.write_all(&bytes)
        .map_err(|e| MemoryError::with_source("open_memory_write_failed", e))?;
    file.write_all(b"\n")
        .map_err(|e| MemoryError::with_source("open_memory_write_failed", e))?;
    Ok(episode_hashes.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn episodic_hash_deterministic_across_runtimes() {
        let root_one = std::env::temp_dir().join(format!("pie_episode_one_{}", Uuid::new_v4()));
        let root_two = std::env::temp_dir().join(format!("pie_episode_two_{}", Uuid::new_v4()));
        let payload = EpisodePayload {
            tick_index: 0,
            intent_kind: "no_op".to_string(),
            request_hash: "sha256:request".to_string(),
            state_delta_ref: "sha256:delta".to_string(),
            artifact_refs: vec![],
        };
        let hash_one = append_episode(&root_one, None, payload.clone()).expect("append one");
        let hash_two = append_episode(&root_two, None, payload).expect("append two");
        assert_eq!(hash_one, hash_two);
    }

    #[test]
    fn episodic_head_points_to_latest() {
        let root = std::env::temp_dir().join(format!("pie_episode_head_{}", Uuid::new_v4()));
        let payload = EpisodePayload {
            tick_index: 0,
            intent_kind: "no_op".to_string(),
            request_hash: "sha256:request".to_string(),
            state_delta_ref: "sha256:delta".to_string(),
            artifact_refs: vec![],
        };
        let first = append_episode(&root, None, payload.clone()).expect("append one");
        let second = append_episode(&root, Some(first.clone()), payload).expect("append two");
        let head = load_episode_head(&root)
            .expect("load head")
            .expect("missing head");
        assert_eq!(head, second);
        let record = read_episode(&root, &head).expect("read head");
        assert_eq!(record.prev_episode_hash, Some(first));
    }

    #[test]
    fn episode_chain_lists_oldest_to_newest() {
        let root = std::env::temp_dir().join(format!("pie_episode_chain_{}", Uuid::new_v4()));
        let payload = EpisodePayload {
            tick_index: 0,
            intent_kind: "no_op".to_string(),
            request_hash: "sha256:request".to_string(),
            state_delta_ref: "sha256:delta".to_string(),
            artifact_refs: vec![],
        };
        let first = append_episode(&root, None, payload.clone()).expect("append one");
        let second =
            append_episode(&root, Some(first.clone()), payload.clone()).expect("append two");
        let third = append_episode(&root, Some(second.clone()), payload).expect("append three");
        let chain = list_episode_chain(&root).expect("list chain");
        assert_eq!(chain, vec![first, second, third]);
    }

    #[test]
    fn memory_config_defaults_when_missing() {
        let root = std::env::temp_dir().join(format!("pie_mem_cfg_default_{}", Uuid::new_v4()));
        let config = load_memory_config(&root).expect("load config");
        assert_eq!(config, MemoryConfig::default());
    }

    #[test]
    fn memory_config_overrides_are_applied() {
        let root = std::env::temp_dir().join(format!("pie_mem_cfg_override_{}", Uuid::new_v4()));
        let dir = root.join("memory");
        fs::create_dir_all(&dir).expect("create memory dir");
        let config = MemoryConfig {
            working_capacity: 5,
            working_ttl_ticks: 3,
        };
        let bytes = serde_json::to_vec(&config).expect("serialize config");
        fs::write(dir.join("config.json"), bytes).expect("write config");
        let loaded = load_memory_config(&root).expect("load config");
        assert_eq!(loaded, config);
    }

    #[test]
    fn working_memory_eviction_is_deterministic() {
        let mut memory = WorkingMemory::new(2, 2);
        let update1 = memory.insert("k1".to_string(), "v1".to_string(), 0);
        let update2 = memory.insert("k2".to_string(), "v2".to_string(), 0);
        let update3 = memory.insert("k3".to_string(), "v3".to_string(), 1);
        assert_eq!(update1.keys_added, 1);
        assert_eq!(update2.keys_added, 1);
        assert_eq!(update3.keys_evicted, 1);
        let keys: Vec<String> = memory.entries.iter().map(|e| e.key.clone()).collect();
        assert_eq!(keys, vec!["k2".to_string(), "k3".to_string()]);
    }
}
