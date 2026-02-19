//! GSAMA Store: deterministic vector store with cosine similarity retrieval.

use crate::canonical::{compute_entry_id, compute_new_head_hash, genesis_head_hash};
use crate::math::{cosine_similarity, l2_normalized, MathError};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;

/// Error type for GSAMA store operations.
#[derive(Debug)]
pub enum StoreError {
    Math(MathError),
    DimensionMismatch { expected: usize, got: usize },
    EmptyStore,
    SnapshotInvalid(String),
    VectorNotNormalized { entry_id: String },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Math(e) => write!(f, "math error: {}", e),
            StoreError::DimensionMismatch { expected, got } => {
                write!(f, "dimension mismatch: expected {}, got {}", expected, got)
            }
            StoreError::EmptyStore => write!(f, "store is empty"),
            StoreError::SnapshotInvalid(reason) => write!(f, "snapshot invalid: {}", reason),
            StoreError::VectorNotNormalized { entry_id } => {
                write!(f, "vector not normalized for entry: {}", entry_id)
            }
        }
    }
}

impl std::error::Error for StoreError {}

impl From<MathError> for StoreError {
    fn from(e: MathError) -> Self {
        StoreError::Math(e)
    }
}

/// A single entry in the GSAMA store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Deterministic ID: sha256:...
    pub id: String,
    /// L2-normalized vector
    pub vector: Vec<f32>,
    /// Sorted tags as (key, value) pairs
    pub tags: Vec<(String, String)>,
    /// Entropy value (used for eviction)
    pub entropy: f32,
    /// Timestamp (explicit, not wall-clock)
    pub time: u64,
}

/// Result of a write operation.
#[derive(Debug, Clone)]
pub struct WriteResult {
    /// ID of the newly written entry
    pub id: String,
    /// IDs of entries evicted (in eviction order)
    pub evicted_ids: Vec<String>,
    /// New head hash after this write
    pub new_head_hash: [u8; 32],
}

/// A single retrieval result.
#[derive(Debug, Clone)]
pub struct RetrieveResult {
    /// Entry ID
    pub id: String,
    /// Cosine similarity score
    pub score: f32,
}

/// GSAMA Store: deterministic vector store.
#[derive(Debug, Clone)]
pub struct Store {
    /// Vector dimension (fixed at creation)
    dim: usize,
    /// Maximum capacity
    capacity: usize,
    /// Stored entries
    entries: Vec<Entry>,
    /// Current head hash for deterministic chaining
    head_hash: [u8; 32],
}

impl Store {
    /// Create a new store with given dimension and capacity.
    pub fn new(dim: usize, capacity: usize) -> Self {
        Store {
            dim,
            capacity,
            entries: Vec::new(),
            head_hash: genesis_head_hash(),
        }
    }

    /// Get current dimension.
    pub fn dim(&self) -> usize {
        self.dim
    }

    /// Get current capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get current number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get current head hash.
    pub fn head_hash(&self) -> &[u8; 32] {
        &self.head_hash
    }

    /// Get head hash as hex string.
    pub fn head_hash_hex(&self) -> String {
        format!("sha256:{}", hex::encode(self.head_hash))
    }

    /// Get all entries (for testing/serialization).
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Write a new entry to the store.
    ///
    /// - Normalizes the vector
    /// - Computes deterministic ID
    /// - Appends entry
    /// - Evicts if over capacity
    pub fn write(
        &mut self,
        vector: Vec<f32>,
        tags: Vec<(String, String)>,
        entropy: f32,
        time: u64,
    ) -> Result<WriteResult, StoreError> {
        // Validate dimension
        if vector.len() != self.dim {
            return Err(StoreError::DimensionMismatch {
                expected: self.dim,
                got: vector.len(),
            });
        }

        // Validate entropy
        if entropy.is_nan() || entropy.is_infinite() {
            return Err(StoreError::Math(MathError::NanValue));
        }

        // Normalize vector
        let normalized = l2_normalized(&vector)?;

        // Sort tags deterministically
        let mut sorted_tags = tags;
        sorted_tags.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        // Compute entry ID
        let id = compute_entry_id(&self.head_hash, &normalized, &sorted_tags, entropy, time);

        // Update head hash
        let new_head_hash = compute_new_head_hash(&self.head_hash, &id);

        // Create entry
        let entry = Entry {
            id: id.clone(),
            vector: normalized,
            tags: sorted_tags,
            entropy,
            time,
        };

        // Append
        self.entries.push(entry);
        self.head_hash = new_head_hash;

        // Evict if necessary
        let evicted_ids = self.evict();

        Ok(WriteResult {
            id,
            evicted_ids,
            new_head_hash,
        })
    }

    /// Evict entries to maintain capacity.
    /// Returns list of evicted IDs in eviction order.
    /// Eviction order: (entropy asc, time asc, id asc)
    fn evict(&mut self) -> Vec<String> {
        if self.entries.len() <= self.capacity {
            return Vec::new();
        }

        let to_evict = self.entries.len() - self.capacity;

        // Build eviction order: (entropy, time, id)
        let mut candidates: Vec<(f32, u64, String, usize)> = self
            .entries
            .iter()
            .enumerate()
            .map(|(idx, e)| (e.entropy, e.time, e.id.clone(), idx))
            .collect();

        // Sort by (entropy asc, time asc, id asc)
        candidates.sort_by(|a, b| {
            a.0.partial_cmp(&b.0)
                .unwrap_or(Ordering::Equal)
                .then(a.1.cmp(&b.1))
                .then(a.2.cmp(&b.2))
        });

        // Collect indices to remove (in eviction order)
        let mut evicted_ids = Vec::with_capacity(to_evict);
        let mut indices_to_remove: BTreeSet<usize> = BTreeSet::new();

        for (_, _, id, idx) in candidates.iter().take(to_evict) {
            evicted_ids.push(id.clone());
            indices_to_remove.insert(*idx);
        }

        // Remove entries (in reverse index order to preserve indices)
        let mut new_entries = Vec::with_capacity(self.entries.len() - to_evict);
        for (idx, entry) in self.entries.drain(..).enumerate() {
            if !indices_to_remove.contains(&idx) {
                new_entries.push(entry);
            }
        }
        self.entries = new_entries;

        evicted_ids
    }

    /// Retrieve up to k entries matching the query and optional tag filter.
    ///
    /// - Query vector is normalized
    /// - Filter by exact tag matches (all provided tags must match)
    /// - Results ordered by: (score desc, time desc, id asc)
    pub fn retrieve(
        &self,
        query: Vec<f32>,
        k: usize,
        tag_filter: Option<&[(String, String)]>,
    ) -> Result<Vec<RetrieveResult>, StoreError> {
        if k == 0 {
            return Ok(Vec::new());
        }

        if self.entries.is_empty() {
            return Ok(Vec::new());
        }

        // Validate dimension
        if query.len() != self.dim {
            return Err(StoreError::DimensionMismatch {
                expected: self.dim,
                got: query.len(),
            });
        }

        // Normalize query
        let query_norm = l2_normalized(&query)?;

        // Score all entries
        let mut scored: Vec<(f32, u64, &str)> = Vec::new();

        for entry in &self.entries {
            // Apply tag filter
            if let Some(filter) = tag_filter {
                let mut matches = true;
                for (fk, fv) in filter {
                    let found = entry.tags.iter().any(|(k, v)| k == fk && v == fv);
                    if !found {
                        matches = false;
                        break;
                    }
                }
                if !matches {
                    continue;
                }
            }

            // Compute cosine similarity
            let score = cosine_similarity(&query_norm, &entry.vector)?;
            scored.push((score, entry.time, &entry.id));
        }

        // Sort by (score desc, time desc, id asc)
        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(Ordering::Equal)
                .then(b.1.cmp(&a.1))
                .then(a.2.cmp(b.2))
        });

        // Take top k
        let results: Vec<RetrieveResult> = scored
            .into_iter()
            .take(k)
            .map(|(score, _, id)| RetrieveResult {
                id: id.to_string(),
                score,
            })
            .collect();

        Ok(results)
    }

    /// Get an entry by ID.
    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Create a snapshot of the store for persistence.
    /// The snapshot preserves all entry IDs and the head hash.
    pub fn to_snapshot(&self) -> StoreSnapshot {
        StoreSnapshot {
            schema: STORE_SNAPSHOT_SCHEMA.to_string(),
            dim: self.dim,
            capacity: self.capacity,
            head_hash: format!("sha256:{}", hex::encode(self.head_hash)),
            entries: self
                .entries
                .iter()
                .map(|e| SnapshotEntry {
                    id: e.id.clone(),
                    vector: e.vector.clone(),
                    tags: e.tags.clone(),
                    entropy: e.entropy,
                    time: e.time,
                })
                .collect(),
        }
    }

    /// Restore a store from a snapshot.
    /// Validates that all vectors are L2-normalized.
    pub fn from_snapshot(snapshot: StoreSnapshot) -> Result<Self, StoreError> {
        // Validate schema
        if snapshot.schema != STORE_SNAPSHOT_SCHEMA {
            return Err(StoreError::SnapshotInvalid(format!(
                "expected schema {}, got {}",
                STORE_SNAPSHOT_SCHEMA, snapshot.schema
            )));
        }

        // Parse head hash
        let head_hash = parse_head_hash(&snapshot.head_hash)?;

        // Validate and convert entries
        let mut entries = Vec::with_capacity(snapshot.entries.len());
        for se in snapshot.entries {
            // Validate vector dimension
            if se.vector.len() != snapshot.dim {
                return Err(StoreError::DimensionMismatch {
                    expected: snapshot.dim,
                    got: se.vector.len(),
                });
            }

            // Validate vector is normalized (within tolerance)
            if !is_normalized(&se.vector, 1e-5) {
                return Err(StoreError::VectorNotNormalized {
                    entry_id: se.id.clone(),
                });
            }

            // Validate no NaN/Inf in vector
            for &v in &se.vector {
                if v.is_nan() || v.is_infinite() {
                    return Err(StoreError::Math(MathError::NanValue));
                }
            }

            entries.push(Entry {
                id: se.id,
                vector: se.vector,
                tags: se.tags,
                entropy: se.entropy,
                time: se.time,
            });
        }

        Ok(Store {
            dim: snapshot.dim,
            capacity: snapshot.capacity,
            entries,
            head_hash,
        })
    }
}

/// Schema identifier for GSAMA store snapshots.
pub const STORE_SNAPSHOT_SCHEMA: &str = "gsama.store_snapshot.v1";

/// Serializable snapshot of a GSAMA store.
/// This preserves all entry IDs and the head hash for exact restoration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreSnapshot {
    /// Schema identifier
    pub schema: String,
    /// Vector dimension
    pub dim: usize,
    /// Maximum capacity
    pub capacity: usize,
    /// Head hash as "sha256:<hex>" string
    pub head_hash: String,
    /// All entries with their original IDs
    pub entries: Vec<SnapshotEntry>,
}

/// A single entry in a store snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    /// Entry ID (sha256:...)
    pub id: String,
    /// L2-normalized vector
    pub vector: Vec<f32>,
    /// Sorted tags as (key, value) pairs
    pub tags: Vec<(String, String)>,
    /// Entropy value
    pub entropy: f32,
    /// Timestamp
    pub time: u64,
}

/// Parse a head hash from "sha256:<hex>" format.
fn parse_head_hash(s: &str) -> Result<[u8; 32], StoreError> {
    let hex_str = s.strip_prefix("sha256:").ok_or_else(|| {
        StoreError::SnapshotInvalid("head_hash must start with 'sha256:'".to_string())
    })?;

    let bytes = hex::decode(hex_str)
        .map_err(|e| StoreError::SnapshotInvalid(format!("invalid head_hash hex: {}", e)))?;

    if bytes.len() != 32 {
        return Err(StoreError::SnapshotInvalid(format!(
            "head_hash must be 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Check if a vector is L2-normalized (norm ~= 1.0 within tolerance).
fn is_normalized(v: &[f32], tolerance: f32) -> bool {
    let norm_sq: f32 = v.iter().map(|x| x * x).sum();
    (norm_sq - 1.0).abs() < tolerance
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vector(dim: usize, seed: f32) -> Vec<f32> {
        (0..dim).map(|i| seed + i as f32).collect()
    }

    #[test]
    fn test_write_and_retrieve() {
        let mut store = Store::new(4, 10);

        let v1 = make_vector(4, 1.0);
        let result = store
            .write(v1.clone(), vec![("k".into(), "v1".into())], 0.5, 100)
            .unwrap();
        assert!(result.id.starts_with("sha256:"));
        assert!(result.evicted_ids.is_empty());

        let v2 = make_vector(4, 2.0);
        store
            .write(v2, vec![("k".into(), "v2".into())], 0.6, 200)
            .unwrap();

        assert_eq!(store.len(), 2);

        // Retrieve with query similar to v1
        let results = store.retrieve(v1, 10, None).unwrap();
        assert_eq!(results.len(), 2);
        // First result should be most similar to query
    }

    #[test]
    fn test_eviction_order() {
        let mut store = Store::new(2, 2);

        // Write 3 entries with different entropy/time
        store.write(vec![1.0, 0.0], vec![], 0.5, 100).unwrap(); // lowest entropy
        store.write(vec![0.0, 1.0], vec![], 0.7, 200).unwrap(); // higher entropy
        let result = store.write(vec![1.0, 1.0], vec![], 0.6, 300).unwrap(); // middle entropy

        // Should evict the one with lowest entropy (first write)
        assert_eq!(result.evicted_ids.len(), 1);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_deterministic_ids() {
        let mut store1 = Store::new(2, 10);
        let mut store2 = Store::new(2, 10);

        let v = vec![3.0, 4.0];
        let tags = vec![("a".into(), "1".into())];

        let r1 = store1.write(v.clone(), tags.clone(), 0.5, 1000).unwrap();
        let r2 = store2.write(v, tags, 0.5, 1000).unwrap();

        assert_eq!(r1.id, r2.id);
        assert_eq!(r1.new_head_hash, r2.new_head_hash);
    }

    #[test]
    fn test_zero_vector_rejected() {
        let mut store = Store::new(2, 10);
        let result = store.write(vec![0.0, 0.0], vec![], 0.5, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_nan_vector_rejected() {
        let mut store = Store::new(2, 10);
        let result = store.write(vec![1.0, f32::NAN], vec![], 0.5, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_inf_vector_rejected() {
        let mut store = Store::new(2, 10);
        let result = store.write(vec![1.0, f32::INFINITY], vec![], 0.5, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_tag_filter() {
        let mut store = Store::new(2, 10);

        store
            .write(vec![1.0, 0.0], vec![("type".into(), "a".into())], 0.5, 100)
            .unwrap();
        store
            .write(vec![0.0, 1.0], vec![("type".into(), "b".into())], 0.5, 200)
            .unwrap();

        // Filter for type=a
        let filter = vec![("type".into(), "a".into())];
        let results = store.retrieve(vec![1.0, 0.0], 10, Some(&filter)).unwrap();
        assert_eq!(results.len(), 1);

        // Filter for type=c (no matches)
        let filter = vec![("type".into(), "c".into())];
        let results = store.retrieve(vec![1.0, 0.0], 10, Some(&filter)).unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_dimension_mismatch() {
        let mut store = Store::new(4, 10);
        let result = store.write(vec![1.0, 2.0], vec![], 0.5, 100);
        assert!(matches!(result, Err(StoreError::DimensionMismatch { .. })));
    }

    #[test]
    fn test_snapshot_round_trip() {
        let mut store = Store::new(4, 10);

        // Write some entries
        let r1 = store
            .write(
                make_vector(4, 1.0),
                vec![("a".into(), "1".into())],
                0.5,
                100,
            )
            .unwrap();
        let r2 = store
            .write(
                make_vector(4, 2.0),
                vec![("b".into(), "2".into())],
                0.6,
                200,
            )
            .unwrap();

        // Create snapshot
        let snapshot = store.to_snapshot();
        assert_eq!(snapshot.schema, STORE_SNAPSHOT_SCHEMA);
        assert_eq!(snapshot.dim, 4);
        assert_eq!(snapshot.capacity, 10);
        assert_eq!(snapshot.entries.len(), 2);
        assert_eq!(snapshot.head_hash, store.head_hash_hex());

        // Restore from snapshot
        let restored = Store::from_snapshot(snapshot).unwrap();

        // Verify restoration
        assert_eq!(restored.dim(), store.dim());
        assert_eq!(restored.capacity(), store.capacity());
        assert_eq!(restored.len(), store.len());
        assert_eq!(restored.head_hash_hex(), store.head_hash_hex());

        // Verify entry IDs are preserved
        assert!(restored.get(&r1.id).is_some());
        assert!(restored.get(&r2.id).is_some());
    }

    #[test]
    fn test_snapshot_preserves_ids() {
        let mut store = Store::new(2, 10);
        let r1 = store.write(vec![3.0, 4.0], vec![], 0.5, 100).unwrap();
        let original_id = r1.id.clone();
        let original_head = store.head_hash_hex();

        // Round-trip through snapshot
        let snapshot = store.to_snapshot();
        let restored = Store::from_snapshot(snapshot).unwrap();

        // IDs must be identical (not regenerated)
        let restored_entry = restored.get(&original_id);
        assert!(restored_entry.is_some(), "Entry ID must be preserved");
        assert_eq!(
            restored.head_hash_hex(),
            original_head,
            "Head hash must be preserved"
        );
    }

    #[test]
    fn test_snapshot_json_serialization() {
        let mut store = Store::new(2, 10);
        store
            .write(vec![3.0, 4.0], vec![("key".into(), "val".into())], 0.5, 100)
            .unwrap();

        let snapshot = store.to_snapshot();
        let json = serde_json::to_string_pretty(&snapshot).unwrap();

        // Deserialize and restore
        let parsed: StoreSnapshot = serde_json::from_str(&json).unwrap();
        let restored = Store::from_snapshot(parsed).unwrap();

        assert_eq!(restored.head_hash_hex(), store.head_hash_hex());
    }

    #[test]
    fn test_snapshot_invalid_schema() {
        let snapshot = StoreSnapshot {
            schema: "wrong.schema.v1".to_string(),
            dim: 2,
            capacity: 10,
            head_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            entries: vec![],
        };

        let result = Store::from_snapshot(snapshot);
        assert!(matches!(result, Err(StoreError::SnapshotInvalid(_))));
    }

    #[test]
    fn test_snapshot_invalid_head_hash() {
        let snapshot = StoreSnapshot {
            schema: STORE_SNAPSHOT_SCHEMA.to_string(),
            dim: 2,
            capacity: 10,
            head_hash: "invalid".to_string(),
            entries: vec![],
        };

        let result = Store::from_snapshot(snapshot);
        assert!(matches!(result, Err(StoreError::SnapshotInvalid(_))));
    }

    #[test]
    fn test_snapshot_non_normalized_vector_rejected() {
        let snapshot = StoreSnapshot {
            schema: STORE_SNAPSHOT_SCHEMA.to_string(),
            dim: 2,
            capacity: 10,
            head_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            entries: vec![SnapshotEntry {
                id: "sha256:test".to_string(),
                vector: vec![1.0, 1.0], // Not normalized (norm = sqrt(2) != 1)
                tags: vec![],
                entropy: 0.5,
                time: 100,
            }],
        };

        let result = Store::from_snapshot(snapshot);
        assert!(matches!(
            result,
            Err(StoreError::VectorNotNormalized { .. })
        ));
    }
}
