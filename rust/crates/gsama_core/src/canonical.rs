//! Canonical serialization for deterministic ID and hash computation.
//!
//! All bytes are computed deterministically:
//! - Floats: IEEE754 little-endian bytes
//! - Tags: sorted by key, then canonical JSON bytes
//! - Vectors: concatenated f32 little-endian bytes

use sha2::{Digest, Sha256};

/// Genesis hash for GSAMA chain.
pub const GENESIS_PREIMAGE: &str = "gsama.genesis.v1";

/// Compute sha256 of bytes, returning "sha256:<hex>" string.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Compute sha256 of bytes, returning raw 32-byte array.
pub fn sha256_raw(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Compute genesis head hash.
pub fn genesis_head_hash() -> [u8; 32] {
    sha256_raw(GENESIS_PREIMAGE.as_bytes())
}

/// Serialize a vector to canonical bytes (f32 little-endian).
pub fn vector_to_bytes(v: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(v.len() * 4);
    for &x in v {
        bytes.extend_from_slice(&x.to_le_bytes());
    }
    bytes
}

/// Serialize tags to canonical bytes.
/// Tags are sorted by key, then serialized as canonical JSON.
pub fn tags_to_bytes(tags: &[(String, String)]) -> Vec<u8> {
    // Tags should already be sorted, but ensure it
    let mut sorted: Vec<_> = tags.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    // Serialize as JSON array of [key, value] pairs
    let json_array: Vec<[&str; 2]> = sorted
        .iter()
        .map(|(k, v)| [k.as_str(), v.as_str()])
        .collect();
    serde_json::to_vec(&json_array).expect("tags serialization cannot fail")
}

/// Serialize entropy to canonical bytes (f32 little-endian).
pub fn entropy_to_bytes(entropy: f32) -> [u8; 4] {
    entropy.to_le_bytes()
}

/// Serialize time to canonical bytes (u64 little-endian).
pub fn time_to_bytes(time: u64) -> [u8; 8] {
    time.to_le_bytes()
}

/// Compute entry ID from components.
/// id = sha256(prev_head_hash || vector_bytes || tags_bytes || entropy_bytes || time_bytes)
pub fn compute_entry_id(
    prev_head_hash: &[u8; 32],
    vector: &[f32],
    tags: &[(String, String)],
    entropy: f32,
    time: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_head_hash);
    hasher.update(&vector_to_bytes(vector));
    hasher.update(&tags_to_bytes(tags));
    hasher.update(&entropy_to_bytes(entropy));
    hasher.update(&time_to_bytes(time));
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Compute new head hash after appending an entry.
/// new_head = sha256(prev_head_hash || id_bytes)
pub fn compute_new_head_hash(prev_head_hash: &[u8; 32], entry_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev_head_hash);
    hasher.update(entry_id.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_hash_deterministic() {
        let h1 = genesis_head_hash();
        let h2 = genesis_head_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_vector_bytes_deterministic() {
        let v = vec![1.0f32, 2.0, 3.0];
        let b1 = vector_to_bytes(&v);
        let b2 = vector_to_bytes(&v);
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_tags_bytes_sorted() {
        let tags1 = vec![
            ("b".to_string(), "2".to_string()),
            ("a".to_string(), "1".to_string()),
        ];
        let tags2 = vec![
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ];
        assert_eq!(tags_to_bytes(&tags1), tags_to_bytes(&tags2));
    }

    #[test]
    fn test_entry_id_deterministic() {
        let prev = genesis_head_hash();
        let vector = vec![0.6f32, 0.8];
        let tags = vec![("k".to_string(), "v".to_string())];
        let entropy = 0.5f32;
        let time = 1000u64;

        let id1 = compute_entry_id(&prev, &vector, &tags, entropy, time);
        let id2 = compute_entry_id(&prev, &vector, &tags, entropy, time);
        assert_eq!(id1, id2);
        assert!(id1.starts_with("sha256:"));
    }
}
