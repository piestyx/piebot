use pie_common::{canonical_serialize_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use uuid::Uuid;
const GENESIS_NAMESPACE_UUID: Uuid = Uuid::from_u128(0x6f6a2a9c8b1f4f5aa0d3c2e1b7a49f10);
const GENESIS_SEED: &str = "piebot.kernel_state.genesis.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelState {
    pub schema_version: u8,
    pub state_id: Uuid,
    pub tick: u64,
    pub goals: Vec<String>,
    pub constraints: Vec<String>,
    pub tags: BTreeMap<String, String>,
}

impl Default for KernelState {
    fn default() -> Self {
        Self {
            schema_version: 1,
            state_id: Uuid::new_v5(&GENESIS_NAMESPACE_UUID, GENESIS_SEED.as_bytes()),
            tick: 0,
            goals: vec![],
            constraints: vec![],
            tags: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum StateDelta {
    TickAdvance { by: u64 },
    SetTag { key: String, value: String },
}

pub fn load_or_init(path: impl AsRef<Path>) -> Result<KernelState, std::io::Error> {
    let path = path.as_ref();
    if path.exists() {
        let bytes = fs::read(path)?;
        let state: KernelState = serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(state)
    } else {
        Ok(KernelState::default())
    }
}

pub fn save(path: impl AsRef<Path>, state: &KernelState) -> Result<(), std::io::Error> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    fs::write(path, bytes)?;
    Ok(())
}

pub fn apply_delta(mut state: KernelState, delta: &StateDelta) -> KernelState {
    match delta {
        StateDelta::TickAdvance { by } => state.tick = state.tick.saturating_add(*by),
        StateDelta::SetTag { key, value } => {
            state.tags.insert(key.clone(), value.clone());
        }
    }
    state
}

pub fn state_hash(state: &KernelState) -> String {
    // Deterministic: hash canonical JSON bytes (sorted object keys).
    // Convert to Value first because pie_common canonicalizes Value only.
    let v = canonical_serialize_bytes(state).unwrap_or_default();
    sha256_bytes(&v)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_changes_after_delta() {
        let base = KernelState::default();
        let h0 = state_hash(&base);
        let next = apply_delta(base, &StateDelta::TickAdvance { by: 1 });
        let h1 = state_hash(&next);
        assert_ne!(h0, h1);
    }

    #[test]
    fn genesis_state_id_is_deterministic() {
        let expected = Uuid::new_v5(&GENESIS_NAMESPACE_UUID, GENESIS_SEED.as_bytes());
        let state = KernelState::default();
        assert_eq!(state.state_id, expected);
    }

    #[test]
    fn hash_is_stable_across_json_formatting() {
        let mut s = KernelState::default();
        s.tags.insert("b".into(), "2".into());
        s.tags.insert("a".into(), "1".into());

        // Pretty vs compact bytes should not matter for the hash (canonicalization fixes it).
        let pretty = serde_json::to_vec_pretty(&s).unwrap();
        let compact = serde_json::to_vec(&s).unwrap();

        let parsed_pretty: KernelState = serde_json::from_slice(&pretty).unwrap();
        let parsed_compact: KernelState = serde_json::from_slice(&compact).unwrap();

        let h1 = state_hash(&parsed_pretty);
        let h2 = state_hash(&parsed_compact);
        assert_eq!(h1, h2, "canonical hash must be formatting-invariant");
    }
}
