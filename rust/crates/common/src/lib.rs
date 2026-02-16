use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug)]
pub enum CanonError {
    Json(serde_json::Error),
}

impl fmt::Display for CanonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonError::Json(e) => write!(f, "json: {}", e),
        }
    }
}

impl std::error::Error for CanonError {}

impl From<serde_json::Error> for CanonError {
    fn from(value: serde_json::Error) -> Self {
        CanonError::Json(value)
    }
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{}", hex::encode(h.finalize()))
}

pub fn canonical_json_bytes(v: &Value) -> Result<Vec<u8>, CanonError> {
    fn canonicalize_value(v: &Value) -> Value {
        match v {
            Value::Object(map) => {
                let mut keys: Vec<_> = map.iter().collect();
                keys.sort_by(|a, b| a.0.cmp(b.0));
                let mut out = serde_json::Map::new();
                for (k, v) in keys {
                    out.insert(k.clone(), canonicalize_value(v));
                }
                Value::Object(out)
            }
            Value::Array(arr) => Value::Array(arr.iter().map(canonicalize_value).collect()),
            _ => v.clone(),
        }
    }

    let canon = canonicalize_value(v);
    Ok(serde_json::to_vec(&canon)?)
}
