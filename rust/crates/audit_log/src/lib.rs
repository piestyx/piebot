use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use pie_common::{canonical_json_bytes, sha256_bytes, CanonError};

#[derive(Debug, thiserror::Error)]
pub enum AuditLogError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("canon: {0}")]
    Canon(#[from] CanonError),
    #[error("hash chain broken at line {line}: expected {expected}, got {got}")]
    HashChainBroken {
        line: usize,
        expected: String,
        got: String,
    },
    #[error("unknown algo_version at line {line}: {version}")]
    UnknownAlgoVersion { line: usize, version: u8 },
}

fn default_algo_version() -> u8 {
    1
}

const ALGO_V1: u8 = 1;
const ALGO_V2: u8 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    #[serde(default = "default_algo_version")]
    pub algo_version: u8,
    pub prev_hash: String,
    pub hash: String,
    pub event: serde_json::Value,
}

pub struct AuditAppender {
    path: PathBuf,
    file: File,
    last_hash: String,
}

impl AuditAppender {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditLogError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let last_hash = verify_log(&path)?;
        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        Ok(Self {
            path,
            file,
            last_hash,
        })
    }

    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    pub fn append<T: Serialize>(&mut self, event: &T) -> Result<String, AuditLogError> {
        let event_value = serde_json::to_value(event)?;
        let payload = serde_json::json!({
            "prev_hash": self.last_hash,
            "event": event_value
        });
        let canon = canonical_json_bytes(&payload)?;
        let new_hash = sha256_bytes(&canon);

        let record = AuditRecord {
            algo_version: ALGO_V2,
            prev_hash: self.last_hash.clone(),
            hash: new_hash.clone(),
            event: event_value,
        };

        let line = serde_json::to_vec(&record)?;
        self.file.write_all(&line)?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;

        self.last_hash = new_hash.clone();
        Ok(new_hash)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn verify_log(path: impl AsRef<Path>) -> Result<String, AuditLogError> {
    let path = path.as_ref();

    if !path.exists() {
        return Ok("sha256:".to_string());
    }

    let f = File::open(path)?;
    let rdr = BufReader::new(f);

    let mut expected_prev = "sha256:".to_string();
    let mut last_hash = expected_prev.clone();

    for (i, line) in rdr.lines().enumerate() {
        let line_no = i + 1;
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let record: AuditRecord = serde_json::from_str(&line)?;

        if record.prev_hash != expected_prev {
            return Err(AuditLogError::HashChainBroken {
                line: line_no,
                expected: expected_prev,
                got: record.prev_hash,
            });
        }

        let AuditRecord {
            algo_version,
            prev_hash,
            hash,
            event,
        } = record;

        let computed = match algo_version {
            ALGO_V1 => {
                let event_type = event
                    .get("event_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let input = format!("{}|{}", prev_hash, event_type);
                sha256_bytes(input.as_bytes())
            }
            ALGO_V2 => {
                let payload = serde_json::json!({
                    "prev_hash": prev_hash,
                    "event": event
                });
                let canon = canonical_json_bytes(&payload)?;
                sha256_bytes(&canon)
            }
            other => {
                return Err(AuditLogError::UnknownAlgoVersion {
                    line: line_no,
                    version: other,
                });
            }
        };

        if computed != hash {
            return Err(AuditLogError::HashChainBroken {
                line: line_no,
                expected: computed,
                got: hash,
            });
        }
        expected_prev = hash.clone();
        last_hash = hash.clone();
    }

    Ok(last_hash)
}
