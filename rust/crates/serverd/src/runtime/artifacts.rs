use crate::provider::ProviderError;
use crate::tools::ToolError;
use pie_common::{canonical_json_bytes, sha256_bytes};
use std::fs;
use std::io::Write;
use std::path::Path;
#[derive(Debug)]
pub(crate) struct ArtifactError {
    reason: &'static str,
    source: Option<std::io::Error>,
}

impl ArtifactError {
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

    pub(crate) fn reason(&self) -> &'static str {
        self.reason
    }

    pub(crate) fn into_source(self) -> Option<std::io::Error> {
        self.source
    }
}

impl std::fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for ArtifactError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e as _)
    }
}

impl From<ArtifactError> for ProviderError {
    fn from(error: ArtifactError) -> Self {
        let reason = error.reason();
        match error.into_source() {
            Some(source) => ProviderError::with_source(reason, source),
            None => ProviderError::new(reason),
        }
    }
}

impl From<ArtifactError> for ToolError {
    fn from(error: ArtifactError) -> Self {
        let reason = error.reason();
        match error.into_source() {
            Some(source) => ToolError::with_source(reason, source),
            None => ToolError::new(reason),
        }
    }
}

pub(crate) fn write_json_artifact_atomic(
    runtime_root: &Path,
    subdir: &str,
    value: &serde_json::Value,
) -> Result<String, ArtifactError> {
    let bytes =
        canonical_json_bytes(value).map_err(|_| ArtifactError::new("artifact_hash_failed"))?;
    let artifact_ref = sha256_bytes(&bytes);
    let dir = runtime_root.join("artifacts").join(subdir);
    fs::create_dir_all(&dir).map_err(|e| ArtifactError::with_source("artifact_write_failed", e))?;
    let filename = artifact_filename(&artifact_ref);
    let path = dir.join(&filename);
    if path.exists() {
        let existing =
            fs::read(&path).map_err(|e| ArtifactError::with_source("artifact_read_failed", e))?;
        if existing != bytes {
            return Err(ArtifactError::new("artifact_conflict"));
        }
        return Ok(artifact_ref);
    }
    let tmp_path = dir.join(format!("{}.tmp", filename));
    let mut file = fs::File::create(&tmp_path)
        .map_err(|e| ArtifactError::with_source("artifact_write_failed", e))?;
    file.write_all(&bytes)
        .map_err(|e| ArtifactError::with_source("artifact_write_failed", e))?;
    file.sync_all()
        .map_err(|e| ArtifactError::with_source("artifact_write_failed", e))?;
    if let Err(e) = fs::rename(&tmp_path, &path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(ArtifactError::with_source("artifact_write_failed", e));
    }
    Ok(artifact_ref)
}

pub(crate) fn write_json_artifact_at_ref_atomic(
    runtime_root: &Path,
    subdir: &str,
    artifact_ref: &str,
    value: &serde_json::Value,
) -> Result<String, ArtifactError> {
    if !is_sha256_ref(artifact_ref) {
        return Err(ArtifactError::new("artifact_ref_invalid"));
    }
    let bytes =
        canonical_json_bytes(value).map_err(|_| ArtifactError::new("artifact_hash_failed"))?;
    let dir = runtime_root.join("artifacts").join(subdir);
    fs::create_dir_all(&dir).map_err(|e| ArtifactError::with_source("artifact_write_failed", e))?;
    let filename = artifact_filename(artifact_ref);
    let path = dir.join(&filename);
    if path.exists() {
        let existing =
            fs::read(&path).map_err(|e| ArtifactError::with_source("artifact_read_failed", e))?;
        if existing != bytes {
            return Err(ArtifactError::new("artifact_conflict"));
        }
        return Ok(artifact_ref.to_string());
    }
    let tmp_path = dir.join(format!("{}.tmp", filename));
    let mut file = fs::File::create(&tmp_path)
        .map_err(|e| ArtifactError::with_source("artifact_write_failed", e))?;
    file.write_all(&bytes)
        .map_err(|e| ArtifactError::with_source("artifact_write_failed", e))?;
    file.sync_all()
        .map_err(|e| ArtifactError::with_source("artifact_write_failed", e))?;
    if let Err(e) = fs::rename(&tmp_path, &path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(ArtifactError::with_source("artifact_write_failed", e));
    }
    Ok(artifact_ref.to_string())
}

pub(crate) fn artifact_filename(artifact_ref: &str) -> String {
    let trimmed = artifact_ref.strip_prefix("sha256:").unwrap_or(artifact_ref);
    format!("{}.json", trimmed)
}

pub(crate) fn is_sha256_ref(value: &str) -> bool {
    if let Some(rest) = value.strip_prefix("sha256:") {
        if rest.len() != 64 {
            return false;
        }
        return rest.chars().all(|c| c.is_ascii_hexdigit());
    }
    false
}
