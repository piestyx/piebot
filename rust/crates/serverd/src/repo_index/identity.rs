use super::canonical::{
    canonical_rel_path, domain_separated_hash_ref, list_files, sha256_digest_hex, sha256_ref,
    sha256_ref_to_hex,
};
use super::config::RepoIndexConfig;
use super::error::RepoIndexError;
use super::schemas::REPO_IDENTITY_SCHEMA;
use pie_common::canonical_json_bytes;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct RepoFileEntry {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct RepoIdentityArtifact {
    pub schema: String,
    pub files: Vec<RepoFileEntry>,
    pub root_hash: String,
}

#[derive(Debug, Clone)]
pub(crate) struct RepoIndexedFileMeta {
    pub path: String,
    pub abs_path: PathBuf,
    pub file_sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct RepoIdentityBuildOutput {
    pub artifact: RepoIdentityArtifact,
    pub files: Vec<RepoIndexedFileMeta>,
    pub file_count: u64,
    pub total_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct RepoIdentityHashFileEntry {
    path: String,
    sha256_hex: String,
    bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct RepoIdentityHashPayload {
    files: Vec<RepoIdentityHashFileEntry>,
}

pub(crate) fn build_repo_identity(
    workspace_root: &Path,
    cfg: &RepoIndexConfig,
) -> Result<RepoIdentityBuildOutput, RepoIndexError> {
    let file_paths = list_files(workspace_root, cfg)?;
    let mut files: Vec<RepoIndexedFileMeta> = Vec::with_capacity(file_paths.len());
    let mut entries: Vec<RepoFileEntry> = Vec::with_capacity(file_paths.len());
    let mut total_bytes = 0u64;
    for file_path in file_paths {
        let path = canonical_rel_path(workspace_root, file_path.as_path())?;
        let bytes = fs::read(file_path.as_path())
            .map_err(|e| RepoIndexError::with_detail("repo_index_walk_failed", e.to_string()))?;
        let file_len =
            u64::try_from(bytes.len()).map_err(|_| RepoIndexError::new("repo_index_total_too_large"))?;
        if file_len > cfg.max_file_bytes {
            return Err(RepoIndexError::new("repo_index_file_too_large"));
        }
        total_bytes = total_bytes
            .checked_add(file_len)
            .ok_or_else(|| RepoIndexError::new("repo_index_total_too_large"))?;
        if total_bytes > cfg.max_total_bytes {
            return Err(RepoIndexError::new("repo_index_total_too_large"));
        }
        let file_sha256_hex = sha256_digest_hex(bytes.as_slice())?;
        let file_sha256 = sha256_ref(file_sha256_hex.as_str())?;
        entries.push(RepoFileEntry {
            path: path.clone(),
            sha256: file_sha256.clone(),
            bytes: file_len,
        });
        files.push(RepoIndexedFileMeta {
            path,
            abs_path: file_path,
            file_sha256,
            bytes: file_len,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let mut hash_files: Vec<RepoIdentityHashFileEntry> = Vec::with_capacity(entries.len());
    for entry in &entries {
        hash_files.push(RepoIdentityHashFileEntry {
            path: entry.path.clone(),
            sha256_hex: sha256_ref_to_hex(entry.sha256.as_str())?,
            bytes: entry.bytes,
        });
    }
    let payload_value = serde_json::to_value(RepoIdentityHashPayload { files: hash_files })
        .map_err(|_| RepoIndexError::new("repo_index_hash_failed"))?;
    let payload_bytes = canonical_json_bytes(&payload_value)
        .map_err(|_| RepoIndexError::new("repo_index_hash_failed"))?;
    let root_hash = domain_separated_hash_ref("repo_identity.v1", payload_bytes.as_slice())?;
    let artifact = RepoIdentityArtifact {
        schema: REPO_IDENTITY_SCHEMA.to_string(),
        files: entries,
        root_hash,
    };
    Ok(RepoIdentityBuildOutput {
        file_count: artifact.files.len() as u64,
        total_bytes,
        artifact,
        files,
    })
}
