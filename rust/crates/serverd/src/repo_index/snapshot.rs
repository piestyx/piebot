use super::canonical::domain_separated_hash;
use super::config::{ChunkMode, RepoIndexConfig};
use super::error::RepoIndexError;
use super::identity::RepoIdentityBuildOutput;
use super::schemas::REPO_INDEX_SNAPSHOT_SCHEMA;
use pie_common::{canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct RepoChunk {
    pub path: String,
    pub file_sha256: String,
    pub start: u64,
    pub len: u64,
    pub chunk_sha256: String,
    pub chunk_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct RepoIndexSnapshotArtifact {
    pub schema: String,
    pub repo_identity_root_hash: String,
    pub chunk_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_chunk_bytes: Option<u64>,
    pub chunks: Vec<RepoChunk>,
    pub root_hash: String,
}

#[derive(Debug, Clone)]
pub(crate) struct RepoIndexSnapshotBuildOutput {
    pub artifact: RepoIndexSnapshotArtifact,
    pub chunk_count: u64,
    pub file_count: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct RepoIndexSnapshotHashPayload<'a> {
    repo_identity_root_hash: &'a str,
    chunk_mode: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    fixed_chunk_bytes: Option<u64>,
    chunks: &'a [RepoChunk],
}

pub(crate) fn build_repo_index_snapshot(
    identity: &RepoIdentityBuildOutput,
    cfg: &RepoIndexConfig,
) -> Result<RepoIndexSnapshotBuildOutput, RepoIndexError> {
    let mode = cfg.chunk_mode_kind()?;
    let mut chunks: Vec<RepoChunk> = Vec::new();
    for file in &identity.files {
        match mode {
            ChunkMode::WholeFile => {
                push_chunk(
                    &mut chunks,
                    file.path.as_str(),
                    file.file_sha256.as_str(),
                    0,
                    file.bytes.as_slice(),
                )?;
            }
            ChunkMode::FixedSize => {
                let chunk_size = usize::try_from(cfg.fixed_chunk_bytes)
                    .map_err(|_| RepoIndexError::new("repo_index_config_invalid"))?;
                if chunk_size == 0 {
                    return Err(RepoIndexError::new("repo_index_config_invalid"));
                }
                if file.bytes.is_empty() {
                    push_chunk(
                        &mut chunks,
                        file.path.as_str(),
                        file.file_sha256.as_str(),
                        0,
                        &[],
                    )?;
                    continue;
                }
                let mut start = 0usize;
                while start < file.bytes.len() {
                    let end = std::cmp::min(start.saturating_add(chunk_size), file.bytes.len());
                    push_chunk(
                        &mut chunks,
                        file.path.as_str(),
                        file.file_sha256.as_str(),
                        start as u64,
                        &file.bytes[start..end],
                    )?;
                    start = end;
                }
            }
        }
    }
    chunks.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.start.cmp(&right.start))
            .then(left.len.cmp(&right.len))
    });
    let fixed_chunk_bytes = if mode == ChunkMode::FixedSize {
        Some(cfg.fixed_chunk_bytes)
    } else {
        None
    };
    let payload_value = serde_json::to_value(RepoIndexSnapshotHashPayload {
        repo_identity_root_hash: identity.artifact.root_hash.as_str(),
        chunk_mode: cfg.chunk_mode.as_str(),
        fixed_chunk_bytes,
        chunks: chunks.as_slice(),
    })
    .map_err(|_| RepoIndexError::new("repo_index_hash_failed"))?;
    let payload_bytes = canonical_json_bytes(&payload_value)
        .map_err(|_| RepoIndexError::new("repo_index_hash_failed"))?;
    let root_hash = domain_separated_hash("repo_index_snapshot.v1", payload_bytes.as_slice());
    let artifact = RepoIndexSnapshotArtifact {
        schema: REPO_INDEX_SNAPSHOT_SCHEMA.to_string(),
        repo_identity_root_hash: identity.artifact.root_hash.clone(),
        chunk_mode: cfg.chunk_mode.clone(),
        fixed_chunk_bytes,
        chunks,
        root_hash,
    };
    Ok(RepoIndexSnapshotBuildOutput {
        chunk_count: artifact.chunks.len() as u64,
        file_count: identity.file_count,
        artifact,
    })
}

fn push_chunk(
    chunks: &mut Vec<RepoChunk>,
    path: &str,
    file_sha256: &str,
    start: u64,
    chunk_bytes: &[u8],
) -> Result<(), RepoIndexError> {
    let len =
        u64::try_from(chunk_bytes.len()).map_err(|_| RepoIndexError::new("repo_index_hash_failed"))?;
    let chunk_sha256 = sha256_bytes(chunk_bytes);
    let chunk_hash_input = format!(
        "repo_chunk.v1\n{}\n{}\n{}\n{}",
        file_sha256, start, len, chunk_sha256
    );
    let chunk_hash = sha256_bytes(chunk_hash_input.as_bytes());
    chunks.push(RepoChunk {
        path: path.to_string(),
        file_sha256: file_sha256.to_string(),
        start,
        len,
        chunk_sha256,
        chunk_hash,
    });
    Ok(())
}
