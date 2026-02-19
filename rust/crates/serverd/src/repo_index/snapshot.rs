use super::canonical::{
    domain_separated_hash_ref, sha256_digest_hex, sha256_ref, sha256_ref_to_hex,
};
use super::config::{ChunkMode, RepoIndexConfig};
use super::error::RepoIndexError;
use super::identity::RepoIdentityBuildOutput;
use super::schemas::REPO_INDEX_SNAPSHOT_SCHEMA;
use pie_common::canonical_json_bytes;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;

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
    repo_identity_root_hash_hex: String,
    chunk_mode: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    fixed_chunk_bytes: Option<u64>,
    chunks: Vec<RepoChunkHashPayload>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct RepoChunkHashInputPayload {
    file_sha256_hex: String,
    start: u64,
    len: u64,
    chunk_sha256_hex: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct RepoChunkHashPayload {
    path: String,
    file_sha256_hex: String,
    start: u64,
    len: u64,
    chunk_sha256_hex: String,
    chunk_hash_hex: String,
}

pub(crate) fn build_repo_index_snapshot(
    identity: &RepoIdentityBuildOutput,
    cfg: &RepoIndexConfig,
) -> Result<RepoIndexSnapshotBuildOutput, RepoIndexError> {
    let mode = cfg.chunk_mode_kind()?;
    let mut chunks: Vec<RepoChunk> = Vec::new();
    for file in &identity.files {
        let file_sha256_hex = sha256_ref_to_hex(file.file_sha256.as_str())?;
        match mode {
            ChunkMode::WholeFile => {
                let file_bytes = fs::read(file.abs_path.as_path())
                    .map_err(|e| RepoIndexError::with_detail("repo_index_walk_failed", e.to_string()))?;
                let actual_bytes = u64::try_from(file_bytes.len())
                    .map_err(|_| RepoIndexError::new("repo_index_hash_failed"))?;
                if actual_bytes != file.bytes {
                    return Err(RepoIndexError::new("repo_index_walk_failed"));
                }
                push_chunk(
                    &mut chunks,
                    file.path.as_str(),
                    file.file_sha256.as_str(),
                    file_sha256_hex.as_str(),
                    0,
                    file_bytes.as_slice(),
                )?;
            }
            ChunkMode::FixedSize => {
                let chunk_size = usize::try_from(cfg.fixed_chunk_bytes)
                    .map_err(|_| RepoIndexError::new("repo_index_config_invalid"))?;
                if chunk_size == 0 {
                    return Err(RepoIndexError::new("repo_index_config_invalid"));
                }
                let mut handle = fs::File::open(file.abs_path.as_path())
                    .map_err(|e| RepoIndexError::with_detail("repo_index_walk_failed", e.to_string()))?;
                let mut buffer = vec![0u8; chunk_size];
                let mut start = 0u64;
                let mut emitted_any = false;
                let mut total_read = 0u64;
                loop {
                    let read = handle
                        .read(buffer.as_mut_slice())
                        .map_err(|e| RepoIndexError::with_detail("repo_index_walk_failed", e.to_string()))?;
                    if read == 0 {
                        break;
                    }
                    emitted_any = true;
                    push_chunk(
                        &mut chunks,
                        file.path.as_str(),
                        file.file_sha256.as_str(),
                        file_sha256_hex.as_str(),
                        start,
                        &buffer[0..read],
                    )?;
                    let read_u64 = u64::try_from(read)
                        .map_err(|_| RepoIndexError::new("repo_index_hash_failed"))?;
                    total_read = total_read
                        .checked_add(read_u64)
                        .ok_or_else(|| RepoIndexError::new("repo_index_hash_failed"))?;
                    start = start
                        .checked_add(read_u64)
                        .ok_or_else(|| RepoIndexError::new("repo_index_hash_failed"))?;
                }
                if total_read != file.bytes {
                    return Err(RepoIndexError::new("repo_index_walk_failed"));
                }
                if !emitted_any {
                    push_chunk(
                        &mut chunks,
                        file.path.as_str(),
                        file.file_sha256.as_str(),
                        file_sha256_hex.as_str(),
                        0,
                        &[],
                    )?;
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
    let mut chunk_hash_payloads: Vec<RepoChunkHashPayload> = Vec::with_capacity(chunks.len());
    for chunk in &chunks {
        chunk_hash_payloads.push(RepoChunkHashPayload {
            path: chunk.path.clone(),
            file_sha256_hex: sha256_ref_to_hex(chunk.file_sha256.as_str())?,
            start: chunk.start,
            len: chunk.len,
            chunk_sha256_hex: sha256_ref_to_hex(chunk.chunk_sha256.as_str())?,
            chunk_hash_hex: sha256_ref_to_hex(chunk.chunk_hash.as_str())?,
        });
    }
    let payload_value = serde_json::to_value(RepoIndexSnapshotHashPayload {
        repo_identity_root_hash_hex: sha256_ref_to_hex(identity.artifact.root_hash.as_str())?,
        chunk_mode: cfg.chunk_mode.as_str(),
        fixed_chunk_bytes,
        chunks: chunk_hash_payloads,
    })
    .map_err(|_| RepoIndexError::new("repo_index_hash_failed"))?;
    let payload_bytes = canonical_json_bytes(&payload_value)
        .map_err(|_| RepoIndexError::new("repo_index_hash_failed"))?;
    let root_hash = domain_separated_hash_ref("repo_index_snapshot.v1", payload_bytes.as_slice())?;
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
    file_sha256_ref: &str,
    file_sha256_hex: &str,
    start: u64,
    chunk_bytes: &[u8],
) -> Result<(), RepoIndexError> {
    let len =
        u64::try_from(chunk_bytes.len()).map_err(|_| RepoIndexError::new("repo_index_hash_failed"))?;
    let chunk_sha256_hex = sha256_digest_hex(chunk_bytes)?;
    let chunk_sha256_ref = sha256_ref(chunk_sha256_hex.as_str())?;
    let hash_input_value = serde_json::to_value(RepoChunkHashInputPayload {
        file_sha256_hex: file_sha256_hex.to_string(),
        start,
        len,
        chunk_sha256_hex,
    })
    .map_err(|_| RepoIndexError::new("repo_index_hash_failed"))?;
    let hash_input_bytes = canonical_json_bytes(&hash_input_value)
        .map_err(|_| RepoIndexError::new("repo_index_hash_failed"))?;
    let chunk_hash_ref = domain_separated_hash_ref("repo_chunk.v1", hash_input_bytes.as_slice())?;
    chunks.push(RepoChunk {
        path: path.to_string(),
        file_sha256: file_sha256_ref.to_string(),
        start,
        len,
        chunk_sha256: chunk_sha256_ref,
        chunk_hash: chunk_hash_ref,
    });
    Ok(())
}
