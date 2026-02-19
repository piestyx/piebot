mod canonical;
mod config;
mod error;
mod identity;
mod schemas;
mod snapshot;

use crate::audit::{append_event, AuditEvent};
use crate::command::ProviderMode;
use crate::runtime::artifacts::write_json_artifact_atomic;
use pie_audit_log::AuditAppender;
use std::path::Path;

pub(crate) use self::canonical::{domain_separated_hash_ref, sha256_ref_to_hex};
use self::config::load_repo_index_config;
use self::error::RepoIndexError;
use self::identity::build_repo_identity;
use self::snapshot::build_repo_index_snapshot;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct RepoIndexEvidence {
    pub repo_identity_ref: String,
    pub repo_identity_root_hash: String,
    pub repo_index_snapshot_ref: String,
    pub repo_index_snapshot_root_hash: String,
}

pub(crate) fn maybe_build_repo_index(
    runtime_root: &Path,
    workspace_root: &Path,
    provider_mode: ProviderMode,
    audit: &mut AuditAppender,
) -> Result<Option<RepoIndexEvidence>, RepoIndexError> {
    let config = load_repo_index_config(runtime_root)?;
    if !config.enabled {
        return Ok(None);
    }
    if matches!(provider_mode, ProviderMode::Replay)
        && (!workspace_root.exists() || !workspace_root.is_dir())
    {
        return Err(RepoIndexError::new(
            "repo_index_workspace_unavailable_in_replay",
        ));
    }

    let identity = build_repo_identity(workspace_root, &config)?;
    let identity_value = serde_json::to_value(&identity.artifact)
        .map_err(|_| RepoIndexError::new("repo_index_hash_failed"))?;
    let identity_ref = write_json_artifact_atomic(runtime_root, "repo_identity", &identity_value)
        .map_err(|e| {
        RepoIndexError::with_detail("repo_index_identity_write_failed", e.to_string())
    })?;
    append_event(
        audit,
        AuditEvent::RepoIdentityWritten {
            root_hash: identity.artifact.root_hash.clone(),
            artifact_ref: identity_ref.clone(),
            file_count: identity.file_count,
            total_bytes: identity.total_bytes,
        },
    )
    .map_err(|e| RepoIndexError::with_detail("repo_index_audit_failed", e.to_string()))?;

    let snapshot = build_repo_index_snapshot(&identity, &config)?;
    let snapshot_value = serde_json::to_value(&snapshot.artifact)
        .map_err(|_| RepoIndexError::new("repo_index_hash_failed"))?;
    let snapshot_ref =
        write_json_artifact_atomic(runtime_root, "repo_index_snapshot", &snapshot_value).map_err(
            |e| RepoIndexError::with_detail("repo_index_snapshot_write_failed", e.to_string()),
        )?;
    append_event(
        audit,
        AuditEvent::RepoIndexSnapshotWritten {
            root_hash: snapshot.artifact.root_hash.clone(),
            artifact_ref: snapshot_ref.clone(),
            chunk_count: snapshot.chunk_count,
            file_count: snapshot.file_count,
        },
    )
    .map_err(|e| RepoIndexError::with_detail("repo_index_audit_failed", e.to_string()))?;

    Ok(Some(RepoIndexEvidence {
        repo_identity_ref: identity_ref,
        repo_identity_root_hash: identity.artifact.root_hash,
        repo_index_snapshot_ref: snapshot_ref,
        repo_index_snapshot_root_hash: snapshot.artifact.root_hash,
    }))
}
