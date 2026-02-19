use super::config::RepoIndexConfig;
use super::error::RepoIndexError;
use pie_common::sha256_bytes;
use std::fs;
use std::path::{Component, Path, PathBuf};

const BASELINE_DENIED_DIRS: [&str; 4] = [".git", "target", "runtime", "node_modules"];
// Hashing contract:
// 1) hash inputs use hex-only digests (or raw bytes), never "sha256:<hex>" strings.
// 2) "sha256:<hex>" is display/storage form only for artifacts and audit fields.
pub(crate) fn sha256_digest_hex(bytes: &[u8]) -> Result<String, RepoIndexError> {
    let digest = sha256_bytes(bytes);
    normalize_digest_hex(digest.as_str())
        .map(|value| value.to_string())
        .ok_or_else(|| RepoIndexError::new("repo_index_hash_failed"))
}

pub(crate) fn sha256_ref(hex: &str) -> Result<String, RepoIndexError> {
    let normalized =
        normalize_digest_hex(hex).ok_or_else(|| RepoIndexError::new("repo_index_hash_failed"))?;
    Ok(format!("sha256:{}", normalized))
}

pub(crate) fn sha256_ref_to_hex(value: &str) -> Result<String, RepoIndexError> {
    normalize_digest_hex(value)
        .map(|normalized| normalized.to_string())
        .ok_or_else(|| RepoIndexError::new("repo_index_hash_failed"))
}

pub(crate) fn domain_separated_hash_hex(
    domain: &str,
    payload: &[u8],
) -> Result<String, RepoIndexError> {
    let mut data = Vec::with_capacity(domain.len() + 1 + payload.len());
    data.extend_from_slice(domain.as_bytes());
    data.push(b'\n');
    data.extend_from_slice(payload);
    sha256_digest_hex(data.as_slice())
}

pub(crate) fn domain_separated_hash_ref(
    domain: &str,
    payload: &[u8],
) -> Result<String, RepoIndexError> {
    let digest_hex = domain_separated_hash_hex(domain, payload)?;
    sha256_ref(digest_hex.as_str())
}

pub(crate) fn canonical_rel_path(root: &Path, path: &Path) -> Result<String, RepoIndexError> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| RepoIndexError::new("repo_index_path_invalid"))?;
    let mut parts = Vec::new();
    for component in rel.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                return Err(RepoIndexError::new("repo_index_path_invalid"));
            }
            Component::ParentDir => {
                return Err(RepoIndexError::new("repo_index_path_invalid"));
            }
            Component::CurDir => {}
            Component::Normal(part) => {
                let value = part
                    .to_str()
                    .ok_or_else(|| RepoIndexError::new("repo_index_path_invalid"))?;
                if value.is_empty() || value.contains('\\') {
                    return Err(RepoIndexError::new("repo_index_path_invalid"));
                }
                parts.push(value.to_string());
            }
        }
    }
    if parts.is_empty() {
        return Err(RepoIndexError::new("repo_index_path_invalid"));
    }
    Ok(parts.join("/"))
}

pub(crate) fn list_files(
    workspace_root: &Path,
    cfg: &RepoIndexConfig,
) -> Result<Vec<PathBuf>, RepoIndexError> {
    if !workspace_root.exists() {
        return Err(RepoIndexError::new("repo_index_workspace_missing"));
    }
    let root_meta = fs::symlink_metadata(workspace_root)
        .map_err(|e| RepoIndexError::with_detail("repo_index_walk_failed", e.to_string()))?;
    if root_meta.file_type().is_symlink() {
        return Err(RepoIndexError::new("repo_index_symlink_denied"));
    }
    if !root_meta.is_dir() {
        return Err(RepoIndexError::new("repo_index_workspace_missing"));
    }
    let mut total_bytes = 0u64;
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    walk_dir(
        workspace_root,
        workspace_root,
        cfg,
        &mut total_bytes,
        &mut files,
    )?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(files.into_iter().map(|(_, path)| path).collect())
}

fn walk_dir(
    root: &Path,
    dir: &Path,
    cfg: &RepoIndexConfig,
    total_bytes: &mut u64,
    files: &mut Vec<(String, PathBuf)>,
) -> Result<(), RepoIndexError> {
    let read_dir = fs::read_dir(dir)
        .map_err(|e| RepoIndexError::with_detail("repo_index_walk_failed", e.to_string()))?;
    let mut entries: Vec<WalkEntry> = Vec::new();
    for entry in read_dir {
        let entry = entry
            .map_err(|e| RepoIndexError::with_detail("repo_index_walk_failed", e.to_string()))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| RepoIndexError::with_detail("repo_index_walk_failed", e.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(RepoIndexError::new("repo_index_symlink_denied"));
        }
        let rel_path = canonical_rel_path(root, &path)?;
        entries.push(WalkEntry {
            rel_path,
            abs_path: path,
            is_dir: metadata.is_dir(),
            is_file: metadata.is_file(),
            file_len: metadata.len(),
        });
    }
    entries.sort_by(|left, right| left.rel_path.cmp(&right.rel_path));
    for entry in entries {
        if entry.is_dir {
            if should_skip_dir(entry.rel_path.as_str(), cfg) {
                continue;
            }
            walk_dir(root, entry.abs_path.as_path(), cfg, total_bytes, files)?;
            continue;
        }
        if !entry.is_file {
            continue;
        }
        if should_ignore_path(entry.rel_path.as_str(), cfg) {
            continue;
        }
        if entry.file_len > cfg.max_file_bytes {
            return Err(RepoIndexError::new("repo_index_file_too_large"));
        }
        *total_bytes = total_bytes
            .checked_add(entry.file_len)
            .ok_or_else(|| RepoIndexError::new("repo_index_total_too_large"))?;
        if *total_bytes > cfg.max_total_bytes {
            return Err(RepoIndexError::new("repo_index_total_too_large"));
        }
        files.push((entry.rel_path, entry.abs_path));
    }
    Ok(())
}

#[derive(Debug)]
struct WalkEntry {
    rel_path: String,
    abs_path: PathBuf,
    is_dir: bool,
    is_file: bool,
    file_len: u64,
}

fn should_skip_dir(rel_path: &str, cfg: &RepoIndexConfig) -> bool {
    let name = rel_path.rsplit('/').next().unwrap_or(rel_path);
    if BASELINE_DENIED_DIRS.iter().any(|denied| denied == &name) {
        return true;
    }
    should_ignore_path(rel_path, cfg)
}

fn should_ignore_path(rel_path: &str, cfg: &RepoIndexConfig) -> bool {
    cfg.ignore_globs
        .iter()
        .any(|prefix| prefix_match(rel_path, prefix))
}

fn prefix_match(path: &str, prefix: &str) -> bool {
    if let Some(rest) = path.strip_prefix(prefix) {
        return rest.is_empty() || rest.starts_with('/');
    }
    false
}

fn normalize_digest_hex(value: &str) -> Option<&str> {
    let normalized = value.strip_prefix("sha256:").unwrap_or(value);
    if normalized.len() != 64 {
        return None;
    }
    if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(normalized)
}

#[cfg(test)]
mod tests {
    use super::list_files;
    use crate::repo_index::config::RepoIndexConfig;
    use crate::repo_index::schemas::REPO_INDEX_CONFIG_SCHEMA;
    use std::fs;
    use std::path::Path;

    fn config_with_caps(max_file_bytes: u64, max_total_bytes: u64) -> RepoIndexConfig {
        RepoIndexConfig {
            schema: REPO_INDEX_CONFIG_SCHEMA.to_string(),
            enabled: true,
            max_file_bytes,
            max_total_bytes,
            chunk_mode: "fixed_size".to_string(),
            fixed_chunk_bytes: 4,
            ignore_globs: Vec::new(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn list_files_rejects_symlink_entries() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let workspace = tmp.path().join("workspace");
        fs::create_dir_all(&workspace).expect("create workspace");
        let target = workspace.join("target.txt");
        fs::write(&target, b"target").expect("write target");
        let link = workspace.join("link.txt");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let err = list_files(Path::new(&workspace), &config_with_caps(1024, 1024))
            .expect_err("symlink should fail");
        assert_eq!(err.reason(), "repo_index_symlink_denied");
    }

    #[test]
    fn list_files_rejects_oversize_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let workspace = tmp.path().join("workspace");
        fs::create_dir_all(&workspace).expect("create workspace");
        fs::write(workspace.join("big.txt"), b"0123456789").expect("write file");

        let err = list_files(Path::new(&workspace), &config_with_caps(4, 4096))
            .expect_err("oversize file should fail");
        assert_eq!(err.reason(), "repo_index_file_too_large");
    }
}
