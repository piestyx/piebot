use super::error::RepoIndexError;
use super::schemas::REPO_INDEX_CONFIG_SCHEMA;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_MAX_FILE_BYTES: u64 = 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
const DEFAULT_FIXED_CHUNK_BYTES: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChunkMode {
    WholeFile,
    FixedSize,
}

impl ChunkMode {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "whole_file" => Some(Self::WholeFile),
            "fixed_size" => Some(Self::FixedSize),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::WholeFile => "whole_file",
            Self::FixedSize => "fixed_size",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct RepoIndexConfig {
    pub schema: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u64,
    #[serde(default = "default_max_total_bytes")]
    pub max_total_bytes: u64,
    #[serde(default = "default_chunk_mode")]
    pub chunk_mode: String,
    #[serde(default = "default_fixed_chunk_bytes")]
    pub fixed_chunk_bytes: u64,
    #[serde(default)]
    pub ignore_globs: Vec<String>,
}

impl Default for RepoIndexConfig {
    fn default() -> Self {
        Self {
            schema: REPO_INDEX_CONFIG_SCHEMA.to_string(),
            enabled: false,
            max_file_bytes: default_max_file_bytes(),
            max_total_bytes: default_max_total_bytes(),
            chunk_mode: default_chunk_mode(),
            fixed_chunk_bytes: default_fixed_chunk_bytes(),
            ignore_globs: Vec::new(),
        }
    }
}

impl RepoIndexConfig {
    pub(crate) fn chunk_mode_kind(&self) -> Result<ChunkMode, RepoIndexError> {
        ChunkMode::parse(self.chunk_mode.as_str())
            .ok_or_else(|| RepoIndexError::new("repo_index_config_invalid"))
    }
}

pub(crate) fn load_repo_index_config(
    runtime_root: &Path,
) -> Result<RepoIndexConfig, RepoIndexError> {
    let path = repo_index_config_path(runtime_root);
    if !path.exists() {
        return Ok(RepoIndexConfig::default());
    }
    let bytes = fs::read(&path)
        .map_err(|e| RepoIndexError::with_detail("repo_index_config_read_failed", e.to_string()))?;
    let mut config: RepoIndexConfig = serde_json::from_slice(&bytes)
        .map_err(|e| RepoIndexError::with_detail("repo_index_config_invalid", e.to_string()))?;
    if config.schema != REPO_INDEX_CONFIG_SCHEMA {
        return Err(RepoIndexError::new("repo_index_config_invalid"));
    }
    normalize_repo_index_config(&mut config)?;
    Ok(config)
}

fn repo_index_config_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join("repo_index").join("config.json")
}

fn normalize_repo_index_config(config: &mut RepoIndexConfig) -> Result<(), RepoIndexError> {
    if config.max_file_bytes == 0 || config.max_total_bytes == 0 {
        return Err(RepoIndexError::new("repo_index_config_invalid"));
    }
    let chunk_mode = ChunkMode::parse(config.chunk_mode.trim())
        .ok_or_else(|| RepoIndexError::new("repo_index_config_invalid"))?;
    if chunk_mode == ChunkMode::FixedSize && config.fixed_chunk_bytes == 0 {
        return Err(RepoIndexError::new("repo_index_config_invalid"));
    }
    config.chunk_mode = chunk_mode.as_str().to_string();
    let mut normalized = Vec::with_capacity(config.ignore_globs.len());
    for prefix in &config.ignore_globs {
        normalized.push(normalize_ignore_prefix(prefix)?);
    }
    normalized.sort();
    normalized.dedup();
    config.ignore_globs = normalized;
    Ok(())
}

fn normalize_ignore_prefix(value: &str) -> Result<String, RepoIndexError> {
    let mut input = value.trim().replace('\\', "/");
    while input.starts_with("./") {
        input = input[2..].to_string();
    }
    while input.ends_with('/') {
        input.pop();
    }
    if input.is_empty() || input.starts_with('/') {
        return Err(RepoIndexError::new("repo_index_config_invalid"));
    }
    if input.chars().any(|c| matches!(c, '*' | '?' | '[' | ']')) {
        return Err(RepoIndexError::new("repo_index_config_invalid"));
    }
    let mut segments = Vec::new();
    for segment in input.split('/') {
        let trimmed = segment.trim();
        if trimmed.is_empty() || trimmed == "." {
            continue;
        }
        if trimmed == ".." {
            return Err(RepoIndexError::new("repo_index_config_invalid"));
        }
        segments.push(trimmed.to_string());
    }
    if segments.is_empty() {
        return Err(RepoIndexError::new("repo_index_config_invalid"));
    }
    Ok(segments.join("/"))
}

fn default_max_file_bytes() -> u64 {
    DEFAULT_MAX_FILE_BYTES
}

fn default_max_total_bytes() -> u64 {
    DEFAULT_MAX_TOTAL_BYTES
}

fn default_fixed_chunk_bytes() -> u64 {
    DEFAULT_FIXED_CHUNK_BYTES
}

fn default_chunk_mode() -> String {
    ChunkMode::FixedSize.as_str().to_string()
}
