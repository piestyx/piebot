use pie_common::{canonical_json_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const WORKSPACE_POLICY_SCHEMA: &str = "serverd.workspace_policy.v1";

pub const WORKSPACE_REASON_DISABLED: &str = "workspace_disabled";
pub const WORKSPACE_REASON_ROOT_INVALID: &str = "workspace_root_invalid";
pub const WORKSPACE_REASON_REPO_ROOT_DISALLOWED: &str = "workspace_repo_root_disallowed";
pub const WORKSPACE_REASON_PATH_TRAVERSAL: &str = "workspace_path_traversal";
pub const WORKSPACE_REASON_PATH_ESCAPE: &str = "workspace_path_escape";
pub const WORKSPACE_REASON_SYMLINK_ESCAPE: &str = "workspace_symlink_escape";
pub const WORKSPACE_REASON_PATH_NONEXISTENT: &str = "workspace_path_nonexistent";
pub const WORKSPACE_REASON_CANONICALIZE_FAILED: &str = "workspace_canonicalize_failed";
pub const WORKSPACE_REASON_POLICY_INVALID: &str = "workspace_policy_invalid";
pub const WORKSPACE_REASON_POLICY_READ_FAILED: &str = "workspace_policy_read_failed";

#[derive(Debug)]
pub struct WorkspaceError {
    reason: &'static str,
    #[allow(dead_code)]
    detail: Option<String>,
}

impl WorkspaceError {
    pub fn new(reason: &'static str) -> Self {
        Self {
            reason,
            detail: None,
        }
    }

    pub fn with_detail(reason: &'static str, detail: String) -> Self {
        Self {
            reason,
            detail: Some(detail),
        }
    }

    pub fn reason(&self) -> &'static str {
        self.reason
    }
}

impl std::fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for WorkspaceError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct WorkspacePolicy {
    pub schema: String,
    pub enabled: bool,
    pub workspace_root: String,
    pub allow_repo_root: bool,
    pub per_run_dir: bool,
}

impl Default for WorkspacePolicy {
    fn default() -> Self {
        Self {
            schema: WORKSPACE_POLICY_SCHEMA.to_string(),
            enabled: true,
            workspace_root: "workspace".to_string(),
            allow_repo_root: false,
            per_run_dir: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkspaceContext {
    pub policy: WorkspacePolicy,
    pub policy_hash: String,
    #[allow(dead_code)]
    pub workspace_root: PathBuf,
    pub run_workspace_root: PathBuf,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CanonicalWorkspacePath {
    pub abs_path: PathBuf,
    pub rel_path: String,
}

pub fn load_workspace_policy(
    runtime_root: &Path,
    run_id: &str,
) -> Result<WorkspaceContext, WorkspaceError> {
    let policy = read_policy(runtime_root)?;
    if policy.schema != WORKSPACE_POLICY_SCHEMA {
        return Err(WorkspaceError::new(WORKSPACE_REASON_POLICY_INVALID));
    }
    let policy_hash = policy_hash(&policy)?;
    let workspace_root = resolve_workspace_root(runtime_root, &policy)?;
    let run_workspace_root = derive_run_workspace_root(&workspace_root, run_id, policy.per_run_dir);
    Ok(WorkspaceContext {
        policy,
        policy_hash,
        workspace_root,
        run_workspace_root,
    })
}

pub fn enforce_workspace_path(
    ctx: &WorkspaceContext,
    requested: &Path,
) -> Result<CanonicalWorkspacePath, WorkspaceError> {
    if !ctx.policy.enabled {
        return Err(WorkspaceError::new(WORKSPACE_REASON_DISABLED));
    }
    let normalized_rel = normalize_relative_path(requested)?;
    let root = ensure_root_exists(&ctx.run_workspace_root)?;
    let parent = parent_path(&root, requested)?;
    if !parent.exists() {
        return Err(WorkspaceError::new(WORKSPACE_REASON_PATH_NONEXISTENT));
    }
    let canonical_parent = fs::canonicalize(&parent).map_err(|e| {
        WorkspaceError::with_detail(WORKSPACE_REASON_CANONICALIZE_FAILED, e.to_string())
    })?;
    if !canonical_parent.starts_with(&root) {
        return Err(WorkspaceError::new(WORKSPACE_REASON_SYMLINK_ESCAPE));
    }
    let abs_path = match requested.file_name() {
        Some(name) => canonical_parent.join(name),
        None => canonical_parent,
    };
    if abs_path.exists() {
        let canonical_abs = fs::canonicalize(&abs_path).map_err(|e| {
            WorkspaceError::with_detail(WORKSPACE_REASON_CANONICALIZE_FAILED, e.to_string())
        })?;
        if !canonical_abs.starts_with(&root) {
            return Err(WorkspaceError::new(WORKSPACE_REASON_SYMLINK_ESCAPE));
        }
    }
    Ok(CanonicalWorkspacePath {
        abs_path,
        rel_path: normalized_rel,
    })
}

fn read_policy(runtime_root: &Path) -> Result<WorkspacePolicy, WorkspaceError> {
    let path = policy_path(runtime_root);
    if !path.exists() {
        return Ok(WorkspacePolicy::default());
    }
    let bytes = fs::read(&path).map_err(|e| {
        WorkspaceError::with_detail(WORKSPACE_REASON_POLICY_READ_FAILED, e.to_string())
    })?;
    let policy: WorkspacePolicy = serde_json::from_slice(&bytes)
        .map_err(|_| WorkspaceError::new(WORKSPACE_REASON_POLICY_INVALID))?;
    Ok(policy)
}

fn policy_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join("workspace").join("policy.json")
}

fn policy_hash(policy: &WorkspacePolicy) -> Result<String, WorkspaceError> {
    let value = serde_json::to_value(policy)
        .map_err(|_| WorkspaceError::new(WORKSPACE_REASON_POLICY_INVALID))?;
    let bytes = canonical_json_bytes(&value)
        .map_err(|_| WorkspaceError::new(WORKSPACE_REASON_POLICY_INVALID))?;
    Ok(sha256_bytes(&bytes))
}

fn resolve_workspace_root(
    runtime_root: &Path,
    policy: &WorkspacePolicy,
) -> Result<PathBuf, WorkspaceError> {
    if policy.workspace_root.trim().is_empty() {
        return Err(WorkspaceError::new(WORKSPACE_REASON_ROOT_INVALID));
    }
    let root_path = if Path::new(&policy.workspace_root).is_absolute() {
        PathBuf::from(&policy.workspace_root)
    } else {
        PathBuf::from(runtime_root).join(&policy.workspace_root)
    };
    if root_path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(WorkspaceError::new(WORKSPACE_REASON_ROOT_INVALID));
    }
    if !policy.allow_repo_root {
        let runtime_root = fs::canonicalize(runtime_root).map_err(|e| {
            WorkspaceError::with_detail(WORKSPACE_REASON_ROOT_INVALID, e.to_string())
        })?;
        if root_path == runtime_root {
            return Err(WorkspaceError::new(WORKSPACE_REASON_REPO_ROOT_DISALLOWED));
        }
        if let Ok(root_canon) = fs::canonicalize(&root_path) {
            if root_canon == runtime_root {
                return Err(WorkspaceError::new(WORKSPACE_REASON_REPO_ROOT_DISALLOWED));
            }
        }
    }
    Ok(root_path)
}

fn derive_run_workspace_root(root: &Path, run_id: &str, per_run_dir: bool) -> PathBuf {
    if !per_run_dir {
        return root.to_path_buf();
    }
    let trimmed = run_id.strip_prefix("sha256:").unwrap_or(run_id);
    root.join("runs").join(trimmed)
}

fn ensure_root_exists(path: &Path) -> Result<PathBuf, WorkspaceError> {
    if let Err(e) = fs::create_dir_all(path) {
        return Err(WorkspaceError::with_detail(
            WORKSPACE_REASON_ROOT_INVALID,
            e.to_string(),
        ));
    }
    fs::canonicalize(path).map_err(|e| {
        WorkspaceError::with_detail(WORKSPACE_REASON_CANONICALIZE_FAILED, e.to_string())
    })
}

fn normalize_relative_path(path: &Path) -> Result<String, WorkspaceError> {
    if path.is_absolute() {
        return Err(WorkspaceError::new(WORKSPACE_REASON_PATH_ESCAPE));
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                return Err(WorkspaceError::new(WORKSPACE_REASON_PATH_ESCAPE));
            }
            Component::ParentDir => {
                return Err(WorkspaceError::new(WORKSPACE_REASON_PATH_TRAVERSAL));
            }
            Component::CurDir => {}
            Component::Normal(name) => parts.push(name.to_string_lossy().to_string()),
        }
    }
    if parts.is_empty() {
        return Ok(".".to_string());
    }
    Ok(parts.join("/"))
}

fn parent_path(root: &Path, requested: &Path) -> Result<PathBuf, WorkspaceError> {
    if requested.is_absolute() {
        return Err(WorkspaceError::new(WORKSPACE_REASON_PATH_ESCAPE));
    }
    let mut components = requested.components().peekable();
    let mut parent = root.to_path_buf();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            break;
        }
        match component {
            Component::Normal(name) => parent.push(name),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(WorkspaceError::new(WORKSPACE_REASON_PATH_TRAVERSAL));
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(WorkspaceError::new(WORKSPACE_REASON_PATH_ESCAPE));
            }
        }
    }
    Ok(parent)
}
