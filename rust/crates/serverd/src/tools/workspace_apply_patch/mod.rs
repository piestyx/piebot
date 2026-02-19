mod schemas;
mod types;

pub use schemas::{
    WORKSPACE_APPLY_PATCH_REQUEST_SCHEMA, WORKSPACE_APPLY_PATCH_RESULT_SCHEMA,
    WORKSPACE_APPLY_PATCH_TOOL_ID, WORKSPACE_APPROVAL_SCHEMA, WORKSPACE_PATCH_RECEIPT_SCHEMA,
};
pub use types::{
    ApprovalArtifact, ApprovalHashRequest, JsonPatchOp, LinePatchOp, WorkspaceApplyPatchMode,
    WorkspaceApplyPatchRequest, WorkspaceApplyPatchResult, WorkspacePatchAction,
    WorkspacePatchReceipt,
};

use crate::policy::workspace::{
    load_workspace_policy, WorkspaceContext, WORKSPACE_REASON_CANONICALIZE_FAILED,
    WORKSPACE_REASON_DISABLED, WORKSPACE_REASON_PATH_ESCAPE, WORKSPACE_REASON_PATH_NONEXISTENT,
    WORKSPACE_REASON_PATH_TRAVERSAL, WORKSPACE_REASON_ROOT_INVALID,
    WORKSPACE_REASON_SYMLINK_ESCAPE,
};
use crate::runtime::artifacts::{artifact_filename, is_sha256_ref};
use crate::tools::ToolError;
use pie_common::{canonical_json_bytes, sha256_bytes};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

pub const WORKSPACE_APPLY_PATCH_NOT_APPROVED: &str = "workspace_apply_patch_not_approved";
pub const WORKSPACE_APPLY_PATCH_PRECONDITION_MISMATCH: &str =
    "workspace_apply_patch_precondition_mismatch";
pub const WORKSPACE_APPLY_PATCH_INPUT_INVALID: &str = "workspace_apply_patch_input_invalid";
pub const WORKSPACE_APPLY_PATCH_TARGET_INVALID: &str = "workspace_apply_patch_target_invalid";
pub const WORKSPACE_APPLY_PATCH_CONTENT_INVALID: &str = "workspace_apply_patch_content_invalid";

#[derive(Debug, Clone)]
pub struct WorkspaceApplyPatchExecution {
    pub request_ref: String,
    pub request_hash_hex: String,
    pub result: WorkspaceApplyPatchResult,
}

#[derive(Debug, Clone)]
struct ResolvedWorkspaceTarget {
    abs_path: PathBuf,
    existed_before: bool,
}

#[doc(hidden)]
pub fn execute_request_with_workspace_policy(
    runtime_root: &Path,
    run_id: &str,
    input_ref: &str,
    input_value: &serde_json::Value,
) -> Result<WorkspaceApplyPatchExecution, ToolError> {
    let workspace_ctx =
        load_workspace_policy(runtime_root, run_id).map_err(|e| ToolError::new(e.reason()))?;
    execute(runtime_root, &workspace_ctx, input_ref, input_value)
}

pub fn approval_scope_request_hash_hex(
    request: &WorkspaceApplyPatchRequest,
) -> Result<String, ToolError> {
    let hash_input = ApprovalHashRequest {
        schema: request.schema.clone(),
        target_path: request.target_path.clone(),
        mode: request.mode.clone(),
        allow_create: request.allow_create,
        allow_create_parents: request.allow_create_parents,
        precondition_sha256_hex: request.precondition_sha256_hex.clone(),
        patch: request.patch.clone(),
        line_patch: request.line_patch.clone(),
        content: request.content.clone(),
    };
    let value = serde_json::to_value(&hash_input)
        .map_err(|_| ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID))?;
    let bytes = canonical_json_bytes(&value)
        .map_err(|_| ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID))?;
    Ok(sha256_hex(bytes.as_slice()))
}

pub(crate) fn execute(
    runtime_root: &Path,
    workspace_ctx: &WorkspaceContext,
    input_ref: &str,
    input_value: &serde_json::Value,
) -> Result<WorkspaceApplyPatchExecution, ToolError> {
    panic_if_workspace_patch_called();
    let mut request: WorkspaceApplyPatchRequest = serde_json::from_value(input_value.clone())
        .map_err(|_| ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID))?;
    if request.schema != WORKSPACE_APPLY_PATCH_REQUEST_SCHEMA {
        return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID));
    }
    request.target_path = normalize_target_path(request.target_path.as_str())?;
    normalize_mode_fields(&request)?;
    if let Some(precondition) = request.precondition_sha256_hex.as_ref() {
        validate_hex_64(precondition)?;
    }
    let request_hash_hex = approval_scope_request_hash_hex(&request)?;
    verify_approval(runtime_root, &request, request_hash_hex.as_str())?;

    let resolved = resolve_workspace_target_path(
        workspace_ctx,
        request.target_path.as_str(),
        request.allow_create,
        request.allow_create_parents,
    )?;
    let before_bytes = if resolved.existed_before {
        let metadata = fs::symlink_metadata(&resolved.abs_path)
            .map_err(|e| ToolError::with_source(WORKSPACE_APPLY_PATCH_TARGET_INVALID, e))?;
        if metadata.file_type().is_symlink() {
            return Err(ToolError::new(WORKSPACE_REASON_SYMLINK_ESCAPE));
        }
        if !metadata.is_file() {
            return Err(ToolError::new(WORKSPACE_APPLY_PATCH_TARGET_INVALID));
        }
        fs::read(&resolved.abs_path)
            .map_err(|e| ToolError::with_source(WORKSPACE_APPLY_PATCH_TARGET_INVALID, e))?
    } else {
        Vec::new()
    };
    let before_sha256_hex = sha256_hex(before_bytes.as_slice());
    if let Some(expected) = request.precondition_sha256_hex.as_ref() {
        let normalized_expected = normalize_hex_64(expected)?;
        if normalized_expected != before_sha256_hex {
            return Err(ToolError::new(WORKSPACE_APPLY_PATCH_PRECONDITION_MISMATCH));
        }
    }

    let (after_bytes, applied_patch_sha256_hex, patch_ops_empty) = match request.mode {
        WorkspaceApplyPatchMode::JsonPatch => {
            let patch_ops = request
                .patch
                .as_ref()
                .ok_or_else(|| ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID))?;
            let after = apply_json_patch(before_bytes.as_slice(), patch_ops)?;
            let patch_value = serde_json::to_value(patch_ops)
                .map_err(|_| ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID))?;
            let patch_bytes = canonical_json_bytes(&patch_value)
                .map_err(|_| ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID))?;
            (
                after,
                sha256_hex(patch_bytes.as_slice()),
                patch_ops.is_empty(),
            )
        }
        WorkspaceApplyPatchMode::FullReplace => {
            let content = request
                .content
                .as_ref()
                .ok_or_else(|| ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID))?;
            let content_bytes = content.as_bytes().to_vec();
            (
                content_bytes.clone(),
                sha256_hex(content_bytes.as_slice()),
                false,
            )
        }
        WorkspaceApplyPatchMode::LinePatch => {
            let patch_ops = request
                .line_patch
                .as_ref()
                .ok_or_else(|| ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID))?;
            let after = apply_line_patch(before_bytes.as_slice(), patch_ops)?;
            let patch_value = serde_json::to_value(patch_ops)
                .map_err(|_| ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID))?;
            let patch_bytes = canonical_json_bytes(&patch_value)
                .map_err(|_| ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID))?;
            (
                after,
                sha256_hex(patch_bytes.as_slice()),
                patch_ops.is_empty(),
            )
        }
    };

    let action = if patch_ops_empty && after_bytes == before_bytes && resolved.existed_before {
        WorkspacePatchAction::Noop
    } else {
        WorkspacePatchAction::Applied
    };
    let created = !resolved.existed_before && action == WorkspacePatchAction::Applied;
    let should_write =
        action == WorkspacePatchAction::Applied && (after_bytes != before_bytes || created);
    let mut bytes_written = 0u64;
    if should_write {
        write_atomic(resolved.abs_path.as_path(), after_bytes.as_slice())?;
        bytes_written = after_bytes.len() as u64;
    }

    let after_sha256_hex = sha256_hex(after_bytes.as_slice());
    let result = WorkspaceApplyPatchResult {
        schema: WORKSPACE_APPLY_PATCH_RESULT_SCHEMA.to_string(),
        target_path: request.target_path.clone(),
        action,
        created,
        before_sha256_hex,
        after_sha256_hex,
        bytes_written,
        applied_patch_sha256_hex,
        precondition_checked: request.precondition_sha256_hex.is_some(),
        approval_ref: request.approval_ref.clone(),
    };
    Ok(WorkspaceApplyPatchExecution {
        request_ref: input_ref.to_string(),
        request_hash_hex,
        result,
    })
}

pub(crate) fn build_receipt_value(
    execution: &WorkspaceApplyPatchExecution,
    result_ref: &str,
) -> Result<serde_json::Value, ToolError> {
    let receipt = WorkspacePatchReceipt {
        schema: WORKSPACE_PATCH_RECEIPT_SCHEMA.to_string(),
        request_ref: execution.request_ref.clone(),
        result_ref: result_ref.to_string(),
        request_hash_hex: execution.request_hash_hex.clone(),
        target_path: execution.result.target_path.clone(),
        before_sha256_hex: execution.result.before_sha256_hex.clone(),
        after_sha256_hex: execution.result.after_sha256_hex.clone(),
        approval_ref: execution.result.approval_ref.clone(),
    };
    serde_json::to_value(&receipt).map_err(|_| ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID))
}

fn normalize_mode_fields(request: &WorkspaceApplyPatchRequest) -> Result<(), ToolError> {
    match request.mode {
        WorkspaceApplyPatchMode::JsonPatch => {
            if request.patch.is_none() || request.content.is_some() || request.line_patch.is_some()
            {
                return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID));
            }
        }
        WorkspaceApplyPatchMode::FullReplace => {
            if request.content.is_none() || request.patch.is_some() || request.line_patch.is_some()
            {
                return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID));
            }
        }
        WorkspaceApplyPatchMode::LinePatch => {
            if request.line_patch.is_none() || request.patch.is_some() || request.content.is_some()
            {
                return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID));
            }
        }
    }
    Ok(())
}

fn normalize_target_path(path: &str) -> Result<String, ToolError> {
    if path.trim().is_empty() {
        return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID));
    }
    if path.starts_with('/') {
        return Err(ToolError::new(WORKSPACE_REASON_PATH_ESCAPE));
    }
    if path.contains('\\') || path.contains(':') {
        return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID));
    }
    let mut parts = Vec::new();
    for raw in path.split('/') {
        let part = raw.trim();
        if part.is_empty() || part == "." {
            return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID));
        }
        if part == ".." {
            return Err(ToolError::new(WORKSPACE_REASON_PATH_TRAVERSAL));
        }
        parts.push(part.to_string());
    }
    if parts.is_empty() {
        return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID));
    }
    Ok(parts.join("/"))
}

fn verify_approval(
    runtime_root: &Path,
    request: &WorkspaceApplyPatchRequest,
    expected_request_hash_hex: &str,
) -> Result<(), ToolError> {
    if approval_bypass_enabled() {
        return Ok(());
    }
    let approval_ref = request
        .approval_ref
        .as_ref()
        .ok_or_else(|| ToolError::new(WORKSPACE_APPLY_PATCH_NOT_APPROVED))?;
    if !is_sha256_ref(approval_ref) {
        return Err(ToolError::new(WORKSPACE_APPLY_PATCH_NOT_APPROVED));
    }
    let path = runtime_root
        .join("artifacts")
        .join("approvals")
        .join(artifact_filename(approval_ref));
    let bytes = fs::read(path).map_err(|_| ToolError::new(WORKSPACE_APPLY_PATCH_NOT_APPROVED))?;
    let approval_value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| ToolError::new(WORKSPACE_APPLY_PATCH_NOT_APPROVED))?;
    let approval: ApprovalArtifact = serde_json::from_value(approval_value.clone())
        .map_err(|_| ToolError::new(WORKSPACE_APPLY_PATCH_NOT_APPROVED))?;
    if approval.schema != WORKSPACE_APPROVAL_SCHEMA
        || !approval.approved
        || approval.scope.kind != "tool_call"
        || approval.scope.tool_id != WORKSPACE_APPLY_PATCH_TOOL_ID
        || normalize_hex_64(approval.scope.request_hash_hex.as_str())? != expected_request_hash_hex
    {
        return Err(ToolError::new(WORKSPACE_APPLY_PATCH_NOT_APPROVED));
    }
    let canonical_bytes = canonical_json_bytes(&approval_value)
        .map_err(|_| ToolError::new(WORKSPACE_APPLY_PATCH_NOT_APPROVED))?;
    let computed_ref = sha256_bytes(&canonical_bytes);
    if computed_ref != *approval_ref {
        return Err(ToolError::new(WORKSPACE_APPLY_PATCH_NOT_APPROVED));
    }
    Ok(())
}

fn approval_bypass_enabled() -> bool {
    std::env::var("WORKSPACE_PATCH_APPROVAL_BYPASS")
        .map(|value| value == "1")
        .unwrap_or(false)
}

fn resolve_workspace_target_path(
    ctx: &WorkspaceContext,
    target_path: &str,
    allow_create: bool,
    allow_create_parents: bool,
) -> Result<ResolvedWorkspaceTarget, ToolError> {
    if !ctx.policy.enabled {
        return Err(ToolError::new(WORKSPACE_REASON_DISABLED));
    }
    let root = ensure_workspace_root(ctx)?;
    let rel_path = target_rel_path(target_path)?;
    let file_name = rel_path
        .file_name()
        .ok_or_else(|| ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID))?;
    let parent_rel = rel_path.parent().unwrap_or_else(|| Path::new(""));
    let canonical_parent =
        resolve_or_create_parent(root.as_path(), parent_rel, allow_create_parents)?;
    let abs_path = canonical_parent.join(file_name);
    if abs_path.exists() {
        let metadata = fs::symlink_metadata(&abs_path)
            .map_err(|e| ToolError::with_source(WORKSPACE_REASON_CANONICALIZE_FAILED, e))?;
        if metadata.file_type().is_symlink() {
            return Err(ToolError::new(WORKSPACE_REASON_SYMLINK_ESCAPE));
        }
        if !metadata.is_file() {
            return Err(ToolError::new(WORKSPACE_APPLY_PATCH_TARGET_INVALID));
        }
        let canonical_abs = fs::canonicalize(&abs_path)
            .map_err(|e| ToolError::with_source(WORKSPACE_REASON_CANONICALIZE_FAILED, e))?;
        if !canonical_abs.starts_with(&root) {
            return Err(ToolError::new(WORKSPACE_REASON_SYMLINK_ESCAPE));
        }
        Ok(ResolvedWorkspaceTarget {
            abs_path,
            existed_before: true,
        })
    } else {
        if !allow_create {
            return Err(ToolError::new(WORKSPACE_REASON_PATH_NONEXISTENT));
        }
        Ok(ResolvedWorkspaceTarget {
            abs_path,
            existed_before: false,
        })
    }
}

fn resolve_or_create_parent(
    root: &Path,
    parent_rel: &Path,
    allow_create_parents: bool,
) -> Result<PathBuf, ToolError> {
    if parent_rel.as_os_str().is_empty() {
        return Ok(root.to_path_buf());
    }
    let mut current = root.to_path_buf();
    for component in parent_rel.components() {
        match component {
            Component::Normal(name) => current.push(name),
            Component::CurDir => return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID)),
            Component::ParentDir => return Err(ToolError::new(WORKSPACE_REASON_PATH_TRAVERSAL)),
            Component::Prefix(_) | Component::RootDir => {
                return Err(ToolError::new(WORKSPACE_REASON_PATH_ESCAPE))
            }
        }
        if current.exists() {
            let metadata = fs::symlink_metadata(&current)
                .map_err(|e| ToolError::with_source(WORKSPACE_REASON_CANONICALIZE_FAILED, e))?;
            if metadata.file_type().is_symlink() {
                return Err(ToolError::new(WORKSPACE_REASON_SYMLINK_ESCAPE));
            }
            if !metadata.is_dir() {
                return Err(ToolError::new(WORKSPACE_APPLY_PATCH_TARGET_INVALID));
            }
        } else {
            if !allow_create_parents {
                return Err(ToolError::new(WORKSPACE_REASON_PATH_NONEXISTENT));
            }
            fs::create_dir(&current)
                .map_err(|e| ToolError::with_source(WORKSPACE_APPLY_PATCH_TARGET_INVALID, e))?;
            let metadata = fs::symlink_metadata(&current)
                .map_err(|e| ToolError::with_source(WORKSPACE_REASON_CANONICALIZE_FAILED, e))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(ToolError::new(WORKSPACE_REASON_SYMLINK_ESCAPE));
            }
        }
    }
    let canonical_parent = fs::canonicalize(&current)
        .map_err(|e| ToolError::with_source(WORKSPACE_REASON_CANONICALIZE_FAILED, e))?;
    if !canonical_parent.starts_with(root) {
        return Err(ToolError::new(WORKSPACE_REASON_SYMLINK_ESCAPE));
    }
    Ok(canonical_parent)
}

fn ensure_workspace_root(ctx: &WorkspaceContext) -> Result<PathBuf, ToolError> {
    if ctx.run_workspace_root.exists() {
        let meta = fs::symlink_metadata(&ctx.run_workspace_root)
            .map_err(|e| ToolError::with_source(WORKSPACE_REASON_ROOT_INVALID, e))?;
        if meta.file_type().is_symlink() {
            return Err(ToolError::new(WORKSPACE_REASON_SYMLINK_ESCAPE));
        }
    }
    fs::create_dir_all(&ctx.run_workspace_root)
        .map_err(|e| ToolError::with_source(WORKSPACE_REASON_ROOT_INVALID, e))?;
    fs::canonicalize(&ctx.run_workspace_root)
        .map_err(|e| ToolError::with_source(WORKSPACE_REASON_CANONICALIZE_FAILED, e))
}

fn target_rel_path(path: &str) -> Result<PathBuf, ToolError> {
    let mut out = PathBuf::new();
    for segment in path.split('/') {
        out.push(segment);
    }
    if out.is_absolute() {
        return Err(ToolError::new(WORKSPACE_REASON_PATH_ESCAPE));
    }
    Ok(out)
}

fn apply_json_patch(before_bytes: &[u8], patch_ops: &[JsonPatchOp]) -> Result<Vec<u8>, ToolError> {
    let mut content = String::from_utf8(before_bytes.to_vec())
        .map_err(|_| ToolError::new(WORKSPACE_APPLY_PATCH_CONTENT_INVALID))?;
    for op in patch_ops {
        match op {
            JsonPatchOp::Insert { at, text } => {
                let at = as_index(*at)?;
                if at > content.len() || !content.is_char_boundary(at) {
                    return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID));
                }
                content.insert_str(at, text);
            }
            JsonPatchOp::Delete { start, end } => {
                replace_range(&mut content, *start, *end, "")?;
            }
            JsonPatchOp::Replace { start, end, text } => {
                replace_range(&mut content, *start, *end, text)?;
            }
        }
    }
    Ok(content.into_bytes())
}

fn apply_line_patch(before_bytes: &[u8], patch_ops: &[LinePatchOp]) -> Result<Vec<u8>, ToolError> {
    let before_text = String::from_utf8(before_bytes.to_vec())
        .map_err(|_| ToolError::new(WORKSPACE_APPLY_PATCH_CONTENT_INVALID))?;
    let normalized = normalize_line_endings(before_text.as_str());
    let mut lines = split_lines(normalized.as_str());
    for op in patch_ops {
        match op {
            LinePatchOp::InsertLines {
                at_line,
                lines: insert,
            } => {
                let at = as_line_index(*at_line, lines.len())?;
                let insert_lines = validate_patch_lines(insert)?;
                lines.splice(at..at, insert_lines.into_iter());
            }
            LinePatchOp::DeleteLines {
                start_line,
                end_line_exclusive,
            } => {
                let start = as_line_index(*start_line, lines.len())?;
                let end = as_line_index(*end_line_exclusive, lines.len())?;
                if start > end {
                    return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID));
                }
                lines.drain(start..end);
            }
            LinePatchOp::ReplaceLines {
                start_line,
                end_line_exclusive,
                lines: replace,
            } => {
                let start = as_line_index(*start_line, lines.len())?;
                let end = as_line_index(*end_line_exclusive, lines.len())?;
                if start > end {
                    return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID));
                }
                let replace_lines = validate_patch_lines(replace)?;
                lines.splice(start..end, replace_lines.into_iter());
            }
        }
    }
    if lines.is_empty() {
        Ok(Vec::new())
    } else {
        let mut joined = lines.join("\n");
        joined.push('\n');
        Ok(joined.into_bytes())
    }
}

fn validate_patch_lines(lines: &[String]) -> Result<Vec<String>, ToolError> {
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        if line.contains('\n') || line.contains('\r') {
            return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID));
        }
        out.push(line.clone());
    }
    Ok(out)
}

fn split_lines(text: &str) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<String> = text.split('\n').map(|line| line.to_string()).collect();
    if matches!(lines.last(), Some(last) if last.is_empty()) {
        lines.pop();
    }
    lines
}

fn normalize_line_endings(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

fn as_line_index(value: u64, max: usize) -> Result<usize, ToolError> {
    let index = as_index(value)?;
    if index > max {
        return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID));
    }
    Ok(index)
}

fn replace_range(
    content: &mut String,
    start_u64: u64,
    end_u64: u64,
    replacement: &str,
) -> Result<(), ToolError> {
    let start = as_index(start_u64)?;
    let end = as_index(end_u64)?;
    if start > end || end > content.len() {
        return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID));
    }
    if !content.is_char_boundary(start) || !content.is_char_boundary(end) {
        return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID));
    }
    content.replace_range(start..end, replacement);
    Ok(())
}

fn as_index(value: u64) -> Result<usize, ToolError> {
    usize::try_from(value).map_err(|_| ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ToolError> {
    let parent = path
        .parent()
        .ok_or_else(|| ToolError::new(WORKSPACE_APPLY_PATCH_TARGET_INVALID))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| ToolError::new(WORKSPACE_APPLY_PATCH_TARGET_INVALID))?
        .to_string_lossy()
        .to_string();
    let tmp_path = parent.join(format!(".{}.workspace_patch.tmp", file_name));
    let mut file = fs::File::create(&tmp_path)
        .map_err(|e| ToolError::with_source(WORKSPACE_APPLY_PATCH_TARGET_INVALID, e))?;
    file.write_all(bytes)
        .map_err(|e| ToolError::with_source(WORKSPACE_APPLY_PATCH_TARGET_INVALID, e))?;
    file.sync_all()
        .map_err(|e| ToolError::with_source(WORKSPACE_APPLY_PATCH_TARGET_INVALID, e))?;
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(ToolError::with_source(
            WORKSPACE_APPLY_PATCH_TARGET_INVALID,
            e,
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let hash_ref = sha256_bytes(bytes);
    hash_ref
        .strip_prefix("sha256:")
        .unwrap_or(hash_ref.as_str())
        .to_ascii_lowercase()
}

fn validate_hex_64(value: &str) -> Result<(), ToolError> {
    normalize_hex_64(value).map(|_| ())
}

fn normalize_hex_64(value: &str) -> Result<String, ToolError> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ToolError::new(WORKSPACE_APPLY_PATCH_INPUT_INVALID));
    }
    Ok(normalized)
}

fn panic_if_workspace_patch_called() {
    let should_panic = std::env::var("PANIC_IF_WORKSPACE_APPLY_PATCH_CALLED")
        .map(|value| value == "1")
        .unwrap_or(false);
    assert!(!should_panic, "workspace apply_patch called unexpectedly");
}
