# Workspace Hygiene

## What you learn

- How workspace root and per-run roots are derived.
- How filesystem tool paths are normalized and restricted.
- Which workspace-specific reasons are emitted on violation.
- Which audit events record policy load and violations.
- Which config knobs alter runtime path behavior.
- Which tests prove traversal/escape protections.

## Purpose

Constrain filesystem-capable tool operations to an approved runtime-scoped workspace subtree.

## Threat model / what it prevents

- Absolute path escape.
- `..` traversal escape.
- Symlink-based escape outside workspace root.
- Repo-root writes when explicitly disallowed.

## Inputs and outputs (artifact refs)

No standalone artifact schema is written for workspace checks; this subsystem controls gate decisions for filesystem tool execution.

Inputs:
   - `workspace/policy.json`
   - requested tool path from `tool_input`
   - run id (for per-run directory derivation)

Outputs:
   - allow path (canonical path + relative path) or fail reason
   - `workspace_violation` audit event on deny

## Audit events emitted

- `workspace_policy_loaded`
- `workspace_violation`

## Fail-closed reasons

- `workspace_disabled`
- `workspace_root_invalid`
- `workspace_repo_root_disallowed`
- `workspace_path_traversal`
- `workspace_path_escape`
- `workspace_symlink_escape`
- `workspace_path_nonexistent`
- `workspace_canonicalize_failed`
- `workspace_policy_invalid`
- `workspace_policy_read_failed`

## Determinism guarantees

- Relative path normalization uses component-wise deterministic checks.
- Per-run root derivation is deterministic from `run_id` when `per_run_dir=true`.
- Policy hash is canonicalized (`WorkspaceContext.policy_hash`).

## Config file(s) + schema(s)

| File | Schema |
|---|---|
| `runtime/workspace/policy.json` | `serverd.workspace_policy.v1` |

Fields: `enabled`, `workspace_root`, `allow_repo_root`, `per_run_dir`.

## Core enforcement points (functions + file paths)

- `policy/workspace.rs::load_workspace_policy`
- `policy/workspace.rs::enforce_workspace_path`
- `tools/execute.rs` (filesystem tool check before builtin execution)
- `runner/mod.rs` (policy load and event emit)

## Tests proving it

- `tests/stage12_workspace.rs`
- `tests/stage_gate_7_12.rs`

## Common failure scenarios + how to diagnose

1. **`workspace_root_invalid`**
   - Invalid root path, cannot create/canonicalize root, or invalid policy.
2. **`workspace_path_traversal` / `workspace_path_escape`**
   - Input path contains `..` or absolute root components.
3. **`workspace_symlink_escape`**
   - Parent/path canonicalization lands outside run workspace root.