# Tools Policy and Execution

## What you learn

- How tool calls move from provider output to executed side-effect.
- Where policy gating, approval gating, and arming gating are enforced.
- How skill constraints and mode constraints tighten tool permissions.
- Which artifacts and audit events are emitted for each decision.
- Which fail-closed reasons are returned by each gate.
- Which tests prove deterministic and deny-by-default behavior.

## Purpose

Execute tool calls safely and deterministically behind policy gates. Tool calls are proposals until `execute_tool(...)` allows and executes them.

## Threat model / what it prevents

- Unauthorized tool execution (`tools_disabled`, `tool_not_allowed`).
- Unarmed high-risk execution (`tool_requires_arming`).
- Missing approval execution (`tool_approval_required` / invalid approvals).
- Skill-unauthorized calls (`skill_tool_not_allowed`, `skill_tool_constraint_failed`).
- Workspace path escape for filesystem tools (`workspace_*` reasons).

## Inputs and outputs (artifact refs)

| Direction | Artifact | Source/Target |
|---|---|---|
| In | `tool_call` inside provider output | `artifacts/outputs/<hash>.json` |
| In | tool input | `artifacts/tool_inputs/<hash>.json` |
| Out | canonical tool call | `artifacts/tool_calls/<hash>.json` |
| Out | tool output envelope | `artifacts/tool_outputs/<hash>.json` |
| Out | approval request | `artifacts/approvals/<hash>.json` |
| Out | approval decision file | `approvals/<hash>.approved.json` |

## Audit events emitted

- `tool_execution_denied`
- `tool_approval_required`
- `tool_selected`
- `tool_call_written`
- `tool_executed`
- `tool_output_written`
- `workspace_violation` (filesystem tool path rejection)

Event enum: `serverd/src/audit.rs`.

## Fail-closed reasons

- Policy/load/registry: `tools_disabled`, `tool_not_allowed`, `tool_requires_arming`, `tool_policy_invalid`, `tool_spec_invalid`, `tool_spec_missing`
- Approval: `tool_approval_required`, `tool_approval_invalid`, `tool_approval_request_failed`
- Call/input/output: `tool_call_invalid`, `tool_input_invalid`, `tool_input_read_failed`, `tool_output_invalid`, `tool_not_implemented`
- Skill binding: `skill_tool_not_allowed`, `skill_tool_constraint_failed`, `skill_tool_input_invalid`, `skill_tool_input_unreadable`
- Workspace checks (if filesystem tool): `workspace_path_traversal`, `workspace_path_escape`, `workspace_symlink_escape`, etc.

## Determinism guarantees

- Tool registry load order is filename-sorted (`ToolRegistry::load_tools`).
- Registry hash is canonical (`as_registry_value` + canonical hash).
- Tool outputs are canonical JSON artifacts by content hash.
- Choke-point invariant: only one runtime callsite executes tools (`route/provider_phase.rs`).

## Config file(s) + schema(s)

| File | Schema |
|---|---|
| `runtime/tools/*.json` (tool specs) | `serverd.tool_spec.v1` |
| `runtime/tools/policy.json` | `serverd.tool_policy.v1` |
| `runtime/artifacts/approvals/*.json` | `serverd.tool_approval_request.v1` |
| `runtime/approvals/*.approved.json` | `serverd.tool_approval.v1` |
| Tool call artifact | `serverd.tool_call.v1` |
| Tool output artifact | `serverd.tool_output.v1` |

## Core enforcement points (functions + file paths)

- `tools/policy.rs::ToolPolicy::check`
- `tools/execute.rs::execute_tool`
- `skills.rs::enforce_tool_call`
- `route/provider_phase.rs` (tool branch and mode constraint overlay)
- `policy/workspace.rs::enforce_workspace_path`

## Tests proving it

- `tests/stage4_tools.rs`
- `tests/invariants_tool_chokepoint.rs`
- `tests/modes.rs` (`mode_tool_tightening_denies_execution`)
- `tests/stage12_workspace.rs` (filesystem/tool workspace gate integration)

## Common failure scenarios + how to diagnose

1. **`tool_not_allowed`**
   - Check `runtime/tools/policy.json` and mode constraints in mode-applied artifact.
   - Confirm `tool_execution_denied` event reason and tool id.
2. **`tool_approval_required`**
   - Find `tool_approval_required.approval_ref`.
   - Create approval via `serverd approve ...` or write matching approved artifact.
3. **`tool_requires_arming`**
   - Set `TOOLS_ARM=1` for high-risk/arming-required tools.
4. **`workspace_*`**
   - Inspect `workspace/policy.json`, requested tool path, and `workspace_violation` event.