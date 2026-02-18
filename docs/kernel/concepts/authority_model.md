# Authority Model

## What you learn

- Where authority lives in the current runtime.
- Which modules are allowed to mutate state.
- Why provider/model output is treated as proposals only.
- Where tool side-effects are forced through policy and workspace gates.
- How audit and artifact writes constrain behavior.
- Which tests guard the authority boundary.

## Core principle

The authoritative control loop is `serverd`; model providers never mutate state directly. Provider output can propose `tool_call`, but execution and state mutation are orchestrator-owned.

## Enforcement map

| Authority boundary | Enforcement point | Outcome on violation |
|---|---|---|
| State mutation only via orchestrator | `runner/mod.rs` + `tick_core.rs` + `state_delta_artifact.rs` | `fail_run(...)` with fail-closed reason |
| Tool execution choke-point | `tools/execute.rs::execute_tool`, called from `route/provider_phase.rs` | tool denied / run failed |
| Skill-level tool limits | `skills.rs::enforce_tool_call` | `ToolExecutionDenied` with `skill_tool_*` reason |
| Workspace path authority | `policy/workspace.rs::enforce_workspace_path` | `WorkspaceViolation` + fail |

## Model/provider trust boundary

- Provider I/O schemas are validated in `provider.rs`.
- Contract validation (`output_contract.rs`) happens before tool execution in `route/provider_phase.rs`.
- If provider output violates contract or schema, run fails closed.

## Audit visibility of authority decisions

Authority-critical events:
    - `run_started`, `run_completed`
    - `route_selected`, `provider_failed`
    - `provider_output_validated`, `provider_output_rejected`
    - `tool_execution_denied`, `tool_approval_required`, `tool_executed`
    - `workspace_violation`

Definitions: `serverd/src/audit.rs`.

## Tests proving this model

- Single tool choke-point invariant: `tests/invariants_tool_chokepoint.rs`
- Tool policy and execution denial/approval paths: `tests/stage4_tools.rs`
- Workspace gate enforcement: `tests/stage12_workspace.rs`
- End-to-end stage ordering (7–12): `tests/stage_gate_7_12.rs`

