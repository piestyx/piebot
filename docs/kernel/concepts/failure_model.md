# Failure Model

## What you learn
- How fail-closed is implemented in runtime control flow.
- Where reason strings originate.
- How failures are surfaced in audit events and CLI JSON.
- Which subsystems emit subsystem-specific denial events before failing.
- How to distinguish validation failure vs I/O failure.
- Which tests assert fail-closed outcomes.

## Fail-closed contract

Most route/null/replay/ingest failures end through:
    - `audit.rs::fail_run(...)`
    - emitted JSON: `{ "ok": false, "error": "<reason>" }`
    - `run_completed` is still appended with final state hash snapshot at failure boundary.

## Reason provenance

Reasons are explicit string constants or module-local literals, for example:
    - Tool policy: `tools_disabled`, `tool_not_allowed`, `tool_requires_arming`
    - Contracts: `provider_output_contract_violation`, `output_contract_not_found`
    - Workspace: `workspace_*` reasons in `policy/workspace.rs`
    - Retrieval/lens/mode: `retrieval_*`, `lens_*`, `mode_*`

## Failure telemetry pattern

Many subsystems emit a structured audit event before fail:
    - `ProviderOutputRejected` before contract failure
    - `ToolExecutionDenied` / `ToolApprovalRequired` for tool policy outcomes
    - `WorkspaceViolation` when path checks reject
    - `RetrievalFailed`, `LensFailed`, `ModeFailed` for phase-level failures

## Tests proving fail-closed behavior

- `tests/stage7_redaction.rs`
- `tests/stage8_context_policy.rs`
- `tests/stage9_output_contracts.rs`
- `tests/stage12_workspace.rs`
- `tests/stage13_retrieval.rs`
- `tests/stage14_lenses.rs`
- `tests/modes.rs`
- `tests/stage17_mode_policy_binding.rs`
- `tests/stage18_lens_plan.rs`
