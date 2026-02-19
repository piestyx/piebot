# Verification and Replay

## What you learn

- How `verify` and `replay` commands are implemented today.
- What they check and what they do not check.
- How replay uses persisted tasks and task status files.
- How cross-runtime parity is validated.
- Which artifacts/events are key evidence during verification.
- Which tests prove these paths.

## Verify command

Entry: `runner/mod.rs::run_verify`.

Key behavior:
    - Reads audit log and verifies hash chain.
    - Optional `--run-id` returns final state hash for that run window.
    - `--memory` enables memory consistency checks in verify path.

Primary failure reasons include:
    - `verify_run_invalid`
    - audit read/chain failures via `audit_log_invalid` path

## Replay command

Entry: `runner/mod.rs::run_replay`.

Key behavior:
    - Loads task by `--task`.
    - Validates task id and task JSON shape.
    - Replays pending task via `execute_one_tick` or returns already-applied outcome.
    - Writes run capsule and `run_completed`.

Primary replay-related reasons include:
    - `task_not_found`, `invalid_task_json`, `invalid_task_request`
    - `task_status_missing`, `task_rejected`, `task_status_write_failed`

## Route provider replay mode (`--mode route --provider replay`)

Entry: route execution path in `route/provider_phase.rs` with provider mode `Replay`.

Key behavior:
    - Provider response is loaded from `artifacts/provider_responses/<request_hash>.json` (provider call is not performed).
    - Retrieval still runs, but GSAMA replay write path is no-write.
    - GSAMA store must already exist in replay (`replay_requires_existing_gsama_store` fail-closed if missing).
    - `memory/gsama/store_snapshot.json` remains byte-stable across replay runs.

Evidence:
    - `tests/pipeline_b5_workflow_demo.rs`

## Parity expectations

For equivalent task+delta artifacts, replay should produce identical final state hash across runtime roots.

Evidence:
    - `tests/invariants_cross_runtime_replay_parity.rs`
    - `tests/stage15_verify_replay.rs`
    - `tests/verify_cmd.rs`

## Operator checklist

1. Verify source run and capture `run_id` + `state_hash`.
2. Confirm task file + state delta artifact refs exist.
3. Run replay on target runtime.
4. Compare final state hash and relevant audit run window.

