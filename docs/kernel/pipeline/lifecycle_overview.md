# Lifecycle Overview

## What you learn

- The top-level run lifecycle for `null`, `route`, `ingest`, and `replay`.
- Which files own orchestration vs per-phase logic.
- Where capsule and audit finalization occur.
- How task queue execution differs from synthetic tick execution.
- Where mode/policy binding is applied.
- How memory lattice integration fits into route/null loops.

## Top-level command entry

- CLI dispatch: `serverd/src/cli.rs`
- Runtime entrypoint: `serverd/src/runner/mod.rs`

## Route lifecycle (high-level)

1. `run_started`
2. Load policies/config (workspace, redaction, context, retrieval, lens, mode, tools, router, skills)
3. For each tick:
   - if pending task exists: claim + execute task intent
   - else: synthesize intent from `--delta`
   - call `run_route_tick(...)` in `route/provider_phase.rs`
4. Build and write run capsule (`run_capsule_written`)
5. Persist task request if present
6. `run_completed`

## Null lifecycle (high-level)

`run_null` in `runner/mod.rs` executes deterministic state delta flow with task queue handling but without provider/route provider logic.

## Ingest lifecycle (high-level)

`run_ingest` validates and persists task requests, writes queue/status events, and emits a run capsule/audit tail.

## Replay lifecycle (high-level)

`run_replay` re-applies pending tasks deterministically (or confirms already-applied), then emits capsule and completion.

## CURRENT CODE BEHAVIOR

The route phase model is implemented in one function (`run_route_tick`) in `route/provider_phase.rs`. It handles retrieval, lensing, context/prompt build, provider I/O, contract validation, tool execution, and state writeback in one deterministic sequence.
