# Ordering Invariants

## What you learn

- Which event ordering constraints are intentional and tested.
- Where single-callsite tool execution is enforced.
- How run capsule and explain ordering is constrained.
- How replay parity invariants are verified.
- Which orderings are implementation details vs explicit contracts.
- How to detect ordering regressions in tests.

## Invariants

### 1) Single tool execution choke-point

- Exactly one runtime `execute_tool(...)` callsite.
- Location must be `route/provider_phase.rs`.
- Test: `tests/invariants_tool_chokepoint.rs`.

### 2) Capsule written before run completion

- `run_capsule_written` occurs before `run_completed`.
- Evidence: `tests/stage10_run_capsule.rs`.

### 3) Explain scoped to one run window

- `explain --run` / `--capsule` must resolve to one run-start/run-completed window.
- No cross-run mixing of related hashes.
- Evidence: `tests/stage11_explain.rs`.

### 4) Cross-runtime replay parity

- Replaying same persisted task + delta artifact in a different runtime root yields same final state hash.
- Evidence: `tests/invariants_cross_runtime_replay_parity.rs`.

### 5) Deterministic retrieval/lens/mode artifact parity

- Same effective config/input gives same output hashes and bytes across runtime roots.
- Evidence: `tests/stage13_retrieval.rs`, `tests/stage14_lenses.rs`, `tests/stage17_mode_policy_binding.rs`, `tests/stage18_lens_plan.rs`.

## CURRENT CODE BEHAVIOR

Route phase ordering is encoded directly in `run_route_tick` rather than spread across separate phase modules. Order-sensitive changes should be reviewed as one function-level diff.

## Regression checklist

- run `cargo test -p serverd --manifest-path rust/Cargo.toml --test stage_gate_7_12`
- run invariant tests:
  - `invariants_tool_chokepoint`
  - `invariants_cross_runtime_replay_parity`
  - `invariants_lens_context_policy_denial`
  - `invariants_capsule_sufficient_verification`