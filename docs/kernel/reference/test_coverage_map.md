# Test Coverage Map

## What you learn

- Which tests back each kernel subsystem.
- Where invariants are enforced in dedicated invariant tests.
- Which integration tests prove cross-subsystem ordering.
- Which tests focus on replay/verify correctness.
- Which tests validate mode/lens/retrieval interactions.
- Which test files to run when changing a subsystem.

## Subsystem → tests

| Subsystem | Primary tests |
|---|---|
| Router/provider boundary | `stage3_router.rs`, `stage6_end_to_end.rs` |
| Redaction | `stage7_redaction.rs` |
| Context policy + prompt | `stage8_context_policy.rs`, `stage8_prompt_build.rs` |
| Output contracts | `stage9_output_contracts.rs` |
| Tools policy/execution | `stage4_tools.rs`, `invariants_tool_chokepoint.rs` |
| Workspace hygiene | `stage12_workspace.rs` |
| Retrieval | `stage13_retrieval.rs`, `stage_gsama_retrieval.rs` |
| Lenses | `stage14_lenses.rs`, `stage18_lens_plan.rs`, `invariants_lens_context_policy_denial.rs` |
| Modes | `modes.rs`, `stage17_mode_policy_binding.rs` |
| Run capsule | `stage10_run_capsule.rs`, `invariants_capsule_sufficient_verification.rs` |
| Explain | `stage11_explain.rs` |
| State delta/replay parity | `stage1_tick.rs`, `stage15_verify_replay.rs`, `invariants_cross_runtime_replay_parity.rs`, `verify_cmd.rs` |
| Memory layers/lattice | `stage2_memory.rs`, `open_memory_mirror.rs`, `stage16_memory_lattice.rs` |
| Task ingest/queue/replay | `task_ingest.rs`, `task_queue_run.rs`, `task_replay.rs` |
| Mutation commands | `stage15_approval.rs`, `stage15_learnings.rs`, `stage15_capsule_export.rs` |

## Full-stack gates

- `stage_gate_7_12.rs` (end-to-end deterministic route gate for redaction/context/prompt/contracts/workspace/capsule/explain)

## Suggested targeted runs

- Single high-level route gate:
  - `cargo test -p serverd --manifest-path rust/Cargo.toml --test stage_gate_7_12`
- Then subsystem-specific test file(s) above.

