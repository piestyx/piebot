# Kernel Lock Declaration (Part A)
This document declares the Part A kernel contracts as LOCKED.
All MUST statements below are normative for kernel changes on `main`.
A contract is either:
- Proven: backed by current automated tests listed in this file.
- Not yet proven: behavior exists in code, but invariant-hardening tests are still required.

No contract in this file may be weakened without an explicit migration stage.

## 1) Scope
Part A kernel boundary is the `serverd` orchestrator runtime and the artifacts/audit surface it controls.

Included boundary:
- orchestration and run lifecycle: `rust/crates/serverd/src/runner/mod.rs`, `rust/crates/serverd/src/cli.rs`
- route tick pipeline and phase ordering: `rust/crates/serverd/src/route/provider_phase.rs`
- policy and safety gates: `rust/crates/serverd/src/policy/*`, `rust/crates/serverd/src/tools/*`, `rust/crates/serverd/src/output_contract.rs`
- state, memory, and replayability primitives: `rust/crates/serverd/src/tick_core.rs`, `rust/crates/serverd/src/state_delta_artifact.rs`, `rust/crates/serverd/src/memory.rs`, `rust/crates/serverd/src/memory_lattice.rs`
- artifact hashing/writes: `rust/crates/serverd/src/runtime/artifacts.rs`
- capsule + explain: `rust/crates/serverd/src/capsule/run_capsule.rs`, `rust/crates/serverd/src/runtime/explain.rs`
- audit chain integrity: `rust/crates/audit_log/src/lib.rs`, `rust/crates/serverd/src/audit.rs`

Part B may evolve:
- internal implementation details that preserve all MUST contracts here
- new schemas via new schema IDs/versions
- new audit events as additive changes
- new optional fields with additive compatibility rules in section 8

## 2) Locked invariants
### 2.1 Determinism MUST hold for identical inputs/config
- Modules: `rust/crates/common/src/lib.rs`, `rust/crates/serverd/src/runtime/artifacts.rs`, `rust/crates/serverd/src/route/provider_phase.rs`
- Audit events: deterministic traces validated across runtimes via `run_started`, `tick_completed`, `run_completed`, `run_capsule_written`
- Tests:
  - `rust/crates/serverd/tests/stage_gate_7_12.rs`
  - `rust/crates/serverd/tests/stage10_run_capsule.rs`
  - `rust/crates/serverd/tests/stage11_explain.rs`
  - `rust/crates/serverd/tests/stage14_lenses.rs`
  - `rust/crates/serverd/tests/stage17_mode_policy_binding.rs`
  - `rust/crates/serverd/tests/invariants_cross_runtime_replay_parity.rs`
- Status: Proven

### 2.1.a Request-hash observation sources MUST exclude generated artifact directories
- Modules: `rust/crates/serverd/src/tick_core.rs` (`observe`, `task_request_hash`)
- Contract:
  - Observation for request-hash derivation MUST include deterministic input-bearing files under the runtime root.
  - Observation MUST exclude generated directories that are produced by route execution itself to avoid circular request-hash drift.
  - Excluded directories are currently: `logs`, `provider_responses`, `tool_outputs`.
- Rationale:
  - Including generated directories would let prior tool/provider outputs perturb subsequent request hashes for otherwise equivalent runs.
  - Exclusions preserve replay parity and deterministic request hash derivation from true inputs.
- Tests:
  - `rust/crates/serverd/tests/invariants_request_hash_observation.rs`
- Status: Proven

### 2.2 Fail-closed behavior MUST hold
- Modules: `rust/crates/serverd/src/audit.rs` (`fail_run`), plus subsystem validators/gates
- Audit events: subsystem-specific failure events before terminal `run_completed` (for example: `provider_output_rejected`, `tool_execution_denied`, `workspace_violation`, `retrieval_failed`, `lens_failed`, `mode_failed`)
- Tests:
  - `rust/crates/serverd/tests/stage7_redaction.rs`
  - `rust/crates/serverd/tests/stage8_context_policy.rs`
  - `rust/crates/serverd/tests/stage9_output_contracts.rs`
  - `rust/crates/serverd/tests/stage12_workspace.rs`
  - `rust/crates/serverd/tests/stage13_retrieval.rs`
  - `rust/crates/serverd/tests/stage14_lenses.rs`
  - `rust/crates/serverd/tests/stage17_mode_policy_binding.rs`
- Status: Proven

### 2.3 Model is untrusted worker; orchestrator is authority
- Modules: `rust/crates/serverd/src/route/provider_phase.rs`, `rust/crates/serverd/src/output_contract.rs`, `rust/crates/serverd/src/tools/execute.rs`
- Audit events: `provider_output_validated`, `provider_output_rejected`, `tool_execution_denied`, `tool_selected`, `tool_executed`
- Tests:
  - `rust/crates/serverd/tests/stage9_output_contracts.rs`
  - `rust/crates/serverd/tests/stage_gate_7_12.rs`
  - `rust/crates/serverd/tests/invariants_tool_chokepoint.rs`
- Status: Proven

### 2.4 Tool-triggered side effects MUST pass the single runtime tool choke-point
- Modules: `rust/crates/serverd/src/tools/execute.rs`, callsite in `rust/crates/serverd/src/route/provider_phase.rs`
- Audit events: `tool_selected`, `tool_call_written`, `tool_executed`, `tool_output_written`
- Tests:
  - `rust/crates/serverd/tests/invariants_tool_chokepoint.rs`
  - `rust/crates/serverd/tests/stage4_tools.rs`
- Status: Proven

### 2.5 Provider egress MUST be ref-addressed and redaction-aware
- Modules:
  - request/response shape: `rust/crates/serverd/src/provider.rs` (`ProviderRequest` uses `input_ref`/`constraints_ref`, plus `context_ref`/`prompt_ref`)
  - redaction and byte caps: `rust/crates/serverd/src/redaction.rs`
  - route sequencing: `rust/crates/serverd/src/route/provider_phase.rs`
- Audit events: `redaction_config_loaded`, `provider_input_redacted`, `provider_request_written`
- Tests:
  - `rust/crates/serverd/tests/stage7_redaction.rs`
  - `rust/crates/serverd/tests/stage_gate_7_12.rs`
  - `rust/crates/serverd/tests/stage6_end_to_end.rs`
- Status: Proven (ordering and refs in request artifacts)
- Not yet proven: explicit invariant test that request artifacts never add inline prompt/context raw body fields.
  - Hardening test to add: `rust/crates/serverd/tests/invariants_provider_request_refs_only.rs`

### 2.6 Output contract validation MUST occur before tool execution
- Modules: `rust/crates/serverd/src/route/provider_phase.rs`, `rust/crates/serverd/src/output_contract.rs`, `rust/crates/serverd/src/tools/execute.rs`
- Audit events: `output_contract_loaded`, `provider_output_validated`, `provider_output_rejected`, `tool_selected`
- Tests:
  - `rust/crates/serverd/tests/stage9_output_contracts.rs`
  - `rust/crates/serverd/tests/stage_gate_7_12.rs`
- Status: Proven

### 2.7 Workspace escape prevention MUST hold for filesystem tools
- Modules: `rust/crates/serverd/src/policy/workspace.rs`, `rust/crates/serverd/src/tools/execute.rs`
- Audit events: `workspace_policy_loaded`, `workspace_violation`
- Tests:
  - `rust/crates/serverd/tests/stage12_workspace.rs`
  - `rust/crates/serverd/tests/stage_gate_7_12.rs`
- Status: Proven

### 2.8 Mode policy MUST be monotonic (tightening-only)
- Modules: `rust/crates/serverd/src/modes/policy.rs`, `rust/crates/serverd/src/modes/apply.rs`, `rust/crates/serverd/src/runner/mod.rs`
- Audit events: `mode_policy_applied`, `mode_failed`
- Tests:
  - `rust/crates/serverd/tests/stage17_mode_policy_binding.rs`
  - `rust/crates/serverd/tests/modes.rs`
- Status: Proven

### 2.9 Audit hash-chain integrity MUST hold
- Modules: `rust/crates/audit_log/src/lib.rs` (`AuditAppender::append`, `verify_log`), `rust/crates/serverd/src/audit.rs`
- Audit events: all events are chain members in `logs/audit_rust.jsonl`
- Tests:
  - `rust/crates/serverd/tests/stage_gate_7_12.rs`
  - `rust/crates/serverd/tests/verify_cmd.rs`
  - `rust/crates/serverd/tests/stage15_verify_replay.rs`
- Status: Proven

## 3) Ordering contracts
These ordering contracts are LOCKED.

- `run_started` MUST be first event in a run window.
  - Modules: `rust/crates/serverd/src/runner/mod.rs`
  - Tests: `rust/crates/serverd/tests/stage_gate_7_12.rs`
- `workspace_policy_loaded` MUST occur before tool decision/execution events.
  - Modules: `rust/crates/serverd/src/runner/mod.rs`, `rust/crates/serverd/src/tools/execute.rs`
  - Tests: `rust/crates/serverd/tests/stage_gate_7_12.rs`
- `provider_input_redacted` MUST occur before `provider_request_written` when redaction is enabled.
  - Modules: `rust/crates/serverd/src/route/provider_phase.rs`
  - Tests: `rust/crates/serverd/tests/stage_gate_7_12.rs`
- `context_policy_loaded` MUST occur before `context_selected`.
  - Modules: `rust/crates/serverd/src/route/provider_phase.rs`
  - Tests: `rust/crates/serverd/tests/stage_gate_7_12.rs`
- `context_selected` MUST occur before `prompt_built`.
  - Modules: `rust/crates/serverd/src/route/provider_phase.rs`
  - Tests: `rust/crates/serverd/tests/stage_gate_7_12.rs`
- `prompt_built` MUST occur before `provider_request_written`.
  - Modules: `rust/crates/serverd/src/route/provider_phase.rs`
  - Tests: `rust/crates/serverd/tests/stage_gate_7_12.rs`
- `provider_output_validated` MUST occur before `tool_selected`.
  - Modules: `rust/crates/serverd/src/route/provider_phase.rs`
  - Tests: `rust/crates/serverd/tests/stage_gate_7_12.rs`
- `retrieval_results_written` MUST occur before `lens_plan_built`.
  - Modules: `rust/crates/serverd/src/route/provider_phase.rs`
  - Tests: `rust/crates/serverd/tests/stage14_lenses.rs` (`lens_event_ordering_after_retrieval_before_context`)
- `lens_outputs_written` MUST occur before `context_selected`.
  - Modules: `rust/crates/serverd/src/route/provider_phase.rs`
  - Tests: `rust/crates/serverd/tests/stage14_lenses.rs` (`lens_event_ordering_after_retrieval_before_context`)
- `run_capsule_written` MUST occur before `run_completed`.
  - Modules: `rust/crates/serverd/src/runner/mod.rs`, `rust/crates/serverd/src/capsule/run_capsule.rs`
  - Tests: `rust/crates/serverd/tests/stage10_run_capsule.rs`, `rust/crates/serverd/tests/stage_gate_7_12.rs`

## 4) Schema and artifact contracts
All schema IDs listed below are frozen for Part A behavior.

Frozen `serverd.*` schema IDs:
- `serverd.audit.v1`
- `serverd.router.v1`
- `serverd.provider_request.v1`
- `serverd.provider_response.v1`
- `serverd.provider_output.v1`
- `serverd.provider_input.v1`
- `serverd.provider_constraints.v1`
- `serverd.redaction_config.v1`
- `serverd.context_selection.v1`
- `serverd.context_policy.v1`
- `serverd.prompt_template.v1`
- `serverd.prompt.v1`
- `serverd.output_contract.v1`
- `serverd.tool_spec.v1`
- `serverd.tool_registry.v1`
- `serverd.tool_policy.v1`
- `serverd.tool_approval_request.v1`
- `serverd.tool_approval.v1`
- `serverd.tool_call.v1`
- `serverd.tool_input.noop.v1`
- `serverd.tool_input.fs_probe.v1`
- `serverd.tool_output.v1`
- `serverd.tool_output.noop.v1`
- `serverd.tool_output.fs_probe.v1`
- `serverd.retrieval_config.v1`
- `serverd.retrieval_query.v1`
- `serverd.retrieval_results.v1`
- `serverd.context_pointer.v1`
- `serverd.lens_config.v1`
- `serverd.lens_plan.v1`
- `serverd.lens_set_selected.v1`
- `serverd.lens_outputs.v1`
- `serverd.mode_config.v1`
- `serverd.mode_profile.v1`
- `serverd.mode_route.v1`
- `serverd.mode_applied.v1`
- `serverd.workspace_policy.v1`
- `serverd.state_delta_artifact.v1`
- `serverd.run_capsule.v1`
- `serverd.explain.v1`
- `serverd.skill_manifest.v1`
- `serverd.task_status.v1`
- `serverd.learning_entry.v1`
- `serverd.memory_lattice_config.v1`
- `serverd.memory_lattice.v1`
- `serverd.episode.v1`
- `serverd.working_memory.v1`

Frozen supporting GSAMA schemas:
- `gsama.store_snapshot.v1`
- `gsama.semantic_vector.v1`

Versioning contract:
- `*.v1` means stable semantics for Part A.
- `*.v2+` MUST be introduced as new schema IDs; existing `v1` behavior MUST continue to parse/verify until migration stage completion.
- Breaking schema changes MUST NOT be made in-place to an existing schema ID.

## 5) Fail-closed reason code contracts
Reason codes are a stable API for operators, tests, and automation.

Contract:
- Existing reason strings MUST NOT change meaning.
- Existing reason strings MUST NOT be silently removed without explicit migration.
- New reason strings MAY be added additively.
- Canonical grouped index: `docs/kernel/reference/fail_closed_reasons_index.md`.

Authority and emission:
- terminal fail path: `rust/crates/serverd/src/audit.rs` (`fail_run`)
- subsystem reason producers: `rust/crates/serverd/src/*` and `rust/crates/serverd/src/*/*`
- observable events: subsystem failure/denial events plus terminal `run_completed`

Proof tests:
- `rust/crates/serverd/tests/stage7_redaction.rs`
- `rust/crates/serverd/tests/stage8_context_policy.rs`
- `rust/crates/serverd/tests/stage9_output_contracts.rs`
- `rust/crates/serverd/tests/stage12_workspace.rs`
- `rust/crates/serverd/tests/stage13_retrieval.rs`
- `rust/crates/serverd/tests/stage14_lenses.rs`
- `rust/crates/serverd/tests/stage17_mode_policy_binding.rs`

## 6) Public surface contracts
### 6.1 Stable CLI/runtime surface
The `serverd` binary surface is LOCKED as the public kernel interface:
- entry: `rust/crates/serverd/src/main.rs` -> `serverd::run()`
- parser/dispatch: `rust/crates/serverd/src/cli.rs`
- commands: run (`null|route`), `verify`, `ingest`, `replay`, `explain`, `approve`, `learn`, `capsule export`
- runtime layout expectations under runtime root (state/logs/artifacts/tasks/memory/workspace plus config paths consumed by loaders)

### 6.2 Stable Rust exports (intentionally locked)
From `rust/crates/serverd/src/lib.rs`, the following exports are locked public contracts:
- `run()`
- `RUN_CAPSULE_SCHEMA`
- `EXPLAIN_SCHEMA`
- `load_context_policy(...)`
- `CONTEXT_POLICY_SCHEMA`

Not yet proven:
- no automated API-surface guard currently enforces this exact export set.
- Hardening test to add: `rust/crates/serverd/tests/invariants_public_api_surface.rs`.

## 7) Verification and replay contracts
Verification and replay are LOCKED as follows:

- Audit-based verification is authoritative.
  - Modules: `rust/crates/audit_log/src/lib.rs`, `rust/crates/serverd/src/runner/mod.rs`
  - Tests: `rust/crates/serverd/tests/verify_cmd.rs`, `rust/crates/serverd/tests/stage15_verify_replay.rs`
- `verify --run-id` MUST return run-window final state hash derived from audit events.
  - Modules: `rust/crates/serverd/src/runner/mod.rs`, `rust/crates/serverd/src/audit.rs`
  - Tests: `rust/crates/serverd/tests/verify_cmd.rs`, `rust/crates/serverd/tests/stage15_verify_replay.rs`
- Replay across runtime roots with equivalent task/delta artifacts MUST converge on equivalent final state hash.
  - Modules: `rust/crates/serverd/src/runner/mod.rs`, `rust/crates/serverd/src/state_delta_artifact.rs`
  - Tests: `rust/crates/serverd/tests/invariants_cross_runtime_replay_parity.rs`
- Run capsule determinism and explain determinism MUST remain consistent with audit-backed verification windows.
  - Modules: `rust/crates/serverd/src/capsule/run_capsule.rs`, `rust/crates/serverd/src/runtime/explain.rs`, `rust/crates/serverd/src/audit.rs`
  - Tests: `rust/crates/serverd/tests/stage10_run_capsule.rs`, `rust/crates/serverd/tests/stage11_explain.rs`, `rust/crates/serverd/tests/stage_gate_7_12.rs`

## 8) Compatibility rules
Additive-only changes are allowed for:
- new audit events added to `AuditEvent` without reinterpreting existing events
- new schema versions (new IDs like `*.v2`) while preserving `*.v1` behavior
- new optional fields guarded by `skip_serializing_if` / defaults that preserve old readers

Breaking changes require all of:
- a new schema version
- migration tooling/scripts and compatibility verification
- an explicit migration stage in the implementation plan before merge

## 9) Compliance checklist (kernel PR gate)
Every kernel PR MUST satisfy:
- [ ] `cargo test -p serverd --manifest-path rust/Cargo.toml --test stage_gate_7_12`
- [ ] `cargo test -p serverd --manifest-path rust/Cargo.toml --test invariants_tool_chokepoint`
- [ ] `cargo test -p serverd --manifest-path rust/Cargo.toml --test stage14_lenses lens_event_ordering_after_retrieval_before_context`
- [ ] `cargo test -p serverd --manifest-path rust/Cargo.toml --test stage12_workspace`
- [ ] `cargo test -p serverd --manifest-path rust/Cargo.toml --test stage17_mode_policy_binding`
- [ ] `cargo test -p serverd --manifest-path rust/Cargo.toml --test stage9_output_contracts`
- [ ] `cargo test -p serverd --manifest-path rust/Cargo.toml --test stage10_run_capsule`
- [ ] `cargo test -p serverd --manifest-path rust/Cargo.toml --test stage11_explain`
- [ ] `cargo test -p serverd --manifest-path rust/Cargo.toml --test verify_cmd`
- [ ] `cargo test -p serverd --manifest-path rust/Cargo.toml --test invariants_cross_runtime_replay_parity`

This checklist is the minimum CI gate for the locked contracts in this document.
