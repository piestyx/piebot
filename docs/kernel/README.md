# Kernel Docs (Implementation-Aligned)

## What you learn

- What the kernel is in this repo: the `serverd` runtime and its control surfaces.
- How a `route` or `null` run is assembled from deterministic modules.
- Where authority is enforced (orchestrator-owned state, tool choke-point, policy gates).
- Which artifacts and audit events are emitted, and where they are written.
- How fail-closed behavior is implemented and how to diagnose failures quickly.
- Which tests prove ordering, replay parity, and policy enforcement.
- How to navigate subsystem, operations, and reference pages for code-level details.

This documentation set is intentionally implementation-first. Every behavior statement maps to concrete files under `rust/crates/serverd` (and supporting crates) plus tests under `rust/crates/serverd/tests`.

## Scope and source of truth

- Primary runtime: `rust/crates/serverd/src/*`
- Shared hashing/canonicalization: `rust/crates/common/src/lib.rs`
- Audit hash chain implementation: `rust/crates/audit_log/src/lib.rs`
- State model: `rust/crates/state/src/lib.rs`
- Test evidence: `rust/crates/serverd/tests/*`

## CURRENT CODE BEHAVIOR

Route orchestration is centralized in `rust/crates/serverd/src/route/provider_phase.rs` and called from `rust/crates/serverd/src/runner/mod.rs`. The split files in `rust/crates/serverd/src/route/*_phase.rs` are placeholders and not the authoritative phase implementation.

## Documentation map
```text
docs/kernel/
  README.md
  concepts/
    authority_model.md
    determinism_model.md
    artifacts_and_refs.md
    audit_log_integrity.md
    failure_model.md
  pipeline/
    lifecycle_overview.md
    route_tick_phases.md
    ordering_invariants.md
  subsystems/
    state_gsama.md
    memory_stratification.md
    router_provider_boundary.md
    redaction.md
    context_policy_and_prompt.md
    output_contracts.md
    tools_policy_and_execution.md
    workspace_hygiene.md
    retrieval.md
    lenses.md
    modes.md
    run_capsule.md
    explain.md
  operations/
    runtime_layout.md
    cli_reference.md
    debugging_playbook.md
    verification_and_replay.md
  reference/
    schemas_index.md
    audit_events_index.md
    fail_closed_reasons_index.md
    config_files_index.md
    test_coverage_map.md
```

## Reading order

1. `pipeline/lifecycle_overview.md`
2. `pipeline/route_tick_phases.md`
3. `pipeline/ordering_invariants.md`
4. Subsystem pages in risk order (tools → contracts → redaction → prompt/context → workspace → retrieval/lenses/modes → capsule/explain → memory/state)
5. Reference indexes for schema/event/reason lookups

## Evidence contract used in these docs

For each subsystem page:
  - Purpose
  - Threat model / prevention target
  - Inputs/outputs (artifact refs)
  - Audit events
  - Fail-closed reasons
  - Determinism guarantees
  - Config and schema files
  - Core enforcement points (module/function)
  - Tests proving behavior
  - Failure scenarios and diagnosis