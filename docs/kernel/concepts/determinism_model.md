# Determinism Model

## What you learn

- How canonical hashing is implemented.
- Which artifacts are content-addressed and stable across runtimes.
- How deterministic ordering is enforced in key subsystems.
- How replay parity is checked.
- Where deterministic assumptions can still fail.
- Which tests prove cross-runtime parity.

## Deterministic primitives

| Primitive | Module | Guarantee |
|---|---|---|
| Canonical JSON bytes | `common/src/lib.rs::canonical_json_bytes` | Object keys sorted before hashing/serialization |
| Content hash format | `common/src/lib.rs::sha256_bytes` | Uniform `sha256:<hex>` identity |
| Audit hash chain | `audit_log/src/lib.rs` | Each record commits prior hash + canonical payload |
| Artifact write-if-equal | `runtime/artifacts.rs::write_json_artifact_atomic` | Existing bytes must match for same hash |

## Deterministic ordering examples

- Tool registry load order sorted by filename: `tools/mod.rs::ToolRegistry::load_tools`
- Retrieval ranking sort tie-breakers: `retrieval/store_io.rs::rank_candidates`
- Lens ID canonical order: `lenses.rs::canonicalize_lens_ids`
- Mode allowlist normalization and sorting: `modes/normalize.rs`

## CURRENT CODE BEHAVIOR

Route phase sequencing is deterministic but consolidated in `route/provider_phase.rs` (not split phase modules).

## Replay and parity evidence

- Cross-runtime replay parity: `tests/invariants_cross_runtime_replay_parity.rs`
- Stage gate parity including capsule/explain: `tests/stage_gate_7_12.rs`
- Deterministic capsule bytes: `tests/stage10_run_capsule.rs`
- Deterministic explain bytes: `tests/stage11_explain.rs`
- Deterministic mode application artifacts: `tests/modes.rs`, `tests/stage17_mode_policy_binding.rs`
- Deterministic lens plan: `tests/stage18_lens_plan.rs`

## Determinism limits

Determinism is scoped to:
    - identical input/task artifacts,
    - identical runtime config/policy artifacts,
    - identical provider behavior for the selected provider.

Policy failures and environment gates (`TOOLS_ENABLE`, `TOOLS_ARM`, `OPEN_MEMORY_ENABLE`) are deterministic for a given environment snapshot but can differ across hosts if environment differs.