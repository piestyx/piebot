# Lenses

## What you learn

- How lens plans are built from intent/mode/retrieval state.
- How lens set selection and pipeline execution work.
- How lens output caps are enforced.
- Which reason codes and failures are surfaced.
- How mode policy hash is propagated into lens plans.
- Which tests prove determinism and fail-closed behavior.

## Purpose

Refine retrieval context candidates through deterministic post-processing (`dedup_v1`, `recency_v1`, `salience_v1`).

## Threat model / what it prevents

- Unbounded candidate growth.
- Lens activation without retrieval preconditions.
- Ambiguous lens order or non-canonical lens selections.

## Inputs and outputs (artifact refs)

| Direction | Artifact | Path |
|---|---|---|
| In | lens config | `lenses/config.json` |
| In | retrieval results | `artifacts/retrieval_results/<hash>.json` |
| Out | lens plan | `artifacts/lens_plans/<hash>.json` |
| Out | lens set selected | `artifacts/lens_sets/<hash>.json` |
| Out | lens outputs | `artifacts/lens_outputs/<hash>.json` |

## Audit events emitted

- `lens_config_loaded`
- `lens_plan_built`
- `lens_set_selected`
- `lens_executed`
- `lens_outputs_written`
- `lens_failed`

## Fail-closed reasons

- Config/selection: `lens_config_read_failed`, `lens_config_invalid`, `lens_selection_invalid`
- Plan: `lens_plan_invalid`, `lens_plan_empty_selection`, `lens_requires_retrieval`
- Output caps: `lens_output_exceeds_max_candidates`, `lens_output_exceeds_max_bytes`
- Pipeline generic: `lens_failed`

## Determinism guarantees

- Lens IDs are canonicalized to fixed order.
- Plan hash computed from canonical plan artifact.
- Execution order follows selected lens id order.
- Output hash computed from deterministic fields and canonical JSON.

## Config file(s) + schema(s)

| File | Schema |
|---|---|
| `runtime/lenses/config.json` | `serverd.lens_config.v1` |
| plan artifact | `serverd.lens_plan.v1` |
| set artifact | `serverd.lens_set_selected.v1` |
| output artifact | `serverd.lens_outputs.v1` |

## Core enforcement points (functions + file paths)

- `lenses.rs::load_lens_config`
- `lenses.rs::build_lens_plan`
- `lenses.rs::build_lens_set_selected`
- `lenses.rs::execute_lens_pipeline`
- `route/provider_phase.rs` (plan/write/execute integration)

## Tests proving it

- `tests/stage14_lenses.rs`
- `tests/stage18_lens_plan.rs`
- `tests/stage17_mode_policy_binding.rs` (mode policy influence)
- `tests/invariants_lens_context_policy_denial.rs`

## Common failure scenarios + how to diagnose

1. **`lens_requires_retrieval`**
   - Lenses enabled while retrieval disabled.
2. **`lens_config_invalid`**
   - Empty `allowed_lenses` or zero caps when enabled.
3. **`lens_output_exceeds_max_bytes`**
   - Candidate/summaries exceed configured output cap.

