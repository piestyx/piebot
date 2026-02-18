# Artifacts and Refs

## What you learn

- How artifact references are formed and resolved.
- Which artifact directories are used by each phase.
- How content hashes are enforced at write time.
- How ref namespaces are normalized.
- How to trace a request across request/response/output/tool artifacts.
- Which modules own artifact path rules.

## Reference format

- Canonical hash ref: `sha256:<64-hex>`
- Artifact filename: `<hash-without-prefix>.json` via `runtime/artifacts.rs::artifact_filename`
- Namespaced refs may appear as `namespace/sha256:<...>` in retrieval/context flows.

## Write semantics

All major writes use content-addressed, atomic writes:
    - `runtime/artifacts.rs::write_json_artifact_atomic`
    - `state_delta_artifact.rs::write_delta_artifact`
    - `capsule/run_capsule.rs::write_run_capsule`
    - `runtime/explain.rs::write_explain`

If a target file already exists for a hash, bytes must match exactly or write fails.

## Common artifact subdirectories

| Subdir under `runtime/artifacts/` | Typical producer |
|---|---|
| `requests`, `responses`, `outputs` | `route/provider_phase.rs` |
| `inputs`, `constraints` | `route/provider_phase.rs` |
| `prompts`, `contexts`, `context_policies` | context/prompt assembly in `route/provider_phase.rs` |
| `tool_calls`, `tool_inputs`, `tool_outputs` | `tools/execute.rs` + route tool branch |
| `retrieval_queries`, `retrieval_results`, `retrieval_configs` | retrieval flow in `route/provider_phase.rs` |
| `lens_plans`, `lens_sets`, `lens_outputs`, `lens_configs` | lens flow in `route/provider_phase.rs` |
| `mode_configs`, `mode_profiles`, `mode_routes`, `mode_applied` | mode loading/apply in `runner/mod.rs` |
| `run_capsules`, `explains` | `run_capsule.rs`, `runtime/explain.rs` |
| `state_deltas` | `state_delta_artifact.rs` |

## Ref normalization helpers

- `ref_utils.rs`: parsing/splitting/normalizing explicit refs
- Retrieval modules depend on normalized refs to maintain deterministic candidate handling.

## Trace example

Minimal route trace (refs only):
1. `provider_request_written.artifact_ref` → `artifacts/requests/<hash>.json`
2. `provider_response_written.artifact_ref` → `artifacts/responses/<hash>.json`
3. response contains `output_ref` → `artifacts/outputs/<hash>.json`
4. if tool call executes: `tool_call_written.tool_call_ref` + `tool_output_written.artifact_ref`

