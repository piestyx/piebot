# Retrieval

## What you learn

- How retrieval config/query/results schemas are enforced.
- Differences between `refs` and `gsama` retrieval modes.
- Where retrieval artifacts and events are emitted.
- How selection limits and namespace constraints fail closed.
- How GSAMA query-vector and store preflight validation works.
- Which tests verify retrieval determinism and failures.

## Purpose

Provide deterministic context candidate selection for route ticks, either via metadata ranking (`refs`) or GSAMA vector retrieval (`gsama`).

## Threat model / what it prevents

- Namespace and source widening beyond policy.
- Invalid or missing GSAMA vectors for gsama mode.
- Oversized retrieval result sets.
- Silent retrieval source degradation.

## Inputs and outputs (artifact refs)

| Direction | Artifact | Path |
|---|---|---|
| In | retrieval config | `retrieval/config.json` |
| Out | config artifact | `artifacts/retrieval_configs/<hash>.json` |
| Out | query artifact | `artifacts/retrieval_queries/<hash>.json` |
| Out | results artifact | `artifacts/retrieval_results/<hash>.json` |
| Out (gsama writeback) | context pointer | `artifacts/contexts/<hash>.json` (schema `serverd.context_pointer.v1`) |
| Out (gsama writeback) | store snapshot | `memory/gsama/store_snapshot.json` |

## Audit events emitted

- `retrieval_config_loaded`
- `retrieval_query_written`
- `retrieval_executed`
- `retrieval_results_written`
- `retrieval_failed`

## Fail-closed reasons

- Config: `retrieval_config_read_failed`, `retrieval_config_invalid`
- Query: `retrieval_query_invalid`, `retrieval_namespace_denied`
- Sources/results: `retrieval_source_unavailable`, `retrieval_selection_exceeds_max_items`, `retrieval_selection_exceeds_max_bytes`, `retrieval_failed`
- GSAMA: `gsama_query_vector_missing`, `gsama_query_vector_dim_mismatch`, `gsama_store_not_found`, `gsama_store_dim_mismatch`, `gsama_store_capacity_mismatch`, `gsama_store_load_failed`, `gsama_store_write_failed`, `gsama_retrieval_failed`

## Determinism guarantees

- Config normalization sorts/dedups source/namespace/tag lists.
- `refs` ranking has deterministic tie-breakers.
- Result-set hash computed from canonical JSON of results + context candidates.
- GSAMA preflight enforces fixed dimension/capacity against config.

## Config file(s) + schema(s)

| File | Schema |
|---|---|
| `runtime/retrieval/config.json` | `serverd.retrieval_config.v1` |
| query artifact | `serverd.retrieval_query.v1` |
| results artifact | `serverd.retrieval_results.v1` |

## Core enforcement points (functions + file paths)

- `retrieval/validation.rs::load_retrieval_config`
- `retrieval/validation.rs::build_retrieval_query`
- `retrieval/validation.rs::execute_retrieval`
- `retrieval/refs_mode.rs` and `retrieval/gsama_mode.rs`
- `route/provider_phase.rs` (retrieval phase + gsama writeback)

## Tests proving it

- `tests/stage13_retrieval.rs`
- `tests/stage_gsama_retrieval.rs`
- `tests/modes.rs` (mode overlays impacting retrieval)
- `tests/stage_gate_7_12.rs`

## Common failure scenarios + how to diagnose

1. **`retrieval_namespace_denied`**
   - Query selectors include namespace outside config allowlist.
2. **`gsama_query_vector_missing`**
   - `kind=gsama` without query vector/ref in required mode.
3. **`retrieval_selection_exceeds_max_bytes`**
   - Candidate list too large for configured result cap.