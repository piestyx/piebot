# Route Tick Phases

## What you learn

- The exact execution order inside one route tick.
- Which audit events correspond to each phase.
- Which artifacts are written at each boundary.
- Where fail-closed checks happen.
- How tool execution is conditioned on contracts and policy.
- Where GSAMA retrieval/writeback branches run.

## Phase sequence (`run_route_tick`)

Authoritative implementation: `serverd/src/route/provider_phase.rs::run_route_tick`.

1. **Observation + request hash prelude**
   - compute observation, current state hash, request hash
2. **Routing selection**
   - select provider from router config
   - optional fallback to `null` if policy allows
3. **Retrieval phase (optional)**
   - build query, write query artifact, execute retrieval, write results
4. **Lens planning/execution (optional)**
   - build lens plan
   - if non-empty selection: write lens set and execute pipeline
5. **Context policy + context selection**
   - apply policy to seed + retrieval/lens candidate refs
   - write context artifact
6. **Prompt construction + redaction/minimization**
   - resolve prompt templates and context bodies
   - write prompt artifact
7. **Provider request/response I/O**
   - write input/constraints/request artifacts
   - provider infer
   - write output/response artifacts
8. **Output contract validation**
   - validate output against skill contract (if configured)
9. **Tool branch (optional)**
   - parse `tool_call`
   - enforce skill constraints
   - enforce tool policy + workspace
   - execute builtin tool and write artifacts
10. **State writeback**
   - call `tick_core` (state delta artifact + apply + episode + working snapshot)
11. **GSAMA writeback branch (if retrieval kind is gsama)**
   - write context pointer
   - append episode embedding to GSAMA store

## Audit event landmarks

- Route/provider: `route_selected`, `provider_request_written`, `provider_response_written`
- Retrieval/lens: `retrieval_*`, `lens_*`
- Context/prompt: `context_policy_loaded`, `context_selected`, `prompt_built`
- Contracts/tools: `output_contract_loaded`, `provider_output_validated`, `tool_*`
- State/memory: `state_delta_artifact_written`, `state_delta_applied`, `episode_appended`, `working_memory_updated`, `tick_completed`

## Failure boundaries

Any phase failure calls `fail_run(...)` immediately with a subsystem reason. No best-effort continuation is attempted.