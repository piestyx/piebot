# Router and Provider Boundary

## What you learn

- How provider selection is computed from router rules.
- How provider request/response artifacts are validated and written.
- How unavailability fallback behavior works.
- Which audit events represent route and provider boundaries.
- Which reasons indicate router vs provider failures.
- Which tests verify deterministic routing behavior.

## Purpose

Select a provider deterministically and execute provider I/O through typed request/response artifacts.

## Threat model / what it prevents

- Invalid provider IDs or malformed router config.
- Silent provider unavailability.
- Invalid provider response schema/hash coupling.
- Provider output used without artifactized trace.

## Inputs and outputs (artifact refs)

| Direction | Artifact | Path |
|---|---|---|
| In | router config | `router/config.json` |
| Out | provider request | `artifacts/requests/<hash>.json` |
| Out | provider output | `artifacts/outputs/<hash>.json` |
| Out | provider response | `artifacts/responses/<hash>.json` |

## Audit events emitted

- `route_selected`
- `provider_request_written`
- `provider_response_written`
- `provider_failed`

## Fail-closed reasons

- Router: `router_config_read_failed`, `router_config_invalid`, `provider_unavailable`
- Request/response/output path: `provider_request_invalid`, `provider_response_invalid`, `provider_output_missing`, `provider_input_write_failed`, `provider_output_ref_missing`, `artifact_*`

## Determinism guarantees

- Route rules evaluated in stable index order.
- Default route behavior deterministic when no rule matches.
- Request/response/output artifacts are canonical and hash-addressed.
- Route reason includes stable rule index (`route:<idx>`) or `default`.

## Config file(s) + schema(s)

| File | Schema |
|---|---|
| `runtime/router/config.json` | `serverd.router.v1` |
| provider request | `serverd.provider_request.v1` |
| provider response | `serverd.provider_response.v1` |
| provider output | `serverd.provider_output.v1` |
| provider input | `serverd.provider_input.v1` |
| provider constraints | `serverd.provider_constraints.v1` |

## Core enforcement points (functions + file paths)

- `router.rs::load_router_config`
- `router.rs::select_provider`
- `route/provider_phase.rs` (provider boundary and failure handling)
- `provider.rs` (request/response structs and mock/null provider implementations)

## Tests proving it

- `tests/stage3_router.rs`
- `tests/stage6_end_to_end.rs`
- `tests/stage_gate_7_12.rs` (route flow parity)

## Common failure scenarios + how to diagnose

1. **`router_config_invalid`**
   - Check schema, provider ids, and `tick_mod` values.
2. **`provider_unavailable`**
   - Confirm provider availability and router `fail_if_unavailable` policy behavior.
3. **`provider_response_invalid`**
   - Validate response schema and request hash linkage.