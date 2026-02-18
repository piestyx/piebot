# Output Contracts

## What you learn

- How provider output is validated before any tool execution.
- Contract file format and supported field constraints.
- How tool call permission is bound to contract config.
- Which events and reasons are emitted on rejection.
- Which module functions enforce structure and constraints.
- Which tests cover acceptance/rejection paths.

## Purpose

Ensure provider outputs are structurally safe and tool-call-authorized before downstream execution.

## Threat model / what it prevents

- Provider invents fields not in allowed schema.
- Required fields missing.
- Wrong type/range at constrained paths.
- Tool call not permitted by contract.
- Inline/ref tool input shape violations.

## Inputs and outputs (artifact refs)

| Direction | Artifact | Path |
|---|---|---|
| In | provider response | `artifacts/responses/<hash>.json` |
| In | provider output | `artifacts/outputs/<hash>.json` |
| In | contract config | `contracts/<contract_id>.json` |
| Out | contract load visibility | `output_contract_loaded` audit event |
| Out | validation outcome | `provider_output_validated` / `provider_output_rejected` |

## Audit events emitted

- `output_contract_loaded`
- `provider_output_validated`
- `provider_output_rejected`

## Fail-closed reasons

- Contract load/shape: `output_contract_invalid`
- Missing contract reference for tool-call response: `output_contract_not_found`
- Output extraction/parsing: `provider_output_validation_failed`, `provider_output_invalid`
- Semantic violations: `provider_output_contract_violation`

## Determinism guarantees

- Contract normalization sorts/dedups allowlists and fields.
- Contract hash uses canonical JSON.
- Validation rules are pure and deterministic for a given output + contract.

## Config file(s) + schema(s)

| File | Schema |
|---|---|
| `runtime/contracts/<contract_id>.json` | `serverd.output_contract.v1` |

Constraint kinds: `string`, `number`, `boolean`, `object`, `array`.

## Core enforcement points (functions + file paths)

- `output_contract.rs::load_output_contracts`
- `output_contract.rs::validate_provider_output`
- `output_contract.rs::read_output_from_response`
- Integration point: `route/provider_phase.rs` (before tool branch)

## Tests proving it

- `tests/stage9_output_contracts.rs`
- `tests/stage_gate_7_12.rs`
- `tests/modes.rs` (contract + tool path interactions)

## Common failure scenarios + how to diagnose

1. **`output_contract_not_found`**
   - Skill manifest references unknown contract id.
2. **`provider_output_contract_violation`**
   - Check field names, required fields, and constrained paths.
   - Check `allowed_tool_calls` if `tool_call` exists.
3. **`provider_output_validation_failed`**
   - Response missing `output_ref` or unreadable output artifact.