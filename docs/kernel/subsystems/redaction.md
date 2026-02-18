# Redaction

## What you learn

- How redaction config is loaded and normalized.
- How provider input minimization is enforced.
- How drop, redact, and regex strategies are applied.
- Which events signal redaction activity.
- Which reasons fail the run when redaction is invalid.
- Which tests prove deterministic redaction and limit enforcement.

## Purpose

Minimize and redact provider-bound payloads before egress, with explicit byte caps.

## Threat model / what it prevents

- Accidental provider exposure of sensitive fields.
- Oversized provider payloads.
- Invalid regex/path configs causing undefined redaction behavior.

## Inputs and outputs (artifact refs)

| Direction | Artifact | Path |
|---|---|---|
| In | redaction config | `redaction/config.json` |
| In | prompt/input candidate JSON | in-memory values in route phase |
| Out | redacted provider input | `artifacts/inputs/<hash>.json` |
| Out | config artifact ref | `artifacts/redaction_configs/<hash>.json` |

## Audit events emitted

- `redaction_config_loaded`
- `provider_input_redacted`

## Fail-closed reasons

- `redaction_config_read_failed`
- `redaction_config_invalid`
- `redaction_failed`
- `redaction_limit_exceeded`

## Determinism guarantees

- Strategy arrays are sorted in normalization (`drop_fields`, `redact_fields`, regex rules).
- Regex compile set is deterministic for a fixed config.
- Output artifacts are canonical content-hash writes.

## Config file(s) + schema(s)

| File | Schema |
|---|---|
| `runtime/redaction/config.json` | `serverd.redaction_config.v1` |

Key fields:
   - `enabled`
   - `max_provider_input_bytes`
   - `strategies.drop_fields`
   - `strategies.redact_fields`
   - `strategies.regex_redactions`
   - `strategies.allow_raw_artifacts`

## Core enforcement points (functions + file paths)

- `redaction.rs::load_redaction_config`
- `redaction.rs::compile_regex_redactions`
- `redaction.rs::minimize_provider_input_with_compiled`
- Route integration: `runner/mod.rs` and `route/provider_phase.rs`

## Tests proving it

- `tests/stage7_redaction.rs`
- `tests/stage_gate_7_12.rs`

## Common failure scenarios + how to diagnose

1. **`redaction_config_invalid`**
   - Invalid schema, zero byte cap when enabled, invalid path syntax, invalid regex pattern.
2. **`redaction_limit_exceeded`**
   - Output still exceeds `max_provider_input_bytes` after strategy application.
3. **No `provider_input_redacted` events when expected**
   - Confirm `enabled=true` and redaction config loaded event exists.