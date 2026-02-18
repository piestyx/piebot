# Explain

## What you learn

- How explain artifacts are built from capsule + run-window audit events.
- How `--capsule` vs `--run` targets are resolved.
- Which findings/actions are currently derived.
- Which safety checks prevent mixed-run explain output.
- Which audit events are emitted by explain command.
- Which tests prove determinism and secrecy constraints.

## Purpose

Generate deterministic, auditable diagnosis artifacts (`serverd.explain.v1`) from run capsule and audit evidence.

## Threat model / what it prevents

- Cross-run contamination of findings.
- Explain generation from invalid/missing capsule input.
- Silent explain write conflicts.

## Inputs and outputs (artifact refs)

| Direction | Artifact | Path |
|---|---|---|
| In | run capsule | `artifacts/run_capsules/<hash>.json` |
| In | audit log | `logs/audit_rust.jsonl` |
| Out | explain artifact | `artifacts/explains/<hash>.json` |

## Audit events emitted

- `explain_written`
- `explain_failed`

## Fail-closed reasons

- `explain_input_invalid`
- `explain_build_failed`
- `explain_write_failed`

## Determinism guarantees

- Explain findings/actions are sorted/deduped.
- Related refs/hashes are normalized and sorted.
- Explain artifact uses canonical JSON hash-addressed write semantics.
- Run-window filtering ensures deterministic scope from `run_started` to `run_completed`.

## Config file(s) + schema(s)

| Artifact | Schema |
|---|---|
| explain artifact | `serverd.explain.v1` |

Inputs validated against:
   - capsule schema `serverd.run_capsule.v1`
   - audit event structure from `audit.rs`.

## Core enforcement points (functions + file paths)

- `runtime/explain.rs::resolve_explain_context`
- `runtime/explain.rs::build_explain`
- `runtime/explain.rs::write_explain`
- `audit.rs::filter_events_for_run`

## Tests proving it

- `tests/stage11_explain.rs`
- `tests/stage_gate_7_12.rs`

## Common failure scenarios + how to diagnose

1. **`explain_input_invalid`**
   - Bad capsule ref, missing capsule, malformed audit, or inconsistent run-window data.
2. **`explain_write_failed`**
   - Filesystem conflict/write error in `artifacts/explains`.
3. **Unexpected mixed findings**
   - Validate run-window filtering and check duplicate/invalid `run_completed` boundaries.