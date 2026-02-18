# Audit Log Integrity

## What you learn

- How the audit hash chain is built and verified.
- What constitutes a broken chain.
- Which algorithm versions are supported.
- How run-window filtering avoids mixed-run analysis.
- Which serverd paths consume audit events.
- Which tests verify integrity expectations.

## Hash-chain implementation

- Module: `rust/crates/audit_log/src/lib.rs`
- Writer: `AuditAppender::append`
- Verifier: `verify_log`

Each record stores:
    - `prev_hash`
    - canonicalized `event`
    - `hash` of `{ prev_hash, event }` (algo v2), or legacy v1 compatibility hash

## Integrity checks

`verify_log` fails on:
    - `HashChainBroken` (prev/hash mismatch),
    - unknown algo version,
    - malformed JSON.

`serverd` uses `verify_log` before success output in `audit.rs::succeed_run`.

## Run-window filtering

`audit.rs::filter_events_for_run` enforces a clean `run_started ... run_completed` window for a run id. This is used by explain (`runtime/explain.rs`) to prevent mixed-run findings.

## Audit events as schema

Event variants and payload fields are centralized in `serverd/src/audit.rs::AuditEvent`.

## Tests proving integrity behavior

- `tests/stage11_explain.rs` (`explain_does_not_mix_runs_in_same_runtime_root`)
- `tests/stage15_verify_replay.rs` and `tests/verify_cmd.rs` (verify/replay paths reading audit)
- `audit.rs` unit tests for run-window filtering invariants

