# State GSAMA

## What you learn

- The authoritative GSAMA state model in this repo.
- How state deltas are encoded as deterministic artifacts.
- Where state hash transitions are emitted in audit.
- How route/null/replay all converge on the same delta-apply path.
- Which fail reasons indicate state artifact or persistence problems.
- Which tests prove state transition determinism.

## Purpose

Represent and evolve authoritative runtime state (`GsamaState`) through explicit `StateDelta` application.

## Threat model / what it prevents

- Hidden in-memory mutation bypassing audited delta flow.
- Non-replayable transitions due to implicit state changes.
- Ambiguous delta interpretation.

## Inputs and outputs (artifact refs)

| Direction | Artifact | Path |
|---|---|---|
| In | state snapshot | `state/gsama_state.json` |
| In | delta artifact ref | `sha256:<...>` |
| Out | delta artifact | `artifacts/state_deltas/<hash>.json` |
| Out | updated state snapshot | `state/gsama_state.json` |

## Audit events emitted

- `state_snapshot_loaded`
- `state_delta_proposed`
- `state_delta_artifact_written`
- `state_delta_applied`
- `tick_completed`

## Fail-closed reasons

- `state_load_failed`
- `state_delta_artifact_invalid`
- `state_delta_artifact_hash_failed`
- `state_delta_artifact_write_failed`
- `state_delta_artifact_read_failed`
- `state_delta_artifact_conflict`

## Determinism guarantees

- Delta artifact body is canonical JSON with explicit `kind` + `params`.
- Delta ref is content hash of canonical artifact.
- Apply path reconstructs delta from artifact, then applies pure `apply_delta(...)`.

## Config file(s) + schema(s)

| File | Schema |
|---|---|
| state snapshot (`GsamaState`) | Rust struct in `state/src/lib.rs` |
| delta artifact | `serverd.state_delta_artifact.v1` |

## Core enforcement points (functions + file paths)

- `state/src/lib.rs::apply_delta`
- `state_delta_artifact.rs::write_delta_artifact`
- `state_delta_artifact.rs::apply_delta_from_artifact`
- `tick_core.rs` and `runner/mod.rs` (state lifecycle integration)

## Tests proving it

- `tests/stage1_tick.rs`
- `tests/stage4_tools.rs` (`delta_artifact_ref_deterministic_across_runtimes`, replay equivalence)
- `tests/stage15_verify_replay.rs`
- `tests/invariants_cross_runtime_replay_parity.rs`

## Common failure scenarios + how to diagnose

1. **`state_delta_artifact_invalid`**
   - Delta artifact schema/kind/params mismatch or malformed JSON.
2. **`state_delta_artifact_conflict`**
   - Existing artifact file bytes differ from canonical bytes for same hash.
3. **`state_load_failed`**
   - Missing/corrupt `state/gsama_state.json` or filesystem write/read error.