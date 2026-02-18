# Run Capsule

## What you learn

- What evidence is captured in `serverd.run_capsule.v1`.
- How capsule refs/hashes are computed and written.
- Which run metadata is intentionally included vs excluded.
- How tool/router/skill/context/state provenance enters the capsule.
- Which audit event confirms capsule write.
- Which tests prove capsule determinism and secrecy constraints.

## Purpose

Produce a deterministic, content-addressed run summary artifact suitable for verification and explain generation.

## Threat model / what it prevents

- Loss of provenance for run reconstruction.
- Inclusion of raw sensitive prompt/output body content in summary artifact.
- Non-deterministic run summary structure.

## Inputs and outputs (artifact refs)

| Direction | Artifact | Path |
|---|---|---|
| In | collector fields from runtime phases | in-memory `RunCapsuleCollector` |
| Out | run capsule artifact | `artifacts/run_capsules/<hash>.json` |

## Audit events emitted

- `run_capsule_written`

## Fail-closed reasons

- `run_capsule_build_failed`
- `run_capsule_write_failed`

## Determinism guarantees

- Capsule bytes are canonical JSON hashed to the artifact ref.
- Existing capsule file must byte-match for same hash.
- Optional sections (`tools`, `tool_io`, `context`, etc.) are omitted deterministically when empty.

## Config file(s) + schema(s)

| Artifact | Schema |
|---|---|
| run capsule | `serverd.run_capsule.v1` |

## Core enforcement points (functions + file paths)

- `capsule/run_capsule.rs::write_run_capsule`
- `capsule/run_capsule_collector.rs` (field collection and finalization)
- `runner/mod.rs` (capsule emission in route/null/replay/ingest paths)

## Tests proving it

- `tests/stage10_run_capsule.rs`
- `tests/stage_gate_7_12.rs`
- `tests/invariants_capsule_sufficient_verification.rs`

## Common failure scenarios + how to diagnose

1. **`run_capsule_build_failed`**
   - Usually canonicalization/serialization/hash pipeline failure.
2. **`run_capsule_write_failed`**
   - Filesystem write error or hash/path conflict with differing bytes.
3. **Missing expected provenance fields**
   - Confirm upstream collector setters were called (skill/router/tools/context/state branches).