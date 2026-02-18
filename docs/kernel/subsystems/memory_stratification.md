# Memory Stratification

## What you learn

- How episodic, working, and open-memory mirror layers are represented.
- How memory lattice summarization is built and capped.
- Which audit events indicate memory mutation vs projection.
- How TTL/capacity eviction works in working memory.
- Which reasons fail closed for memory/memory-lattice paths.
- Which tests prove deterministic memory behavior.

## Purpose

Maintain replayable memory layers:
   - episodic chain (append-only, hashed),
   - working memory snapshot (bounded, TTL-based),
   - optional open-memory mirror,
   - optional memory lattice summary artifact.

## Threat model / what it prevents

- Non-deterministic or lossy memory transitions.
- Unbounded working memory growth.
- Invalid episodic chains or snapshot corruption.
- Oversized lattice outputs.

## Inputs and outputs (artifact refs)

| Layer | Files/artifacts |
|---|---|
| Episodic | `memory/episodes/<hash>.json`, `memory/episodes/head` |
| Working | `memory/working.json` |
| Open mirror (optional) | `memory/open_memory_mirror.jsonl` |
| Lattice (optional) | `artifacts/memory_lattices/<hash>.json` |

## Audit events emitted

- `episode_appended`
- `working_memory_updated`
- `open_memory_mirror_written` (when enabled)
- `memory_lattice_built` (when enabled)

## Fail-closed reasons

- Memory core: `memory_config_read_failed`, `memory_config_invalid`, `episode_not_found`, `invalid_episode`, `episode_cycle_detected`, `episode_write_failed`, `working_snapshot_*`, `open_memory_write_failed`
- Lattice: `memory_lattice_config_invalid`, `memory_lattice_source_missing`, `memory_lattice_exceeds_max_items`, `memory_lattice_exceeds_max_bytes`, `memory_lattice_build_failed`

## Determinism guarantees

- Episode hash includes canonical payload + previous hash pointer.
- Working snapshot entries are key-sorted before write.
- Working eviction follows deterministic oldest `last_touched_tick` rule.
- Lattice `ts_order` is deterministic ordinal based on canonicalized item ordering.

## Config file(s) + schema(s)

| File | Schema |
|---|---|
| `runtime/memory/config.json` | `MemoryConfig` struct (`memory.rs`) |
| `runtime/memory/lattice_config.json` | `serverd.memory_lattice_config.v1` |
| episode record | `serverd.episode.v1` |
| working snapshot | `serverd.working_memory.v1` |
| lattice artifact | `serverd.memory_lattice.v1` |

## Core enforcement points (functions + file paths)

- `memory.rs::append_episode`
- `memory.rs::load_working_memory` / `write_working_snapshot`
- `tick_core.rs` (episode + working + open mirror integration)
- `memory_lattice.rs::build_memory_lattice`
- `runner/mod.rs::maybe_build_memory_lattice`

## Tests proving it

- `tests/stage2_memory.rs`
- `tests/open_memory_mirror.rs`
- `tests/stage16_memory_lattice.rs`
- `tests/stage_gate_7_12.rs` (memory events in broader sequence)

## Common failure scenarios + how to diagnose

1. **`invalid_episode` / `episode_cycle_detected`**
   - Check episodic files for hash mismatch or pointer cycles.
2. **`working_snapshot_invalid`**
   - Check schema/value shape of `memory/working.json`.
3. **`memory_lattice_exceeds_max_bytes`**
   - Increase `max_bytes` or reduce memory source volume.

