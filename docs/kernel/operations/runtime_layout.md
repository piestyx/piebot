# Runtime Layout

## What you learn

- The runtime directory contract expected by `serverd`.
- Which paths are authoritative state vs derived artifacts.
- Where audit logs, task files, and policy/config files are read from.
- Which directories are append-only vs overwritten snapshots.
- How per-run workspace directories are derived.
- Which paths are safe to inspect during debugging.

## Runtime root overview

Default runtime root is `<repo>/runtime` unless overridden by `PIE_RUNTIME_ROOT` (`cli.rs`).

## Directory map

| Path | Purpose | Writer(s) |
|---|---|---|
| `runtime/state/gsama_state.json` | authoritative GSAMA state snapshot | runner/tick core |
| `runtime/logs/audit_rust.jsonl` | append-only audit hash chain | all commands via `AuditAppender` |
| `runtime/artifacts/*` | content-addressed artifacts by phase | route/null/replay/explain |
| `runtime/tasks/*.json` | persisted tasks | ingest/run output persistence |
| `runtime/tasks/*.status.json` | task status tracking | queue/replay flows |
| `runtime/memory/episodes/*` | episodic records + head pointer | tick core |
| `runtime/memory/working.json` | working memory snapshot | tick core |
| `runtime/memory/gsama/store_snapshot.json` | GSAMA vector store snapshot | retrieval gsama mode |
| `runtime/workspace/*` | workspace policy + run work dirs | workspace subsystem |

## Config locations

Runtime-scoped config files:
    - `router/config.json`
    - `redaction/config.json`
    - `context/policy.json`
    - `retrieval/config.json`
    - `lenses/config.json`
    - `modes/config.json`, `modes/route.json`, `modes/profiles/*.json`
    - `tools/policy.json`, `tools/*.json`
    - `workspace/policy.json`
    - `memory/config.json`, `memory/lattice_config.json`
    - `contracts/*.json`
    - `skills/<skill_id>/skill.json`

## Workspace derivation

If `workspace.per_run_dir=true`, active root is:
    - `<workspace_root>/runs/<run_id_without_sha256_prefix>`

Enforced by `policy/workspace.rs`.

## Safety notes

- Audit log and artifact folders are evidence surfaces; avoid manual edits.
- Task files/status files can be read during debugging, but keep task IDs stable.
- Capsule/explain exports should use CLI commands to preserve audit attribution.

