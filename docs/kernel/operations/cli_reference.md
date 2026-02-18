# CLI Reference

## What you learn

- Which top-level commands `serverd` currently supports.
- Which flags belong to each command.
- How run modes differ from subcommands.
- Which commands emit mutation audit events.
- Which command combinations are invalid.
- Where argument parsing behavior is implemented.

## Parser source

`rust/crates/serverd/src/cli.rs`

## Run command (default)

Without subcommand, CLI parses run args and executes:
    - `--mode null|route`
    - `--runtime <path>`
    - `--delta <tick:N|tag:k=v>`
    - `--ticks <u64>`
    - `--skill <skill_id>` (route only)
    - `--mode-profile <mode_id>` (route only)

## Subcommands

### verify

- `serverd verify --runtime <path> [--memory] [--run-id <sha256:...>]`

### ingest

- `serverd ingest --runtime <path> [--stdin | --in <file>]`

### replay

- `serverd replay --runtime <path> --task <task_id>`

### explain

- `serverd explain --runtime <path> (--capsule <sha256:...> | --run <sha256:...>)`

### approve

- `serverd approve --runtime <path> --tool <tool_id> --input-ref <sha256:...> [--run-id <sha256:...>]`

### learn

- `serverd learn --runtime <path> --text <text> [--tags <a,b,c>] [--source <token>]`

### capsule export

- `serverd capsule export --runtime <path> --run-id <sha256:...> [--out <relative-or-exports-scoped-path>]`

## Invalid flag enforcement

Parser rejects cross-command flags (for example `--ticks` on `verify`) and mixed explain targets (`--capsule` + `--run` together).

## Command handlers

- Run/null/route/replay/ingest/verify: `runner/mod.rs`
- Explain: `runtime/explain.rs`
- Approve/learn/capsule export: `mutations.rs`

