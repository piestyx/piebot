  
[![OS](https://img.shields.io/badge/OS-Linux-0078D4)](https://kernel.org)  [![language](https://img.shields.io/badge/language-rust-000000)](https://rust-lang.org/learn/)  [![GitHub last commit](https://img.shields.io/github/last-commit/piestyx/piebot)](https://github.com/piestyx/piebot/commits/main/)


# pieBot

pieBot is a local‑first, Rust‑authoritative agent execution substrate. Models are untrusted compute accelerators; the Rust control plane owns state, policy, tools, audit, and artifacts. The system is the agent. 

## Design Principles

- **Determinism by construction** — all hashes use canonical JSON + SHA256; artifacts avoid wall‑clock timestamps, so identical inputs/configs yield identical refs.
- **Hashes are identities** — artifacts, episodes, capsules, explains, and audit records are addressed by hash; content is only accessed via explicit artifacts.
- **Fail‑closed semantics** — invalid config, policy violations, contract failures, or IO errors abort the run with stable reason codes.
- **Tool‑only side effects** — tools are the only mutation channel; policy + approval + env gates (`TOOLS_ENABLE`, `TOOLS_ARM`) enforce this.
- **Provider boundary** — model I/O is only via request/response artifacts; audit contains refs only. Default providers are local mocks.
- **Redaction before egress** — provider inputs are minimized/redacted and written as artifacts; the redacted input ref is what the provider receives.
- **Context + prompt as artifacts** — context policy bounds selection; prompt templates and prompts are artifacts with stable hashes.
- **Output contracts** — provider outputs are schema‑validated before any tool parsing/execution.
- **Provenance artifacts** — run capsules bind the run's refs/hashes; explain artifacts are deterministic, secrets‑safe derivatives of audit + capsule.
- **Workspace hygiene** — filesystem access is scoped and canonicalized to prevent traversal and symlink escape.
- **Mode overlays** — executive policy profiles can tighten (never loosen) retrieval, lenses, prompts, and tool restrictions.
- **TUI is observation‑only** — the operator terminal UI never owns authority or mutates runtime directly.

## Rust-native GSAMA Implementation

- `gsama_core` provides:
  - L2-normalized vector storage
  - deterministic entry IDs + head hash evolution
  - deterministic eviction and retrieval ordering
  - snapshot load/save for replayable persistence
- `gsama_encoder` provides:
  - deterministic structural/dynamical/salience view composition
  - hash-based text embedding fallback (kernel-pure, no model dependency)
  - deterministic state/query projection utilities
- `serverd` integrations provide:
  - `retrieval.kind = "gsama"` for vector retrieval
  - GSAMA store persistence at `runtime/memory/gsama/store_snapshot.json`
  - fail-closed query/vector dimension checks and config validation

## Quickstart

### Build

```bash
# Build serverd (main daemon)
cargo build -p serverd --manifest-path rust/Cargo.toml
```

### Run serverd

Run a minimal local route tick (uses in‑tree mocks; no network):

```bash
cargo run -p serverd --manifest-path rust/Cargo.toml -- \
  --mode route --ticks 1 --delta "tick:0" --runtime runtime
```

Run with a specific mode profile:

```bash
cargo run -p serverd --manifest-path rust/Cargo.toml -- \
  --mode route --ticks 1 --delta "tick:0" --runtime runtime \
  --mode-id focused
```

Generate an explain artifact for a run:

```bash
cargo run -p serverd --manifest-path rust/Cargo.toml -- \
  explain --runtime runtime --run <run_id>
```

## Tests

All tests:

```bash
# All serverd tests
cargo test -p serverd --manifest-path rust/Cargo.toml
```

Core stage proof tests:

```bash
# Foundation (Stages 0–6)
cargo test -p serverd --manifest-path rust/Cargo.toml --test stage2_memory
cargo test -p serverd --manifest-path rust/Cargo.toml --test stage3_router
cargo test -p serverd --manifest-path rust/Cargo.toml --test stage4_tools
cargo test -p serverd --manifest-path rust/Cargo.toml --test stage5_skills
cargo test -p serverd --manifest-path rust/Cargo.toml --test stage6_end_to_end
```

## Make Targets

```bash
make setup          # Create runtime directories
make check          # Run repo checks
make build          # Build all crates
make test           # Run all tests
make test-serverd   # Run serverd tests only
make test-tui       # Run operator_tui tests only
make test-stage-7-12
make stage-gate
```

## Safety Switches / Environment Flags

- `TOOLS_ENABLE=1` — enables tool execution (default: off)
- `TOOLS_ARM=1` — arms tools that require arming or are high‑risk (default: off)
- `OPEN_MEMORY_ENABLE=1` — enables OpenMemory mirror writes (default: off)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Operator TUI                         │
│              (read‑only, no authority)                  │
└────────────────────────────┬────────────────────────────┘
                             │ spawns
                             ▼
┌─────────────────────────────────────────────────────────┐
│                    serverd (Rust)                       │
│           Authoritative Control Plane                   │
├───────────────┬─────────────┬─────────────┬─────────────┤
│ State (GSAMA) │    Memory   │    Tools    │    Audit    │
├───────────────┼─────────────┼─────────────┼─────────────┤
│   Retrieval   │    Lenses   │    Modes    │  Contracts  │
└───────┴───────┴──────┴──────┴──────┴──────┴──────┴──────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────┐
│              Provider (MockProvider)                    │
│                 (untrusted worker)                      │
└─────────────────────────────────────────────────────────┘
```

## License

See LICENSE file.