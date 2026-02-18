# Config Files Index

## What you learn

- Which runtime config files are consumed by each subsystem.
- Which schema applies to each config file.
- Which loader function enforces schema/validation.
- Which command path consumes each config at runtime.
- Which configs are optional with defaults.
- Which files are profile sets vs singletons.

## Runtime config map

| File | Schema | Loader / module | Notes |
|---|---|---|---|
| `router/config.json` | `serverd.router.v1` | `router.rs::load_router_config` | optional, defaults to `mock` |
| `redaction/config.json` | `serverd.redaction_config.v1` | `redaction.rs::load_redaction_config` | optional, disabled by default |
| `context/policy.json` | `serverd.context_policy.v1` | `policy/context_policy.rs::load_context_policy` | optional, disabled default |
| `retrieval/config.json` | `serverd.retrieval_config.v1` | `retrieval/validation.rs::load_retrieval_config` | optional, disabled default |
| `lenses/config.json` | `serverd.lens_config.v1` | `lenses.rs::load_lens_config` | optional, disabled default |
| `modes/config.json` | `serverd.mode_config.v1` | `modes/load.rs::load_mode_config` | optional, disabled default |
| `modes/route.json` | `serverd.mode_route.v1` | `modes/load.rs::load_mode_route_config` | optional |
| `modes/profiles/<mode>.json` | `serverd.mode_profile.v1` | `modes/load.rs::load_mode_profile` | required only for selected mode |
| `tools/policy.json` | `serverd.tool_policy.v1` | `tools/policy.rs::load_policy_config` | optional, deny-by-default behavior |
| `tools/*.json` | `serverd.tool_spec.v1` | `tools/mod.rs::ToolRegistry::load_tools` | excludes `policy.json` |
| `workspace/policy.json` | `serverd.workspace_policy.v1` | `policy/workspace.rs::load_workspace_policy` | optional defaults enforced |
| `contracts/*.json` | `serverd.output_contract.v1` | `output_contract.rs::load_output_contracts` | optional registry |
| `skills/<id>/skill.json` | `serverd.skill_manifest.v1` | `skills.rs::SkillRegistry::load` | optional registry |
| `memory/config.json` | struct-based | `memory.rs::load_memory_config` | optional defaults |
| `memory/lattice_config.json` | `serverd.memory_lattice_config.v1` | `memory_lattice.rs::load_memory_lattice_config` | optional, disabled default |

## Environment-gated behavior (not file config)

- `TOOLS_ENABLE`
- `TOOLS_ARM`
- `OPEN_MEMORY_ENABLE`
- `PIE_RUNTIME_ROOT`