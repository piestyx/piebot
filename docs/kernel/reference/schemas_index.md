# Schemas Index

## What you learn

- The canonical schema strings currently used by kernel/runtime modules.
- Which file owns each schema constant.
- Which artifact/config category each schema belongs to.
- How to jump from schema to enforcement module quickly.
- Which schemas are subsystem-critical for fail-closed logic.
- Where to add new entries when new schemas are introduced.

## Core schemas

| Schema | Category | Defining module |
|---|---|---|
| `serverd.audit.v1` | audit envelope | `serverd/src/audit.rs` |
| `serverd.router.v1` | router config | `serverd/src/router.rs` |
| `serverd.provider_request.v1` | provider artifact | `serverd/src/provider.rs` |
| `serverd.provider_response.v1` | provider artifact | `serverd/src/provider.rs` |
| `serverd.provider_output.v1` | provider output payload | `serverd/src/provider.rs` |
| `serverd.provider_input.v1` | provider input payload | `serverd/src/provider.rs` |
| `serverd.provider_constraints.v1` | provider constraints payload | `serverd/src/provider.rs` |
| `serverd.redaction_config.v1` | redaction config | `serverd/src/redaction.rs` |
| `serverd.context_selection.v1` | context selection artifact | `serverd/src/context.rs` |
| `serverd.context_policy.v1` | context policy config | `serverd/src/policy/context_policy.rs` |
| `serverd.prompt_template.v1` | prompt template artifact | `serverd/src/prompt.rs` |
| `serverd.prompt.v1` | prompt artifact | `serverd/src/prompt.rs` |
| `serverd.output_contract.v1` | output contract config | `serverd/src/output_contract.rs` |
| `serverd.tool_spec.v1` | tool spec | `serverd/src/tools/mod.rs` |
| `serverd.tool_registry.v1` | tool registry snapshot | `serverd/src/tools/mod.rs` |
| `serverd.tool_policy.v1` | tool policy config | `serverd/src/tools/policy.rs` |
| `serverd.tool_approval_request.v1` | approval request artifact | `serverd/src/tools/policy.rs` |
| `serverd.tool_approval.v1` | approval artifact | `serverd/src/tools/policy.rs` |
| `serverd.tool_call.v1` | tool call artifact | `serverd/src/tools/execute.rs` |
| `serverd.tool_input.noop.v1` | noop tool input payload | `serverd/src/tools/execute.rs` |
| `serverd.tool_input.fs_probe.v1` | fs_probe tool input payload | `serverd/src/tools/execute.rs` |
| `serverd.tool_output.v1` | tool output artifact | `serverd/src/tools/execute.rs` |
| `serverd.tool_output.noop.v1` | noop tool output payload | `serverd/src/tools/execute.rs` |
| `serverd.tool_output.fs_probe.v1` | fs_probe tool output payload | `serverd/src/tools/execute.rs` |
| `serverd.retrieval_config.v1` | retrieval config | `serverd/src/retrieval/types.rs` |
| `serverd.retrieval_query.v1` | retrieval query artifact | `serverd/src/retrieval/types.rs` |
| `serverd.retrieval_results.v1` | retrieval results artifact | `serverd/src/retrieval/types.rs` |
| `serverd.context_pointer.v1` | gsama context pointer artifact | `serverd/src/retrieval/types.rs` |
| `serverd.lens_config.v1` | lens config | `serverd/src/lenses.rs` |
| `serverd.lens_plan.v1` | lens plan artifact | `serverd/src/lenses.rs` |
| `serverd.lens_set_selected.v1` | lens set artifact | `serverd/src/lenses.rs` |
| `serverd.lens_outputs.v1` | lens output artifact | `serverd/src/lenses.rs` |
| `serverd.mode_config.v1` | mode config | `serverd/src/modes/types.rs` |
| `serverd.mode_profile.v1` | mode profile | `serverd/src/modes/types.rs` |
| `serverd.mode_route.v1` | mode route config | `serverd/src/modes/types.rs` |
| `serverd.mode_applied.v1` | mode applied artifact | `serverd/src/modes/types.rs` |
| `serverd.workspace_policy.v1` | workspace policy | `serverd/src/policy/workspace.rs` |
| `serverd.state_delta_artifact.v1` | state delta artifact | `serverd/src/state_delta_artifact.rs` |
| `serverd.run_capsule.v1` | run capsule artifact | `serverd/src/capsule/run_capsule.rs` |
| `serverd.explain.v1` | explain artifact | `serverd/src/runtime/explain.rs` |
| `serverd.skill_manifest.v1` | skill manifest | `serverd/src/skills.rs` |
| `serverd.task_status.v1` | task status file | `serverd/src/task/task_status.rs` |
| `serverd.learning_entry.v1` | learning entry append payload | `serverd/src/mutations.rs` |
| `serverd.memory_lattice_config.v1` | lattice config | `serverd/src/memory_lattice.rs` |
| `serverd.memory_lattice.v1` | lattice artifact | `serverd/src/memory_lattice.rs` |
| `serverd.episode.v1` | episodic record | `serverd/src/memory.rs` |
| `serverd.working_memory.v1` | working memory snapshot | `serverd/src/memory.rs` |

## GSAMA supporting schema

| Schema | Module |
|---|---|
| `gsama.store_snapshot.v1` | `gsama_core` crate (`STORE_SNAPSHOT_SCHEMA`) |
| `gsama.semantic_vector.v1` | `gsama_encoder` crate |