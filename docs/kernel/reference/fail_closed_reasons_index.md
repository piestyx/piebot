# Fail-Closed Reasons Index

## What you learn

- A practical index of fail-closed reason strings used by kernel subsystems.
- Which module owns each reason family.
- Which reasons map to policy denial vs schema/IO failures.
- Where to find matching tests for major reason families.
- How to triage by reason prefix quickly.
- Which reasons are especially high-signal for security posture.

This index is implementation-aligned but grouped for operator use.

## Shared artifact layer

| Reason(s) | Module(s) |
|---|---|
| `artifact_hash_failed`, `artifact_write_failed`, `artifact_read_failed`, `artifact_conflict` | `runtime/artifacts.rs` |

## Router/provider

| Reason(s) | Module(s) |
|---|---|
| `router_config_read_failed`, `router_config_invalid` | `router.rs` |
| `provider_unavailable`, `provider_request_invalid`, `provider_response_invalid`, `provider_output_missing` | `route/provider_phase.rs`, `provider.rs` |
| `provider_input_write_failed`, `provider_output_ref_missing` | `route/provider_phase.rs`, `provider.rs` |

## Redaction/context/prompt

| Reason(s) | Module(s) |
|---|---|
| `redaction_config_read_failed`, `redaction_config_invalid`, `redaction_failed`, `redaction_limit_exceeded` | `redaction.rs` |
| `context_policy_read_failed`, `context_policy_invalid`, `context_policy_override_invalid` | `policy/context_policy.rs` |
| `context_namespace_denied`, `context_selection_exceeds_max_items`, `context_selection_exceeds_max_bytes`, `context_selection_failed` | `policy/context_policy.rs` |
| `prompt_build_failed`, `prompt_write_failed` | `route/provider_phase.rs` |

## Output contracts

| Reason(s) | Module(s) |
|---|---|
| `output_contract_invalid`, `output_contract_not_found` | `output_contract.rs`, route integration |
| `provider_output_validation_failed`, `provider_output_invalid`, `provider_output_contract_violation` | `output_contract.rs` |

## Tools/skill/workspace

| Reason(s) | Module(s) |
|---|---|
| `tools_disabled`, `tool_not_allowed`, `tool_requires_arming`, `tool_approval_required`, `tool_approval_invalid` | `tools/policy.rs`, route integration |
| `tool_spec_missing`, `tool_spec_invalid`, `tool_policy_invalid` | `tools/mod.rs`, `tools/policy.rs` |
| `tool_call_invalid`, `tool_input_invalid`, `tool_input_read_failed`, `tool_output_invalid`, `tool_not_implemented` | `tools/execute.rs` |
| `skill_tool_not_allowed`, `skill_tool_constraint_failed`, `skill_tool_input_invalid`, `skill_tool_input_unreadable` | `skills.rs` |
| `workspace_disabled`, `workspace_root_invalid`, `workspace_repo_root_disallowed`, `workspace_path_traversal`, `workspace_path_escape`, `workspace_symlink_escape`, `workspace_path_nonexistent`, `workspace_canonicalize_failed`, `workspace_policy_invalid`, `workspace_policy_read_failed` | `policy/workspace.rs` |

## Retrieval/lenses/modes

| Reason(s) | Module(s) |
|---|---|
| `retrieval_config_read_failed`, `retrieval_config_invalid`, `retrieval_query_invalid`, `retrieval_namespace_denied`, `retrieval_source_unavailable`, `retrieval_selection_exceeds_max_items`, `retrieval_selection_exceeds_max_bytes`, `retrieval_failed` | `retrieval/*` |
| `gsama_query_vector_missing`, `gsama_query_vector_dim_mismatch`, `gsama_write_vector_missing`, `gsama_write_input_invalid`, `gsama_store_not_found`, `gsama_store_read_failed`, `gsama_store_invalid`, `gsama_store_load_failed`, `gsama_store_dim_mismatch`, `gsama_store_capacity_mismatch`, `gsama_store_write_failed`, `gsama_store_serialize_failed`, `gsama_dir_create_failed`, `gsama_retrieval_failed`, `replay_requires_existing_gsama_store` | `retrieval/*` |
| `lens_config_read_failed`, `lens_config_invalid`, `lens_plan_invalid`, `lens_plan_empty_selection`, `lens_selection_invalid`, `lens_requires_retrieval`, `lens_output_exceeds_max_candidates`, `lens_output_exceeds_max_bytes`, `lens_failed` | `lenses.rs`, route integration |
| `mode_config_invalid`, `mode_route_invalid`, `mode_not_allowed`, `mode_profile_missing`, `mode_profile_invalid`, `mode_profile_too_large`, `mode_policy_loosen_attempt`, `mode_policy_empty_intersection`, `mode_prompt_template_missing`, `mode_tools_invalid`, `mode_retrieval_empty_allowlist`, `mode_retrieval_empty_sources`, `mode_lenses_cannot_enable`, `mode_lens_empty` | `modes/*`, runner integration |

## State/memory/capsule/explain

| Reason(s) | Module(s) |
|---|---|
| `state_load_failed`, `state_delta_artifact_invalid`, `state_delta_artifact_hash_failed`, `state_delta_artifact_write_failed`, `state_delta_artifact_read_failed`, `state_delta_artifact_conflict` | `runner/mod.rs`, `state_delta_artifact.rs` |
| `memory_config_*`, `episode_*`, `working_snapshot_*`, `open_memory_write_failed` | `memory.rs` |
| `memory_lattice_config_invalid`, `memory_lattice_source_missing`, `memory_lattice_exceeds_max_items`, `memory_lattice_exceeds_max_bytes`, `memory_lattice_build_failed` | `memory_lattice.rs` |
| `run_capsule_build_failed`, `run_capsule_write_failed` | `capsule/run_capsule.rs` |
| `explain_input_invalid`, `explain_build_failed`, `explain_write_failed` | `runtime/explain.rs` |

