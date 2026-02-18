# Audit Events Index

## What you learn

- The current audit event taxonomy from `AuditEvent`.
- Which stage families each event belongs to.
- Which events are primary pivots during incident/debug flows.
- Which events are produced by mutation commands.
- How to map event names to enforcement modules.
- Where to update this index when `AuditEvent` changes.

Source of truth: `rust/crates/serverd/src/audit.rs`.

## Run lifecycle

- `run_started`
- `tick_completed`
- `run_completed`

## State + memory

- `state_snapshot_loaded`
- `observation_captured`
- `intent_selected`
- `state_delta_proposed`
- `state_delta_applied`
- `state_delta_artifact_written`
- `episode_appended`
- `working_memory_updated`
- `open_memory_mirror_written`
- `memory_lattice_built`

## Task queue/ingest/replay

- `task_received`
- `task_rejected`
- `task_accepted`
- `task_persisted`
- `task_persist_failed`
- `task_enqueued`
- `task_claimed`
- `task_applied`
- `task_already_applied`
- `task_replay_requested`
- `task_replay_loaded`
- `task_queue_scanned`

## Router/provider

- `route_selected`
- `provider_request_written`
- `provider_response_written`
- `provider_failed`

## Redaction/context/prompt

- `redaction_config_loaded`
- `provider_input_redacted`
- `context_policy_loaded`
- `context_selected`
- `prompt_built`

## Retrieval/lenses/modes

- `retrieval_config_loaded`
- `retrieval_query_written`
- `retrieval_executed`
- `retrieval_results_written`
- `retrieval_failed`
- `lens_config_loaded`
- `lens_plan_built`
- `lens_set_selected`
- `lens_executed`
- `lens_outputs_written`
- `lens_failed`
- `mode_config_loaded`
- `mode_profile_selected`
- `mode_routed`
- `mode_applied`
- `mode_policy_applied`
- `mode_failed`

## Contracts/tools/workspace

- `output_contract_loaded`
- `provider_output_validated`
- `provider_output_rejected`
- `tool_execution_denied`
- `tool_approval_required`
- `tool_selected`
- `tool_call_written`
- `tool_executed`
- `tool_output_written`
- `workspace_policy_loaded`
- `workspace_violation`

## Capsule/explain/mutations

- `run_capsule_written`
- `explain_written`
- `explain_failed`
- `approval_created`
- `learning_appended`
- `capsule_exported`
- `skill_selected`
- `skill_learning_appended`

