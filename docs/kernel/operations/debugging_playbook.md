# Debugging Playbook

## What you learn

- A practical sequence to debug fail-closed runs.
- Which artifacts and events to inspect first.
- How to isolate policy vs provider vs tool failures.
- How to diagnose mode/retrieval/lens interactions.
- How to use explain and verify commands safely.
- Which tests to run for regression confirmation.

## Quick triage flow

1. Capture the CLI error reason (`{ "ok": false, "error": "<reason>" }`).
2. Open latest audit tail and locate phase-local failure event (`*_failed`, `*_rejected`, `tool_execution_denied`, `workspace_violation`).
3. Follow artifact refs from the nearest preceding success event.
4. Confirm config/schema for the failing subsystem.
5. Re-run targeted tests.

## Event-first diagnosis

| Symptom | First event to inspect | Typical next artifact |
|---|---|---|
| Contract rejection | `provider_output_rejected` | `responses/<ref>`, `outputs/<ref>`, contract file |
| Tool denied | `tool_execution_denied` | `tool_calls/<ref>`, `tools/policy.json`, mode_applied |
| Workspace deny | `workspace_violation` | tool input artifact + `workspace/policy.json` |
| Retrieval failure | `retrieval_failed` | retrieval config/query/results artifacts |
| Lens failure | `lens_failed` / `lens_plan_built` | lens config/plan/set/output artifacts |
| Mode failure | `mode_failed` | mode config/route/profile/applied artifacts |

## Common command patterns

- Verify run hash:
  - `serverd verify --runtime <path> --run-id <sha256:...>`
- Build explain from run:
  - `serverd explain --runtime <path> --run <sha256:...>`
- Export capsule for offline diff:
  - `serverd capsule export --runtime <path> --run-id <sha256:...>`

## Focused regression tests

- Route stack: `stage_gate_7_12`
- Tools: `stage4_tools`, `invariants_tool_chokepoint`
- Contracts: `stage9_output_contracts`
- Workspace: `stage12_workspace`
- Retrieval/lenses/modes: `stage13_retrieval`, `stage14_lenses`, `modes`, `stage17_mode_policy_binding`, `stage18_lens_plan`
- Capsule/explain: `stage10_run_capsule`, `stage11_explain`