# Modes

## What you learn

- How mode selection is resolved (default, route-by-skill, explicit override).
- How mode profile biases and policies modify retrieval/lens/prompt/tools behavior.
- How strictness-only mode policy binding is enforced.
- Which mode artifacts and events are emitted.
- Which reasons indicate invalid profile/config or policy loosening attempts.
- Which tests verify mode determinism and fail-closed semantics.

## Purpose

Apply constrained runtime overlays for retrieval, lenses, prompt template selection, and tool constraints without relaxing base policy.

## Threat model / what it prevents

- Unapproved mode ids.
- Profile files that widen capabilities (`mode_policy_loosen_attempt`).
- Empty intersections after tightening (`mode_policy_empty_intersection`).
- Invalid prompt template references in mode bias.

## Inputs and outputs (artifact refs)

| Direction | Artifact | Path |
|---|---|---|
| In | mode config | `modes/config.json` |
| In | route-by-skill map | `modes/route.json` |
| In | profile | `modes/profiles/<mode_id>.json` |
| Out | mode config/profile/route artifacts | `artifacts/mode_configs`, `mode_profiles`, `mode_routes` |
| Out | mode applied artifact | `artifacts/mode_applied/<hash>.json` |

## Audit events emitted

- `mode_config_loaded`
- `mode_routed`
- `mode_profile_selected`
- `mode_applied`
- `mode_policy_applied`
- `mode_failed`

## Fail-closed reasons

- Config/route/profile: `mode_config_invalid`, `mode_route_invalid`, `mode_not_allowed`, `mode_profile_missing`, `mode_profile_invalid`, `mode_profile_too_large`
- Bias/policy: `mode_retrieval_empty_allowlist`, `mode_retrieval_empty_sources`, `mode_lenses_cannot_enable`, `mode_lens_empty`, `mode_prompt_template_missing`, `mode_tools_invalid`, `mode_policy_loosen_attempt`, `mode_policy_empty_intersection`
- Cross-subsystem interaction: `lens_requires_retrieval`

## Determinism guarantees

- Mode ids/allowlists/sources/lenses are normalized and sorted.
- Effective mode hash computed from final constrained config.
- Mode-applied artifact bytes are deterministic across runtimes for same inputs.
- Explicit `--mode-profile` override deterministically suppresses skill-route selection.

## Config file(s) + schema(s)

| File | Schema |
|---|---|
| `runtime/modes/config.json` | `serverd.mode_config.v1` |
| `runtime/modes/route.json` | `serverd.mode_route.v1` |
| `runtime/modes/profiles/<id>.json` | `serverd.mode_profile.v1` |
| mode applied artifact | `serverd.mode_applied.v1` |

## Core enforcement points (functions + file paths)

- `modes/load.rs` (config/route/profile load + selection)
- `modes/normalize.rs` (validation + canonicalization)
- `modes/policy.rs` (strictness-only policy application)
- `modes/apply.rs::apply_mode_profile`
- Integration: `runner/mod.rs` (mode lifecycle and event emission)

## Tests proving it

- `tests/modes.rs`
- `tests/stage17_mode_policy_binding.rs`
- `tests/stage18_lens_plan.rs` (mode policy hash propagation into lens plan)

## Common failure scenarios + how to diagnose

1. **`mode_not_allowed`**
   - Selected/route-derived mode not in `allowed_modes`.
2. **`mode_policy_loosen_attempt`**
   - Profile policy attempts to increase limits or enable disabled base capability.
3. **`mode_prompt_template_missing`**
   - Mode prompt bias references template not in skill prompt refs or missing artifact.