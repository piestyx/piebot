# Context Policy and Prompt

## What you learn

- How context references are selected and policy-constrained.
- How prompt artifacts are assembled from templates + context refs.
- How skill overrides are validated against global context policy.
- Which events and artifacts are emitted.
- Which reasons fail closed for context or prompt assembly.
- Which tests cover policy/order/size behavior.

## Purpose

Construct provider-ready prompts from approved context references under explicit namespace/count/byte constraints.

## Threat model / what it prevents

- Namespace escape via context refs.
- Skill-level override widening of context permissions.
- Oversized context payloads and prompt build ambiguity.

## Inputs and outputs (artifact refs)

| Direction | Artifact | Path |
|---|---|---|
| In | policy config | `context/policy.json` |
| In | seed refs + retrieval/lens candidate refs | in-memory route phase inputs |
| Out | context selection artifact | `artifacts/contexts/<hash>.json` |
| Out | policy artifact | `artifacts/context_policies/<hash>.json` |
| Out | prompt artifact | `artifacts/prompts/<hash>.json` |

## Audit events emitted

- `context_policy_loaded`
- `context_selected`
- `prompt_built`

## Fail-closed reasons

- Policy: `context_policy_read_failed`, `context_policy_invalid`, `context_policy_override_invalid`
- Selection: `context_namespace_denied`, `context_selection_exceeds_max_items`, `context_selection_exceeds_max_bytes`, `context_selection_failed`
- Prompt assembly: `prompt_build_failed`, `prompt_write_failed`

## Determinism guarantees

- Namespace lists are sorted/deduped.
- Ordering is explicit (`lexicographic` or `stable_manifest_order`).
- Selection metrics (`total_items`, `total_bytes`) are canonicalized iteratively.
- Prompt artifact is canonical hash-addressed JSON.

## Config file(s) + schema(s)

| File | Schema |
|---|---|
| `runtime/context/policy.json` | `serverd.context_policy.v1` |
| prompt template artifact | `serverd.prompt_template.v1` |
| prompt artifact | `serverd.prompt.v1` |

## Core enforcement points (functions + file paths)

- `policy/context_policy.rs::load_context_policy`
- `policy/context_policy.rs::enforce_context_policy`
- `route/provider_phase.rs::resolve_prompt_template_text`
- `route/provider_phase.rs::resolve_context_body`
- `route/provider_phase.rs` (context/prompt write path)

## Tests proving it

- `tests/stage8_context_policy.rs`
- `tests/stage8_prompt_build.rs`
- `tests/modes.rs` (`mode_applies_prompt_template`)
- `tests/stage_gate_7_12.rs`

## Common failure scenarios + how to diagnose

1. **`context_namespace_denied`**
   - Check namespace parsed from refs and policy allowlist.
2. **`context_policy_override_invalid`**
   - Skill override exceeds policy (`allowed_context_namespaces`, max items/bytes).
3. **`prompt_build_failed`**
   - Missing or malformed template/context artifacts, schema mismatch, or canonicalization failure.