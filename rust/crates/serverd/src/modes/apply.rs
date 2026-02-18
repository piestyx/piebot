pub fn apply_mode_profile(
    mode_id: &str,
    profile: &ModeProfile,
    input: &ModeApplyInput<'_>,
) -> Result<EffectiveMode, ModeError> {
    if profile.mode_id != mode_id {
        return Err(ModeError::new("mode_profile_invalid"));
    }
    let mut retrieval_config =
        apply_retrieval_bias(input.base_retrieval, profile.bias.retrieval.as_ref())?;
    let mut lens_config = apply_lens_bias(input.base_lenses, profile.bias.lenses.as_ref())?;
    apply_retrieval_policy(&mut retrieval_config, profile.retrieval_policy.as_ref())?;
    apply_lens_policy(&mut lens_config, profile.lens_policy.as_ref())?;
    let mode_policy_hash = compute_mode_policy_hash(
        profile.retrieval_policy.as_ref(),
        profile.lens_policy.as_ref(),
        &retrieval_config,
        &lens_config,
    )?;
    let prompt_template_ref = resolve_prompt_template_bias(
        input.runtime_root,
        input.base_prompt_template_refs,
        profile.bias.prompt.as_ref(),
    )?;
    let tool_constraints =
        resolve_tool_constraints(input.runtime_root, profile.bias.tools.as_ref())?;
    let mode_hash = compute_mode_hash(
        mode_id,
        &retrieval_config,
        &lens_config,
        prompt_template_ref.as_deref(),
        &tool_constraints,
    )?;
    let applied_artifact = ModeAppliedArtifact {
        schema: MODE_APPLIED_SCHEMA.to_string(),
        mode_id: mode_id.to_string(),
        retrieval_config: retrieval_config.clone(),
        lens_config: lens_config.clone(),
        retrieval_policy: profile.retrieval_policy.clone(),
        lens_policy: profile.lens_policy.clone(),
        mode_policy_hash: mode_policy_hash.clone(),
        prompt_template_ref: prompt_template_ref.clone(),
        tool_constraints: tool_constraints.clone(),
        mode_hash: mode_hash.clone(),
    };
    Ok(EffectiveMode {
        mode_id: mode_id.to_string(),
        retrieval_config,
        lens_config,
        mode_policy_hash,
        prompt_template_ref,
        tool_constraints,
        mode_hash,
        applied_artifact,
    })
}

