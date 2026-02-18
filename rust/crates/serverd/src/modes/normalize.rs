fn mode_config_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join("modes").join("config.json")
}

fn mode_profile_path(runtime_root: &Path, mode_id: &str) -> PathBuf {
    runtime_root
        .join("modes")
        .join("profiles")
        .join(format!("{}.json", mode_id))
}

fn mode_route_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join("modes").join("route.json")
}

fn normalize_mode_config(config: &mut ModeConfig) -> Result<(), ModeError> {
    if !is_safe_token(&config.default_mode) {
        return Err(ModeError::new("mode_config_invalid"));
    }
    for mode in &config.allowed_modes {
        if !is_safe_token(mode) {
            return Err(ModeError::new("mode_config_invalid"));
        }
    }
    config.allowed_modes.sort();
    config.allowed_modes.dedup();
    if config.enabled {
        if config.allowed_modes.is_empty()
            || config.max_profile_bytes == 0
            || !config
                .allowed_modes
                .iter()
                .any(|value| value == &config.default_mode)
        {
            return Err(ModeError::new("mode_config_invalid"));
        }
    }
    Ok(())
}

fn normalize_mode_route_config(config: &mut ModeRouteConfig) -> Result<(), ModeError> {
    for (skill_id, mode_id) in &config.by_skill {
        if !is_safe_token(skill_id) || !is_safe_token(mode_id) {
            return Err(ModeError::new("mode_route_invalid"));
        }
    }
    Ok(())
}

fn normalize_mode_profile(profile: &mut ModeProfile) -> Result<(), ModeError> {
    if !is_safe_token(&profile.mode_id) {
        return Err(ModeError::new("mode_profile_invalid"));
    }
    if let Some(retrieval) = profile.bias.retrieval.as_mut() {
        if let Some(namespaces) = retrieval.namespaces_allowlist.as_mut() {
            for namespace in namespaces.iter() {
                if !is_safe_token(namespace) {
                    return Err(ModeError::new("mode_profile_invalid"));
                }
            }
            namespaces.sort();
            namespaces.dedup();
        }
        if let Some(sources) = retrieval.sources.as_mut() {
            for source in sources.iter() {
                if !is_valid_retrieval_source(source) {
                    return Err(ModeError::new("mode_profile_invalid"));
                }
            }
            sources.sort();
            sources.dedup();
        }
        if let Some(recency_ticks) = retrieval.default_recency_ticks {
            if recency_ticks == 0 {
                return Err(ModeError::new("mode_profile_invalid"));
            }
        }
    }
    if let Some(lenses) = profile.bias.lenses.as_mut() {
        if let Some(allowed_lenses) = lenses.allowed_lenses.as_mut() {
            let mut parsed = Vec::with_capacity(allowed_lenses.len());
            for lens in allowed_lenses.iter() {
                let parsed_lens =
                    parse_lens_id(lens).ok_or_else(|| ModeError::new("mode_profile_invalid"))?;
                parsed.push(parsed_lens);
            }
            parsed.sort_by_key(|lens_id| lens_order_key(*lens_id));
            parsed.dedup();
            *allowed_lenses = parsed
                .into_iter()
                .map(|lens_id| lens_id.as_str().to_string())
                .collect();
        }
        if let Some(recency_ticks) = lenses.recency_ticks {
            if recency_ticks == 0 {
                return Err(ModeError::new("mode_profile_invalid"));
            }
        }
        if let Some(top_per_group) = lenses.top_per_group {
            if top_per_group == 0 {
                return Err(ModeError::new("mode_profile_invalid"));
            }
        }
        if let Some(max_candidates) = lenses.max_candidates {
            if max_candidates == 0 {
                return Err(ModeError::new("mode_profile_invalid"));
            }
        }
        if let Some(max_output_bytes) = lenses.max_output_bytes {
            if max_output_bytes == 0 {
                return Err(ModeError::new("mode_profile_invalid"));
            }
        }
    }
    if let Some(retrieval_policy) = profile.retrieval_policy.as_mut() {
        normalize_mode_retrieval_policy(retrieval_policy)?;
    }
    if let Some(lens_policy) = profile.lens_policy.as_mut() {
        normalize_mode_lens_policy(lens_policy)?;
    }
    if let Some(prompt) = profile.bias.prompt.as_mut() {
        if let Some(template_id) = prompt.template_id.as_mut() {
            if template_id.trim().is_empty() {
                return Err(ModeError::new("mode_profile_invalid"));
            }
        }
    }
    if let Some(tools) = profile.bias.tools.as_mut() {
        if let Some(deny_tools) = tools.deny_tools.as_mut() {
            normalize_tool_ids(deny_tools)?;
        }
        if let Some(require_approval_tools) = tools.require_approval_tools.as_mut() {
            normalize_tool_ids(require_approval_tools)?;
        }
        if let Some(require_arming_tools) = tools.require_arming_tools.as_mut() {
            normalize_tool_ids(require_arming_tools)?;
        }
    }
    Ok(())
}

fn normalize_tool_ids(values: &mut Vec<String>) -> Result<(), ModeError> {
    for value in values.iter() {
        if ToolId::parse(value).is_err() {
            return Err(ModeError::new("mode_tools_invalid"));
        }
    }
    values.sort();
    values.dedup();
    Ok(())
}

fn normalize_mode_retrieval_policy(policy: &mut ModeRetrievalPolicy) -> Result<(), ModeError> {
    if let Some(namespaces) = policy.allow_namespaces.as_mut() {
        for namespace in namespaces.iter() {
            if !is_safe_token(namespace) {
                return Err(ModeError::new("mode_profile_invalid"));
            }
        }
        namespaces.sort();
        namespaces.dedup();
    }
    if let Some(max_items) = policy.max_items {
        if max_items == 0 {
            return Err(ModeError::new("mode_profile_invalid"));
        }
    }
    if let Some(max_bytes) = policy.max_bytes {
        if max_bytes == 0 {
            return Err(ModeError::new("mode_profile_invalid"));
        }
    }
    Ok(())
}

fn normalize_mode_lens_policy(policy: &mut ModeLensPolicy) -> Result<(), ModeError> {
    if let Some(require_lenses) = policy.require_lenses.as_mut() {
        *require_lenses = canonicalize_lens_ids(require_lenses)?;
    }
    if let Some(forbid_lenses) = policy.forbid_lenses.as_mut() {
        *forbid_lenses = canonicalize_lens_ids(forbid_lenses)?;
    }
    if let Some(max_candidates) = policy.max_candidates {
        if max_candidates == 0 {
            return Err(ModeError::new("mode_profile_invalid"));
        }
    }
    if let Some(max_output_bytes) = policy.max_output_bytes {
        if max_output_bytes == 0 {
            return Err(ModeError::new("mode_profile_invalid"));
        }
    }
    Ok(())
}

