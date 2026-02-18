fn apply_retrieval_bias(
    base: &RetrievalConfig,
    bias: Option<&ModeRetrievalBias>,
) -> Result<RetrievalConfig, ModeError> {
    let mut config = base.clone();
    let Some(bias) = bias else {
        return Ok(config);
    };
    if let Some(namespaces) = &bias.namespaces_allowlist {
        config.namespaces_allowlist = intersect_sorted(&config.namespaces_allowlist, namespaces);
        if config.enabled && config.namespaces_allowlist.is_empty() {
            return Err(ModeError::new("mode_retrieval_empty_allowlist"));
        }
    }
    if let Some(sources) = &bias.sources {
        config.sources = intersect_sorted(&config.sources, sources);
        if config.enabled && config.sources.is_empty() {
            return Err(ModeError::new("mode_retrieval_empty_sources"));
        }
    }
    if let Some(recency_ticks) = bias.default_recency_ticks {
        if recency_ticks == 0 {
            return Err(ModeError::new("mode_profile_invalid"));
        }
        config.default_recency_ticks = config.default_recency_ticks.min(recency_ticks);
    }
    Ok(config)
}

fn apply_lens_bias(
    base: &LensConfig,
    bias: Option<&ModeLensesBias>,
) -> Result<LensConfig, ModeError> {
    let mut config = base.clone();
    let Some(bias) = bias else {
        return Ok(config);
    };
    if let Some(enabled) = bias.enabled {
        if !enabled {
            config.enabled = false;
        } else if !base.enabled {
            return Err(ModeError::new("mode_lenses_cannot_enable"));
        }
    }
    if let Some(allowed_lenses) = &bias.allowed_lenses {
        config.allowed_lenses = intersect_sorted(&config.allowed_lenses, allowed_lenses);
    }
    if let Some(max_candidates) = bias.max_candidates {
        if max_candidates == 0 {
            return Err(ModeError::new("mode_profile_invalid"));
        }
        config.max_candidates = if config.max_candidates == 0 {
            max_candidates
        } else {
            config.max_candidates.min(max_candidates)
        };
    }
    if let Some(max_output_bytes) = bias.max_output_bytes {
        if max_output_bytes == 0 {
            return Err(ModeError::new("mode_profile_invalid"));
        }
        config.max_output_bytes = if config.max_output_bytes == 0 {
            max_output_bytes
        } else {
            config.max_output_bytes.min(max_output_bytes)
        };
    }
    if let Some(recency_ticks) = bias.recency_ticks {
        if recency_ticks == 0 {
            return Err(ModeError::new("mode_profile_invalid"));
        }
        let current = config.recency_ticks.unwrap_or(DEFAULT_LENS_RECENCY_TICKS);
        config.recency_ticks = Some(current.min(recency_ticks));
    }
    if let Some(top_per_group) = bias.top_per_group {
        if top_per_group == 0 {
            return Err(ModeError::new("mode_profile_invalid"));
        }
        let current = config.top_per_group.unwrap_or(DEFAULT_LENS_TOP_PER_GROUP);
        config.top_per_group = Some(current.min(top_per_group));
    }
    config.allowed_lenses = canonicalize_lens_ids(&config.allowed_lenses)?;
    if config.enabled && config.allowed_lenses.is_empty() {
        return Err(ModeError::new("mode_lens_empty"));
    }
    Ok(config)
}

fn apply_retrieval_policy(
    config: &mut RetrievalConfig,
    policy: Option<&ModeRetrievalPolicy>,
) -> Result<(), ModeError> {
    let Some(policy) = policy else {
        return Ok(());
    };
    if let Some(enabled) = policy.enabled {
        if enabled && !config.enabled {
            return Err(ModeError::new("mode_policy_loosen_attempt"));
        }
        if !enabled {
            config.enabled = false;
        }
    }
    if let Some(allow_namespaces) = policy.allow_namespaces.as_ref() {
        let base_allowlist: BTreeSet<String> =
            config.namespaces_allowlist.iter().cloned().collect();
        for namespace in allow_namespaces {
            if !base_allowlist.contains(namespace) {
                return Err(ModeError::new("mode_policy_loosen_attempt"));
            }
        }
        config.namespaces_allowlist =
            intersect_sorted(&config.namespaces_allowlist, allow_namespaces);
        if config.enabled && config.namespaces_allowlist.is_empty() {
            return Err(ModeError::new("mode_policy_empty_intersection"));
        }
    }
    if let Some(max_items) = policy.max_items {
        if max_items > config.max_items {
            return Err(ModeError::new("mode_policy_loosen_attempt"));
        }
        config.max_items = max_items;
    }
    if let Some(max_bytes) = policy.max_bytes {
        if max_bytes > config.max_bytes {
            return Err(ModeError::new("mode_policy_loosen_attempt"));
        }
        config.max_bytes = max_bytes;
    }
    Ok(())
}

fn apply_lens_policy(
    config: &mut LensConfig,
    policy: Option<&ModeLensPolicy>,
) -> Result<(), ModeError> {
    let Some(policy) = policy else {
        return Ok(());
    };
    if let Some(enabled) = policy.enabled {
        if enabled && !config.enabled {
            return Err(ModeError::new("mode_policy_loosen_attempt"));
        }
        if !enabled {
            config.enabled = false;
        }
    }
    let base_allowed = canonicalize_lens_ids(&config.allowed_lenses)?;
    if let Some(require_lenses) = policy.require_lenses.as_ref() {
        let base_set: BTreeSet<String> = base_allowed.iter().cloned().collect();
        for lens_id in require_lenses {
            if !base_set.contains(lens_id) {
                return Err(ModeError::new("mode_policy_loosen_attempt"));
            }
        }
    }
    let mut allowed = base_allowed;
    if let Some(forbid_lenses) = policy.forbid_lenses.as_ref() {
        let forbid_set: BTreeSet<String> = forbid_lenses.iter().cloned().collect();
        allowed.retain(|lens_id| !forbid_set.contains(lens_id));
    }
    if let Some(require_lenses) = policy.require_lenses.as_ref() {
        allowed = intersect_sorted(&allowed, require_lenses);
    }
    if (policy.require_lenses.is_some() || policy.forbid_lenses.is_some())
        && config.enabled
        && allowed.is_empty()
    {
        return Err(ModeError::new("mode_policy_empty_intersection"));
    }
    if !allowed.is_empty() || !config.enabled {
        config.allowed_lenses = allowed;
    }
    if let Some(max_candidates) = policy.max_candidates {
        if config.max_candidates > 0 && max_candidates > config.max_candidates {
            return Err(ModeError::new("mode_policy_loosen_attempt"));
        }
        config.max_candidates = max_candidates;
    }
    if let Some(max_output_bytes) = policy.max_output_bytes {
        if config.max_output_bytes > 0 && max_output_bytes > config.max_output_bytes {
            return Err(ModeError::new("mode_policy_loosen_attempt"));
        }
        config.max_output_bytes = max_output_bytes;
    }
    if config.enabled && config.allowed_lenses.is_empty() {
        return Err(ModeError::new("mode_policy_empty_intersection"));
    }
    Ok(())
}

fn compute_mode_policy_hash(
    retrieval_policy: Option<&ModeRetrievalPolicy>,
    lens_policy: Option<&ModeLensPolicy>,
    retrieval_config: &RetrievalConfig,
    lens_config: &LensConfig,
) -> Result<Option<String>, ModeError> {
    if retrieval_policy.is_none() && lens_policy.is_none() {
        return Ok(None);
    }
    let value = serde_json::json!({
        "retrieval_policy": retrieval_policy,
        "lens_policy": lens_policy,
        "retrieval_config": retrieval_config,
        "lens_config": lens_config
    });
    let bytes = canonical_json_bytes(&value).map_err(|_| ModeError::new("mode_profile_invalid"))?;
    Ok(Some(sha256_bytes(&bytes)))
}

fn resolve_prompt_template_bias(
    runtime_root: &Path,
    base_prompt_template_refs: &[String],
    bias: Option<&ModePromptBias>,
) -> Result<Option<String>, ModeError> {
    let Some(bias) = bias else {
        return Ok(None);
    };
    let Some(template_ref) = bias.template_id.as_ref() else {
        return Ok(None);
    };
    if !base_prompt_template_refs
        .iter()
        .any(|value| value == template_ref)
    {
        return Err(ModeError::new("mode_prompt_template_missing"));
    }
    if !prompt_template_exists(runtime_root, template_ref)? {
        return Err(ModeError::new("mode_prompt_template_missing"));
    }
    Ok(Some(template_ref.clone()))
}

fn resolve_tool_constraints(
    runtime_root: &Path,
    bias: Option<&ModeToolsBias>,
) -> Result<ModeToolConstraints, ModeError> {
    let Some(bias) = bias else {
        return Ok(ModeToolConstraints::default());
    };
    let mut constraints = ModeToolConstraints {
        deny_tools: bias.deny_tools.clone().unwrap_or_default(),
        require_approval_tools: bias.require_approval_tools.clone().unwrap_or_default(),
        require_arming_tools: bias.require_arming_tools.clone().unwrap_or_default(),
    };
    constraints.deny_tools.sort();
    constraints.deny_tools.dedup();
    constraints.require_approval_tools.sort();
    constraints.require_approval_tools.dedup();
    constraints.require_arming_tools.sort();
    constraints.require_arming_tools.dedup();
    if constraints.deny_tools.is_empty()
        && constraints.require_approval_tools.is_empty()
        && constraints.require_arming_tools.is_empty()
    {
        return Ok(constraints);
    }
    let registry =
        ToolRegistry::load_tools(runtime_root).map_err(|_| ModeError::new("mode_tools_invalid"))?;
    let mut all_ids: BTreeSet<String> = BTreeSet::new();
    all_ids.extend(constraints.deny_tools.iter().cloned());
    all_ids.extend(constraints.require_approval_tools.iter().cloned());
    all_ids.extend(constraints.require_arming_tools.iter().cloned());
    for tool_id in all_ids {
        let parsed = ToolId::parse(&tool_id).map_err(|_| ModeError::new("mode_tools_invalid"))?;
        if registry.get(&parsed).is_none() {
            return Err(ModeError::new("mode_tools_invalid"));
        }
    }
    Ok(constraints)
}

fn compute_mode_hash(
    mode_id: &str,
    retrieval_config: &RetrievalConfig,
    lens_config: &LensConfig,
    prompt_template_ref: Option<&str>,
    tool_constraints: &ModeToolConstraints,
) -> Result<String, ModeError> {
    let value = serde_json::json!({
        "mode_id": mode_id,
        "retrieval_config": retrieval_config,
        "lens_config": lens_config,
        "prompt_template_ref": prompt_template_ref,
        "tool_constraints": tool_constraints
    });
    let bytes = canonical_json_bytes(&value).map_err(|_| ModeError::new("mode_profile_invalid"))?;
    Ok(sha256_bytes(&bytes))
}

fn prompt_template_exists(runtime_root: &Path, template_ref: &str) -> Result<bool, ModeError> {
    let (namespace, artifact_ref) = split_artifact_ref(template_ref, "prompt_templates")?;
    let path = runtime_root
        .join("artifacts")
        .join(namespace)
        .join(artifact_filename(&artifact_ref));
    if !path.is_file() {
        return Ok(false);
    }
    let bytes = fs::read(&path).map_err(|_| ModeError::new("mode_prompt_template_missing"))?;
    let template: PromptTemplateArtifact = serde_json::from_slice(&bytes)
        .map_err(|_| ModeError::new("mode_prompt_template_missing"))?;
    Ok(template.schema == PROMPT_TEMPLATE_SCHEMA)
}

fn split_artifact_ref(value: &str, default_namespace: &str) -> Result<(String, String), ModeError> {
    split_ref_parts_with_default(value, default_namespace)
        .ok_or_else(|| ModeError::new("mode_profile_invalid"))
}

fn intersect_sorted(left: &[String], right: &[String]) -> Vec<String> {
    let left_set: BTreeSet<String> = left.iter().cloned().collect();
    let right_set: BTreeSet<String> = right.iter().cloned().collect();
    left_set.intersection(&right_set).cloned().collect()
}

fn default_mode_id() -> String {
    DEFAULT_MODE_ID.to_string()
}

fn is_valid_retrieval_source(value: &str) -> bool {
    matches!(value, "episodic" | "working" | "open_memory_mirror")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LensId {
    DedupV1,
    RecencyV1,
    SalienceV1,
}

impl LensId {
    fn as_str(self) -> &'static str {
        match self {
            Self::DedupV1 => "dedup_v1",
            Self::RecencyV1 => "recency_v1",
            Self::SalienceV1 => "salience_v1",
        }
    }
}

fn parse_lens_id(value: &str) -> Option<LensId> {
    match value {
        "dedup_v1" => Some(LensId::DedupV1),
        "recency_v1" => Some(LensId::RecencyV1),
        "salience_v1" => Some(LensId::SalienceV1),
        _ => None,
    }
}

fn lens_order_key(id: LensId) -> u8 {
    match id {
        LensId::DedupV1 => 0,
        LensId::RecencyV1 => 1,
        LensId::SalienceV1 => 2,
    }
}

fn canonicalize_lens_ids(values: &[String]) -> Result<Vec<String>, ModeError> {
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let id = parse_lens_id(value).ok_or_else(|| ModeError::new("mode_profile_invalid"))?;
        parsed.push(id);
    }
    parsed.sort_by_key(|id| lens_order_key(*id));
    parsed.dedup();
    Ok(parsed
        .into_iter()
        .map(|id| id.as_str().to_string())
        .collect())
}
