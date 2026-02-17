pub fn load_retrieval_config(runtime_root: &Path) -> Result<RetrievalConfig, RetrievalError> {
    let path = retrieval_config_path(runtime_root);
    if !path.exists() {
        return Ok(RetrievalConfig::default());
    }
    let bytes = fs::read(&path)
        .map_err(|e| RetrievalError::with_detail("retrieval_config_read_failed", e.to_string()))?;
    let mut config: RetrievalConfig = serde_json::from_slice(&bytes)
        .map_err(|e| RetrievalError::with_detail("retrieval_config_invalid", e.to_string()))?;
    if config.schema != RETRIEVAL_CONFIG_SCHEMA {
        return Err(RetrievalError::new("retrieval_config_invalid"));
    }
    normalize_retrieval_config(&mut config)?;
    Ok(config)
}

pub(crate) fn build_retrieval_query(
    config: &RetrievalConfig,
    input: &RetrievalBuildInput<'_>,
) -> Result<RetrievalQueryArtifact, RetrievalError> {
    let mut namespaces = namespaces_from_refs(input.seed_context_refs);
    if namespaces.is_empty() {
        namespaces = config.namespaces_allowlist.clone();
    }
    if namespaces.is_empty() {
        return Err(RetrievalError::new("retrieval_query_invalid"));
    }
    let allowed: BTreeSet<String> = config.namespaces_allowlist.iter().cloned().collect();
    for namespace in &namespaces {
        if !allowed.contains(namespace) {
            return Err(RetrievalError::new("retrieval_namespace_denied"));
        }
    }
    let mut query_vector = input.query_vector.clone();
    let query_vector_ref = input.query_vector_ref.map(|v| v.to_string());
    if config.kind == RetrievalKind::Gsama {
        let mode = parse_gsama_vector_source_mode(config)?;
        match mode {
            GsamaVectorSourceMode::HashFallbackOnly => {
                if query_vector.is_some() || query_vector_ref.is_some() {
                    return Err(RetrievalError::new("retrieval_query_invalid"));
                }
                query_vector = Some(build_gsama_query_vector(config, input, mode)?);
            }
            GsamaVectorSourceMode::ExternalOnly => {
                if query_vector.is_none() && query_vector_ref.is_none() {
                    return Err(RetrievalError::new("gsama_query_vector_missing"));
                }
            }
            GsamaVectorSourceMode::ExternalOrHashFallback => {
                if query_vector.is_none() && query_vector_ref.is_none() {
                    query_vector = Some(build_gsama_query_vector(config, input, mode)?);
                }
            }
        }
    }
    let query = RetrievalQueryArtifact {
        schema: RETRIEVAL_QUERY_SCHEMA.to_string(),
        run_id: input.run_id.to_string(),
        request_hash: input.request_hash.to_string(),
        query_kind: input.query_kind.to_string(),
        anchors: RetrievalAnchors {
            tick_index: input.tick_index,
            state_hash: input.state_hash.to_string(),
            task_id: input.task_id.map(|v| v.to_string()),
            skill_id: input.skill_id.map(|v| v.to_string()),
        },
        selectors: RetrievalSelectors {
            namespaces,
            tags_any: config.default_tags.clone(),
            recency_ticks: config.default_recency_ticks,
        },
        caps: RetrievalCaps {
            max_items: config.max_items,
            max_bytes: config.max_bytes,
        },
        query_vector,
        query_vector_ref,
    };
    validate_query(&query, config)?;
    Ok(query)
}

fn build_gsama_query_vector(
    config: &RetrievalConfig,
    input: &RetrievalBuildInput<'_>,
    vector_mode: GsamaVectorSourceMode,
) -> Result<Vec<f32>, RetrievalError> {
    build_gsama_combined_vector(
        config,
        vector_mode,
        input.query_text.unwrap_or(""),
        input.injected_semantic_vector.clone(),
        GsamaFeatureProfile {
            turn_index: input.turn_index,
            time_since_last: input.time_since_last,
            write_frequency: input.write_frequency,
            entropy: input.entropy,
            self_state_shift_cosine: input.self_state_shift_cosine,
            importance: input.importance,
        },
        "gsama_query_vector_missing",
    )
}

fn build_gsama_combined_vector(
    config: &RetrievalConfig,
    vector_mode: GsamaVectorSourceMode,
    text: &str,
    semantic_vector: Option<Vec<f32>>,
    feature_profile: GsamaFeatureProfile,
    missing_reason: &'static str,
) -> Result<Vec<f32>, RetrievalError> {
    let semantic_dim = gsama_semantic_dim(config)?;
    let injected_semantic = match semantic_vector {
        Some(vector) => {
            if !vector_mode.allows_external() {
                return Err(RetrievalError::new("retrieval_query_invalid"));
            }
            if vector.len() != semantic_dim {
                return Err(RetrievalError::new("retrieval_query_invalid"));
            }
            Some(vector)
        }
        None => {
            if !vector_mode.allows_hash_fallback() {
                return Err(RetrievalError::new(missing_reason));
            }
            None
        }
    };
    let dynamical = DynamicalInput {
        turn_index: feature_profile.turn_index,
        time_since_last: feature_profile.time_since_last,
        write_frequency: feature_profile.write_frequency,
    };
    let salience = SalienceInput {
        entropy: feature_profile.entropy,
        self_state_shift_cosine: feature_profile.self_state_shift_cosine,
        importance: feature_profile.importance,
    };
    let views = if vector_mode.allows_hash_fallback() {
        if config.gsama_hash_embedder_dim == 0 || config.gsama_hash_embedder_dim != semantic_dim {
            return Err(RetrievalError::new("retrieval_config_invalid"));
        }
        let embedder = HashEmbedder::new(config.gsama_hash_embedder_dim)
            .map_err(|e| RetrievalError::with_detail("retrieval_config_invalid", e.to_string()))?;
        let encoder = MultiViewEncoder::new(embedder);
        encoder
            .encode(text, dynamical, salience, injected_semantic)
            .map_err(|e| RetrievalError::with_detail(missing_reason, e.to_string()))?
    } else {
        let encoder = MultiViewEncoder::new(ExternalOnlyEmbedder { dim: semantic_dim });
        encoder
            .encode(text, dynamical, salience, injected_semantic)
            .map_err(|e| RetrievalError::with_detail(missing_reason, e.to_string()))?
    };
    if views.semantic_view.len() != semantic_dim {
        return Err(RetrievalError::new("gsama_query_vector_dim_mismatch"));
    }
    if views.combined.len() != config.gsama_vector_dim {
        return Err(RetrievalError::new("gsama_query_vector_dim_mismatch"));
    }
    Ok(views.combined)
}

pub(crate) fn execute_retrieval(
    runtime_root: &Path,
    config: &RetrievalConfig,
    query: &RetrievalQueryArtifact,
    query_ref: &str,
) -> Result<RetrievalResultsArtifact, RetrievalError> {
    validate_query(query, config)?;

    // Dispatch based on retrieval kind
    match config.kind {
        RetrievalKind::Refs => execute_refs_retrieval(runtime_root, config, query, query_ref),
        RetrievalKind::Gsama => execute_gsama_retrieval(runtime_root, config, query, query_ref),
    }
}

