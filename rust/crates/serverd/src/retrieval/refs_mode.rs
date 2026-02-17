fn execute_refs_retrieval(
    runtime_root: &Path,
    config: &RetrievalConfig,
    query: &RetrievalQueryArtifact,
    query_ref: &str,
) -> Result<RetrievalResultsArtifact, RetrievalError> {
    let sources = parse_source_kinds(&config.sources)?;
    let mut candidates = Vec::new();
    for source in sources {
        match source {
            SourceKind::Episodic => scan_episodic(runtime_root, &mut candidates)?,
            SourceKind::Working => scan_working(runtime_root, &mut candidates)?,
            SourceKind::OpenMemoryMirror => scan_open_memory(runtime_root, &mut candidates)?,
        }
    }

    let ranked = rank_candidates(candidates, query);
    if ranked.len() as u64 > query.caps.max_items {
        return Err(RetrievalError::new("retrieval_selection_exceeds_max_items"));
    }

    let results: Vec<RetrievalResultEntry> = ranked.into_iter().map(|row| row.entry).collect();
    let mut context_candidates: Vec<String> = results
        .iter()
        .filter_map(|row| context_candidate_ref(&row.ref_value))
        .collect();
    context_candidates.sort();
    context_candidates.dedup();
    let result_set_hash = compute_result_set_hash(&results, &context_candidates)?;
    let mut artifact = RetrievalResultsArtifact {
        schema: RETRIEVAL_RESULTS_SCHEMA.to_string(),
        run_id: query.run_id.clone(),
        request_hash: query.request_hash.clone(),
        query_ref: query_ref.to_string(),
        result_set_hash,
        results,
        limits: RetrievalLimits {
            items_returned: 0,
            bytes_written: 0,
        },
        context_candidates,
    };
    let bytes_written = compute_results_bytes(&mut artifact)?;
    if bytes_written > query.caps.max_bytes {
        return Err(RetrievalError::new("retrieval_selection_exceeds_max_bytes"));
    }
    Ok(artifact)
}

fn resolve_gsama_query_vector(
    runtime_root: &Path,
    config: &RetrievalConfig,
    query: &RetrievalQueryArtifact,
) -> Result<Vec<f32>, RetrievalError> {
    let mode = parse_gsama_vector_source_mode(config)?;
    let semantic_dim = gsama_semantic_dim(config)?;
    let feature_profile = GsamaFeatureProfile {
        turn_index: query.anchors.tick_index as f32,
        time_since_last: 0.0,
        write_frequency: 1.0,
        entropy: 0.0,
        self_state_shift_cosine: 0.0,
        importance: 1.0,
    };
    match (&query.query_vector, &query.query_vector_ref) {
        (Some(_), Some(_)) => Err(RetrievalError::new("retrieval_query_invalid")),
        (Some(v), None) => {
            if v.len() == config.gsama_vector_dim {
                Ok(v.clone())
            } else if mode.allows_external() && v.len() == semantic_dim {
                build_gsama_combined_vector(
                    config,
                    mode,
                    "",
                    Some(v.clone()),
                    feature_profile,
                    "gsama_query_vector_missing",
                )
            } else {
                Err(RetrievalError::new("retrieval_query_invalid"))
            }
        }
        (None, Some(vector_ref)) => {
            let semantic = load_query_vector_from_ref(runtime_root, vector_ref, semantic_dim)?;
            build_gsama_combined_vector(
                config,
                mode,
                "",
                Some(semantic),
                feature_profile,
                "gsama_query_vector_missing",
            )
        }
        (None, None) => Err(RetrievalError::new("gsama_query_vector_missing")),
    }
}

fn load_query_vector_from_ref(
    runtime_root: &Path,
    vector_ref: &str,
    expected_semantic_dim: usize,
) -> Result<Vec<f32>, RetrievalError> {
    let (namespace, artifact_ref) = split_ref_parts_with_default(vector_ref, "semantic_vectors")
        .ok_or_else(|| RetrievalError::new("retrieval_query_invalid"))?;
    if namespace != "semantic_vectors" {
        return Err(RetrievalError::new("retrieval_query_invalid"));
    }
    let path = runtime_root
        .join("artifacts")
        .join("semantic_vectors")
        .join(artifact_filename(&artifact_ref));
    let bytes = fs::read(&path)
        .map_err(|e| RetrievalError::with_detail("gsama_query_vector_missing", e.to_string()))?;
    let artifact: SemanticVectorArtifact = serde_json::from_slice(&bytes)
        .map_err(|e| RetrievalError::with_detail("gsama_query_vector_missing", e.to_string()))?;
    if artifact.schema != SEMANTIC_VECTOR_SCHEMA {
        return Err(RetrievalError::new("gsama_query_vector_missing"));
    }
    if artifact.dim != expected_semantic_dim {
        return Err(RetrievalError::new("retrieval_query_invalid"));
    }
    if artifact.vector.len() != artifact.dim || artifact.dim == 0 {
        return Err(RetrievalError::new("retrieval_query_invalid"));
    }
    for &v in &artifact.vector {
        if v.is_nan() || v.is_infinite() {
            return Err(RetrievalError::new("gsama_query_vector_missing"));
        }
    }
    Ok(artifact.vector)
}

