fn execute_gsama_retrieval(
    runtime_root: &Path,
    config: &RetrievalConfig,
    query: &RetrievalQueryArtifact,
    query_ref: &str,
) -> Result<RetrievalResultsArtifact, RetrievalError> {
    let query_vector = resolve_gsama_query_vector(runtime_root, config, query)?;

    // Load GSAMA store from disk
    let store = load_gsama_store(runtime_root)?;
    if query_vector.len() != store.dim() {
        return Err(RetrievalError::new("gsama_query_vector_dim_mismatch"));
    }

    // Build tag filter from selectors
    let tag_filter: Vec<(String, String)> = query
        .selectors
        .tags_any
        .iter()
        .filter_map(|t| {
            let parts: Vec<&str> = t.splitn(2, ':').collect();
            if parts.len() == 2 {
                Some((parts[0].to_string(), parts[1].to_string()))
            } else {
                None
            }
        })
        .collect();

    let filter_ref = if tag_filter.is_empty() {
        None
    } else {
        Some(tag_filter.as_slice())
    };

    // Retrieve from GSAMA store
    let gsama_results = store
        .retrieve(query_vector, query.caps.max_items as usize, filter_ref)
        .map_err(|e| RetrievalError::with_detail("gsama_retrieval_failed", e.to_string()))?;

    // Map GSAMA results to retrieval entries
    let mut results: Vec<RetrievalResultEntry> = Vec::new();
    for (rank, result) in gsama_results.iter().enumerate() {
        if let Some(entry) = store.get(&result.id) {
            let context_ref = entry
                .tags
                .iter()
                .find(|(k, _)| k == "context_ref")
                .and_then(|(_, v)| context_candidate_ref(v));
            let episode_ref = entry
                .tags
                .iter()
                .find(|(k, _)| k == "episode_ref")
                .and_then(|(_, v)| {
                    if let Some((namespace, id)) = split_explicit_ref(v) {
                        normalize_ref(namespace, id)
                    } else {
                        normalize_ref("episodes", v)
                    }
                });
            let ref_value = context_ref
                .or(episode_ref)
                .unwrap_or_else(|| result.id.clone());
            let namespace = split_explicit_ref(&ref_value)
                .map(|(ns, _)| ns.to_string())
                .unwrap_or_else(|| "gsama".to_string());
            let mut tags: Vec<String> = entry
                .tags
                .iter()
                .map(|(k, v)| format!("{}:{}", k, v))
                .collect();
            tags.sort();
            tags.dedup();
            let score = gsama_similarity_to_score(result.score);

            results.push(RetrievalResultEntry {
                ref_value,
                source: "gsama".to_string(),
                tick_index: None,
                namespace,
                tags,
                score,
                reason_code: format!("gsama_rank_{}", rank),
            });
        }
    }

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

/// Load GSAMA store from disk using snapshot format.
/// Store location: runtime/memory/gsama/store_snapshot.json
fn load_gsama_store(runtime_root: &Path) -> Result<gsama_core::Store, RetrievalError> {
    let store_path = runtime_root
        .join("memory")
        .join("gsama")
        .join("store_snapshot.json");

    if !store_path.exists() {
        return Err(RetrievalError::new("gsama_store_not_found"));
    }

    let content = fs::read_to_string(&store_path)
        .map_err(|e| RetrievalError::with_detail("gsama_store_read_failed", e.to_string()))?;

    let snapshot: gsama_core::StoreSnapshot = serde_json::from_str(&content)
        .map_err(|e| RetrievalError::with_detail("gsama_store_invalid", e.to_string()))?;

    // Load from snapshot (preserves IDs and head hash)
    gsama_core::Store::from_snapshot(snapshot)
        .map_err(|e| RetrievalError::with_detail("gsama_store_load_failed", e.to_string()))
}

/// Save a GSAMA store to disk using snapshot format.
/// Store location: runtime/memory/gsama/store_snapshot.json
#[allow(dead_code)]
pub fn save_gsama_store(
    runtime_root: &Path,
    store: &gsama_core::Store,
) -> Result<(), RetrievalError> {
    let gsama_dir = runtime_root.join("memory").join("gsama");
    fs::create_dir_all(&gsama_dir)
        .map_err(|e| RetrievalError::with_detail("gsama_dir_create_failed", e.to_string()))?;

    let snapshot = store.to_snapshot();
    let content = serde_json::to_string_pretty(&snapshot)
        .map_err(|e| RetrievalError::with_detail("gsama_store_serialize_failed", e.to_string()))?;

    let store_path = gsama_dir.join("store_snapshot.json");
    fs::write(&store_path, content)
        .map_err(|e| RetrievalError::with_detail("gsama_store_write_failed", e.to_string()))?;

    Ok(())
}

pub(crate) fn preflight_gsama_store(
    runtime_root: &Path,
    config: &RetrievalConfig,
) -> Result<(), RetrievalError> {
    if config.kind != RetrievalKind::Gsama {
        return Ok(());
    }
    if config.gsama_store_capacity == 0 || config.gsama_vector_dim == 0 {
        return Err(RetrievalError::new("retrieval_config_invalid"));
    }
    let semantic_dim = gsama_semantic_dim(config)?;
    let mode = parse_gsama_vector_source_mode(config)?;
    if mode.allows_hash_fallback()
        && (config.gsama_hash_embedder_dim == 0 || config.gsama_hash_embedder_dim != semantic_dim)
    {
        return Err(RetrievalError::new("retrieval_config_invalid"));
    }
    match load_gsama_store(runtime_root) {
        Ok(store) => {
            if store.dim() != config.gsama_vector_dim {
                return Err(RetrievalError::new("gsama_store_dim_mismatch"));
            }
            if store.capacity() != config.gsama_store_capacity {
                return Err(RetrievalError::new("gsama_store_capacity_mismatch"));
            }
            Ok(())
        }
        Err(err) if err.reason() == "gsama_store_not_found" => Ok(()),
        Err(err) => Err(err),
    }
}

pub(crate) fn write_context_pointer_artifact(
    runtime_root: &Path,
    run_id: &str,
    tick_index: u64,
    episode_hash: &str,
) -> Result<String, RetrievalError> {
    let episode_ref = normalize_ref("episodes", episode_hash)
        .ok_or_else(|| RetrievalError::new(CONTEXT_POINTER_WRITE_FAILED))?;
    let artifact = ContextPointerArtifact {
        schema: CONTEXT_POINTER_SCHEMA.to_string(),
        run_id: run_id.to_string(),
        episode_ref,
        episode_hash: episode_hash.to_string(),
        created_tick: tick_index,
    };
    let value = serde_json::to_value(&artifact)
        .map_err(|_| RetrievalError::new(CONTEXT_POINTER_WRITE_FAILED))?;
    let artifact_ref = write_json_artifact_atomic(runtime_root, "contexts", &value)
        .map_err(|_| RetrievalError::new(CONTEXT_POINTER_WRITE_FAILED))?;
    normalize_ref("contexts", &artifact_ref)
        .ok_or_else(|| RetrievalError::new(CONTEXT_POINTER_WRITE_FAILED))
}

