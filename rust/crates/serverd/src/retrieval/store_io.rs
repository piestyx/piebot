fn retrieval_config_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join("retrieval").join("config.json")
}

fn parse_gsama_vector_source_mode(
    config: &RetrievalConfig,
) -> Result<GsamaVectorSourceMode, RetrievalError> {
    let raw = config.gsama_vector_source_mode.trim();
    if raw.is_empty() {
        return Ok(if config.gsama_allow_hash_embedder {
            GsamaVectorSourceMode::ExternalOrHashFallback
        } else {
            GsamaVectorSourceMode::ExternalOnly
        });
    }
    match raw {
        GSAMA_VECTOR_SOURCE_HASH_FALLBACK_ONLY => Ok(GsamaVectorSourceMode::HashFallbackOnly),
        GSAMA_VECTOR_SOURCE_EXTERNAL_ONLY => Ok(GsamaVectorSourceMode::ExternalOnly),
        GSAMA_VECTOR_SOURCE_EXTERNAL_OR_HASH_FALLBACK => {
            Ok(GsamaVectorSourceMode::ExternalOrHashFallback)
        }
        _ => Err(RetrievalError::new("retrieval_config_invalid")),
    }
}

fn normalize_gsama_vector_source_mode(
    config: &mut RetrievalConfig,
) -> Result<GsamaVectorSourceMode, RetrievalError> {
    let mode = parse_gsama_vector_source_mode(config)?;
    config.gsama_vector_source_mode = mode.as_str().to_string();
    config.gsama_allow_hash_embedder = mode.allows_hash_fallback();
    Ok(mode)
}

fn normalize_retrieval_config(config: &mut RetrievalConfig) -> Result<(), RetrievalError> {
    config.sources.sort();
    config.sources.dedup();
    config.namespaces_allowlist.sort();
    config.namespaces_allowlist.dedup();
    config.default_tags.sort();
    config.default_tags.dedup();

    for source in &config.sources {
        if SourceKind::parse(source).is_none() {
            return Err(RetrievalError::new("retrieval_config_invalid"));
        }
    }
    for namespace in &config.namespaces_allowlist {
        if !is_safe_token(namespace) {
            return Err(RetrievalError::new("retrieval_config_invalid"));
        }
    }
    for tag in &config.default_tags {
        if !is_safe_tag(tag) {
            return Err(RetrievalError::new("retrieval_config_invalid"));
        }
    }

    if config.enabled {
        if config.sources.is_empty()
            || config.namespaces_allowlist.is_empty()
            || config.max_items == 0
            || config.max_bytes == 0
            || config.default_recency_ticks == 0
        {
            return Err(RetrievalError::new("retrieval_config_invalid"));
        }
        if config.kind == RetrievalKind::Gsama {
            let mode = normalize_gsama_vector_source_mode(config)?;
            if config.gsama_store_capacity == 0 || config.gsama_vector_dim == 0 {
                return Err(RetrievalError::new("retrieval_config_invalid"));
            }
            let semantic_dim = gsama_semantic_dim(config)?;
            if mode.allows_hash_fallback()
                && (config.gsama_hash_embedder_dim == 0
                    || config.gsama_hash_embedder_dim != semantic_dim)
            {
                return Err(RetrievalError::new("retrieval_config_invalid"));
            }
        }
    }
    Ok(())
}

fn validate_query(
    query: &RetrievalQueryArtifact,
    config: &RetrievalConfig,
) -> Result<(), RetrievalError> {
    if query.schema != RETRIEVAL_QUERY_SCHEMA {
        return Err(RetrievalError::new("retrieval_query_invalid"));
    }
    if query.run_id.trim().is_empty()
        || query.request_hash.trim().is_empty()
        || query.anchors.state_hash.trim().is_empty()
    {
        return Err(RetrievalError::new("retrieval_query_invalid"));
    }
    match query.query_kind.as_str() {
        "skill_context" | "operator_search" | "tool_followup" | "debug" => {}
        _ => return Err(RetrievalError::new("retrieval_query_invalid")),
    }
    if query.caps.max_items == 0 || query.caps.max_bytes == 0 || query.selectors.recency_ticks == 0
    {
        return Err(RetrievalError::new("retrieval_query_invalid"));
    }

    let allowlist: BTreeSet<String> = config.namespaces_allowlist.iter().cloned().collect();
    for namespace in &query.selectors.namespaces {
        if !is_safe_token(namespace) {
            return Err(RetrievalError::new("retrieval_query_invalid"));
        }
        if !allowlist.contains(namespace) {
            return Err(RetrievalError::new("retrieval_namespace_denied"));
        }
    }
    for tag in &query.selectors.tags_any {
        if !is_safe_tag(tag) {
            return Err(RetrievalError::new("retrieval_query_invalid"));
        }
    }

    if config.kind == RetrievalKind::Gsama {
        let mode = parse_gsama_vector_source_mode(config)?;
        if query.query_vector.is_some() && query.query_vector_ref.is_some() {
            return Err(RetrievalError::new("retrieval_query_invalid"));
        }
        if query.query_vector.is_none() && query.query_vector_ref.is_none() {
            return Err(RetrievalError::new("gsama_query_vector_missing"));
        }
        if mode == GsamaVectorSourceMode::HashFallbackOnly && query.query_vector_ref.is_some() {
            return Err(RetrievalError::new("retrieval_query_invalid"));
        }
        if let Some(vector) = &query.query_vector {
            if vector.is_empty() {
                return Err(RetrievalError::new("gsama_query_vector_missing"));
            }
            for &v in vector {
                if v.is_nan() || v.is_infinite() {
                    return Err(RetrievalError::new("gsama_query_vector_missing"));
                }
            }
        }
        if let Some(vector_ref) = &query.query_vector_ref {
            if vector_ref.trim().is_empty() {
                return Err(RetrievalError::new("gsama_query_vector_missing"));
            }
        }
    }

    Ok(())
}

fn namespaces_from_refs(refs: &[String]) -> Vec<String> {
    let mut namespaces: Vec<String> = Vec::new();
    for value in refs {
        let (namespace, _) = match split_explicit_ref(value) {
            Some(parts) => parts,
            None => continue,
        };
        if namespace == "contexts" {
            namespaces.push(namespace.to_string());
        }
    }
    namespaces.sort();
    namespaces.dedup();
    namespaces
}

fn scan_episodic(runtime_root: &Path, out: &mut Vec<Candidate>) -> Result<(), RetrievalError> {
    let chain = list_episode_chain(runtime_root)
        .map_err(|_| RetrievalError::new("retrieval_source_unavailable"))?;
    for episode_hash in chain {
        let record = read_episode(runtime_root, &episode_hash)
            .map_err(|_| RetrievalError::new("retrieval_source_unavailable"))?;
        let mut tags = vec![format!("intent:{}", record.payload.intent_kind)];
        tags.sort();
        tags.dedup();

        out.push(Candidate {
            ref_value: episode_hash,
            source: SourceKind::Episodic,
            tick_index: Some(record.payload.tick_index),
            namespace: "episodes".to_string(),
            tags: tags.clone(),
            key_tokens: vec![record.payload.request_hash.clone()],
        });

        let mut artifact_refs = record.payload.artifact_refs.clone();
        artifact_refs.sort();
        artifact_refs.dedup();
        for artifact_ref in artifact_refs {
            let (namespace, normalized_ref) = split_ref(&artifact_ref, "contexts")?;
            out.push(Candidate {
                ref_value: normalized_ref,
                source: SourceKind::Episodic,
                tick_index: Some(record.payload.tick_index),
                namespace,
                tags: tags.clone(),
                key_tokens: Vec::new(),
            });
        }
    }
    Ok(())
}

fn scan_working(runtime_root: &Path, out: &mut Vec<Candidate>) -> Result<(), RetrievalError> {
    let config = load_memory_config(runtime_root)
        .map_err(|_| RetrievalError::new("retrieval_source_unavailable"))?;
    let memory = load_working_memory(runtime_root, &config)
        .map_err(|_| RetrievalError::new("retrieval_source_unavailable"))?;
    let mut entries = memory.entries().to_vec();
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    for entry in entries {
        let (namespace, normalized_ref) = split_ref(&entry.value_ref, "working")?;
        out.push(Candidate {
            ref_value: normalized_ref,
            source: SourceKind::Working,
            tick_index: Some(entry.last_touched_tick),
            namespace,
            tags: vec!["working".to_string()],
            key_tokens: vec![entry.key.clone()],
        });
    }
    Ok(())
}

fn scan_open_memory(runtime_root: &Path, out: &mut Vec<Candidate>) -> Result<(), RetrievalError> {
    if !open_memory_enabled() {
        return Err(RetrievalError::new("retrieval_source_unavailable"));
    }
    let path = runtime_root.join("memory").join("open_memory_mirror.jsonl");
    if !path.exists() {
        return Err(RetrievalError::new("retrieval_source_unavailable"));
    }
    let contents = fs::read_to_string(&path)
        .map_err(|_| RetrievalError::new("retrieval_source_unavailable"))?;
    let mut refs = BTreeSet::new();
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|_| RetrievalError::new("retrieval_source_unavailable"))?;
        let hashes = value
            .get("episode_hashes")
            .and_then(|v| v.as_array())
            .ok_or_else(|| RetrievalError::new("retrieval_source_unavailable"))?;
        for hash in hashes {
            let hash = hash
                .as_str()
                .ok_or_else(|| RetrievalError::new("retrieval_source_unavailable"))?;
            refs.insert(hash.to_string());
        }
    }
    for ref_value in refs {
        out.push(Candidate {
            ref_value,
            source: SourceKind::OpenMemoryMirror,
            tick_index: None,
            namespace: "open_memory".to_string(),
            tags: vec!["open_memory".to_string()],
            key_tokens: Vec::new(),
        });
    }
    Ok(())
}

fn rank_candidates(
    candidates: Vec<Candidate>,
    query: &RetrievalQueryArtifact,
) -> Vec<RankedCandidate> {
    let namespace_filter: BTreeSet<String> = query.selectors.namespaces.iter().cloned().collect();
    let tag_filter: BTreeSet<String> = query.selectors.tags_any.iter().cloned().collect();
    let mut rows = Vec::new();
    for candidate in candidates {
        if !namespace_filter.is_empty() && !namespace_filter.contains(&candidate.namespace) {
            continue;
        }
        let tag_matches = candidate
            .tags
            .iter()
            .filter(|tag| tag_filter.contains((*tag).as_str()))
            .count();
        if !tag_filter.is_empty() && tag_matches == 0 {
            continue;
        }
        let recency_bonus = match candidate.tick_index {
            Some(tick) => {
                let distance = query.anchors.tick_index.saturating_sub(tick);
                if distance > query.selectors.recency_ticks {
                    continue;
                }
                query.selectors.recency_ticks.saturating_sub(distance) + 1
            }
            None => 0,
        };
        let mut score = recency_bonus;
        let mut reason = "recency";
        let key_match = candidate
            .key_tokens
            .iter()
            .any(|k| k == &query.request_hash)
            || query
                .anchors
                .task_id
                .as_ref()
                .map(|task_id| candidate.key_tokens.iter().any(|k| k == task_id))
                .unwrap_or(false)
            || query
                .anchors
                .skill_id
                .as_ref()
                .map(|skill_id| candidate.key_tokens.iter().any(|k| k == skill_id))
                .unwrap_or(false);
        if key_match {
            score = score.saturating_add(1_000_000);
            reason = "exact_key";
        }
        if namespace_filter.contains(&candidate.namespace) {
            score = score.saturating_add(10_000);
            if reason != "exact_key" {
                reason = "namespace_match";
            }
        }
        if tag_matches > 0 {
            score = score.saturating_add((tag_matches as u64).saturating_mul(1_000));
            if reason != "exact_key" {
                reason = "tag_match";
            }
        }
        let mut tags = candidate.tags.clone();
        tags.sort();
        tags.dedup();
        rows.push(RankedCandidate {
            entry: RetrievalResultEntry {
                ref_value: candidate.ref_value,
                source: candidate.source.as_result_source().to_string(),
                tick_index: candidate.tick_index,
                namespace: candidate.namespace,
                tags,
                score,
                reason_code: reason.to_string(),
            },
        });
    }

    rows.sort_by(|a, b| {
        b.entry
            .score
            .cmp(&a.entry.score)
            .then(
                b.entry
                    .tick_index
                    .unwrap_or(0)
                    .cmp(&a.entry.tick_index.unwrap_or(0)),
            )
            .then(a.entry.ref_value.cmp(&b.entry.ref_value))
            .then(a.entry.source.cmp(&b.entry.source))
    });
    rows
}

fn compute_result_set_hash(
    results: &[RetrievalResultEntry],
    context_candidates: &[String],
) -> Result<String, RetrievalError> {
    let value = serde_json::json!({
        "results": results,
        "context_candidates": context_candidates
    });
    let bytes =
        canonical_json_bytes(&value).map_err(|_| RetrievalError::new("retrieval_failed"))?;
    Ok(sha256_bytes(&bytes))
}

fn compute_results_bytes(artifact: &mut RetrievalResultsArtifact) -> Result<u64, RetrievalError> {
    let items_returned = artifact.results.len() as u64;
    let mut current_bytes = 0u64;
    for _ in 0..5 {
        artifact.limits.items_returned = items_returned;
        artifact.limits.bytes_written = current_bytes;
        let value =
            serde_json::to_value(&artifact).map_err(|_| RetrievalError::new("retrieval_failed"))?;
        let bytes =
            canonical_json_bytes(&value).map_err(|_| RetrievalError::new("retrieval_failed"))?;
        let next = bytes.len() as u64;
        if next == current_bytes {
            artifact.limits.bytes_written = next;
            return Ok(next);
        }
        current_bytes = next;
    }
    Err(RetrievalError::new("retrieval_failed"))
}

fn split_ref(value: &str, default_namespace: &str) -> Result<(String, String), RetrievalError> {
    let (namespace, id) = split_ref_parts_with_default(value, default_namespace)
        .ok_or_else(|| RetrievalError::new("retrieval_query_invalid"))?;
    let normalized = normalize_ref(&namespace, &id)
        .ok_or_else(|| RetrievalError::new("retrieval_query_invalid"))?;
    Ok((namespace, normalized))
}

fn context_candidate_ref(value: &str) -> Option<String> {
    let (namespace, id) = split_explicit_ref(value)?;
    normalize_ref(namespace, id)
}

fn parse_source_kinds(tokens: &[String]) -> Result<Vec<SourceKind>, RetrievalError> {
    let mut kinds = Vec::new();
    for token in tokens {
        let kind = SourceKind::parse(token)
            .ok_or_else(|| RetrievalError::new("retrieval_config_invalid"))?;
        kinds.push(kind);
    }
    kinds.sort();
    kinds.dedup();
    Ok(kinds)
}

fn is_safe_tag(value: &str) -> bool {
    if value.trim().is_empty() {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':')
}
fn gsama_similarity_to_score(sim: f32) -> u64 {
    if !sim.is_finite() {
        return 0;
    }
    (((sim.clamp(-1.0, 1.0) + 1.0) / 2.0) * 1000.0).round() as u64
}

