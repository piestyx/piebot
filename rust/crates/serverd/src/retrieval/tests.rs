#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    fn gsama_config(vector_source_mode: &str) -> RetrievalConfig {
        RetrievalConfig {
            schema: RETRIEVAL_CONFIG_SCHEMA.to_string(),
            enabled: true,
            kind: RetrievalKind::Gsama,
            sources: vec!["episodic".to_string()],
            namespaces_allowlist: vec!["contexts".to_string()],
            max_items: 16,
            max_bytes: 8 * 1024,
            default_recency_ticks: 16,
            default_tags: Vec::new(),
            gsama_vector_source_mode: vector_source_mode.to_string(),
            gsama_allow_hash_embedder: vector_source_mode != GSAMA_VECTOR_SOURCE_EXTERNAL_ONLY,
            gsama_hash_embedder_dim: 32,
            gsama_store_capacity: 1000,
            gsama_vector_dim: 42,
        }
    }

    fn build_input<'a>(seed_context_refs: &'a [String]) -> RetrievalBuildInput<'a> {
        RetrievalBuildInput {
            run_id: "run_1",
            request_hash: "sha256:req",
            query_kind: "operator_search",
            tick_index: 1,
            state_hash: "sha256:state",
            task_id: None,
            skill_id: None,
            seed_context_refs: seed_context_refs,
            query_vector: None,
            query_vector_ref: None,
            query_text: Some("hello world"),
            injected_semantic_vector: None,
            turn_index: 1.0,
            time_since_last: 0.0,
            write_frequency: 1.0,
            entropy: 0.0,
            self_state_shift_cosine: 0.0,
            importance: 1.0,
        }
    }

    #[test]
    fn gsama_query_fails_closed_in_external_only_mode_without_vector() {
        let config = gsama_config(GSAMA_VECTOR_SOURCE_EXTERNAL_ONLY);
        let refs = vec!["contexts/seed".to_string()];
        let input = build_input(&refs);
        let err = build_retrieval_query(&config, &input).expect_err("must fail closed");
        assert_eq!(err.reason(), "gsama_query_vector_missing");
    }

    #[test]
    fn gsama_query_builds_vector_in_hash_fallback_only_mode() {
        let config = gsama_config(GSAMA_VECTOR_SOURCE_HASH_FALLBACK_ONLY);
        let refs = vec!["contexts/seed".to_string()];
        let input = build_input(&refs);
        let query = build_retrieval_query(&config, &input).expect("query should build");
        assert!(query.query_vector.is_some());
        assert!(query.query_vector_ref.is_none());
        let v = query.query_vector.unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn gsama_query_rejects_vector_ref_in_hash_fallback_only_mode() {
        let config = gsama_config(GSAMA_VECTOR_SOURCE_HASH_FALLBACK_ONLY);
        let refs = vec!["contexts/seed".to_string()];
        let mut input = build_input(&refs);
        input.query_vector_ref = Some("semantic_vectors/sha256:deadbeef");
        let err = build_retrieval_query(&config, &input).expect_err("must reject external refs");
        assert_eq!(err.reason(), "retrieval_query_invalid");
    }

    #[test]
    fn gsama_query_resolves_vector_from_semantic_vector_artifact_ref() {
        let tmp = TempDir::new().unwrap();
        let runtime_root = tmp.path();
        let dir = runtime_root.join("artifacts").join("semantic_vectors");
        fs::create_dir_all(&dir).unwrap();
        let mut config = gsama_config(GSAMA_VECTOR_SOURCE_EXTERNAL_ONLY);
        config.gsama_hash_embedder_dim = 0;
        config.gsama_vector_dim = NON_SEMANTIC_DIM + 2;

        let vector = vec![0.6f32, 0.8f32];
        let artifact = SemanticVectorArtifact {
            schema: SEMANTIC_VECTOR_SCHEMA.to_string(),
            run_id: "run_1".to_string(),
            request_hash: "sha256:req".to_string(),
            vector: vector.clone(),
            dim: vector.len(),
            source: "external_embedder_service".to_string(),
        };
        let bytes = serde_json::to_vec(&artifact).unwrap();
        let artifact_ref = sha256_bytes(&bytes);
        let path = dir.join(artifact_filename(&artifact_ref));
        fs::write(path, bytes).unwrap();

        let query = RetrievalQueryArtifact {
            schema: RETRIEVAL_QUERY_SCHEMA.to_string(),
            run_id: "run_1".to_string(),
            request_hash: "sha256:req".to_string(),
            query_kind: "operator_search".to_string(),
            anchors: RetrievalAnchors {
                tick_index: 1,
                state_hash: "sha256:state".to_string(),
                task_id: None,
                skill_id: None,
            },
            selectors: RetrievalSelectors {
                namespaces: vec!["contexts".to_string()],
                tags_any: Vec::new(),
                recency_ticks: 1,
            },
            caps: RetrievalCaps {
                max_items: 1,
                max_bytes: 1024,
            },
            query_vector: None,
            query_vector_ref: Some(artifact_ref),
        };
        let loaded = resolve_gsama_query_vector(runtime_root, &config, &query)
            .expect("should resolve vector");
        assert_eq!(loaded.len(), config.gsama_vector_dim);
    }

    #[test]
    fn load_query_vector_ref_enforces_semantic_dim() {
        let tmp = TempDir::new().unwrap();
        let runtime_root = tmp.path();
        let dir = runtime_root.join("artifacts").join("semantic_vectors");
        fs::create_dir_all(&dir).unwrap();
        let artifact = SemanticVectorArtifact {
            schema: SEMANTIC_VECTOR_SCHEMA.to_string(),
            run_id: "run_1".to_string(),
            request_hash: "sha256:req".to_string(),
            vector: vec![0.1f32; 8],
            dim: 8,
            source: "external_embedder_service".to_string(),
        };
        let bytes = serde_json::to_vec(&artifact).unwrap();
        let artifact_ref = sha256_bytes(&bytes);
        let path = dir.join(artifact_filename(&artifact_ref));
        fs::write(path, bytes).unwrap();

        let err = load_query_vector_from_ref(runtime_root, &artifact_ref, 16)
            .expect_err("semantic dim mismatch must fail");
        assert_eq!(err.reason(), "retrieval_query_invalid");
    }

    #[test]
    fn preflight_detects_store_dim_mismatch() {
        let tmp = TempDir::new().unwrap();
        let runtime_root = tmp.path();
        let config = gsama_config(GSAMA_VECTOR_SOURCE_EXTERNAL_OR_HASH_FALLBACK);
        let store =
            gsama_core::Store::new(config.gsama_vector_dim + 1, config.gsama_store_capacity);
        save_gsama_store(runtime_root, &store).expect("store should save");
        let err = preflight_gsama_store(runtime_root, &config).expect_err("dim mismatch expected");
        assert_eq!(err.reason(), "gsama_store_dim_mismatch");
    }

    #[test]
    fn write_context_pointer_creates_context_ref_artifact() {
        let tmp = TempDir::new().unwrap();
        let runtime_root = tmp.path();
        let context_ref =
            write_context_pointer_artifact(runtime_root, "run_1", 7, "sha256:episode")
                .expect("context pointer should write");
        let (namespace, artifact_ref) =
            split_ref_parts_with_default(&context_ref, "contexts").expect("valid context ref");
        assert_eq!(namespace, "contexts");
        let path = runtime_root
            .join("artifacts")
            .join("contexts")
            .join(artifact_filename(&artifact_ref));
        let bytes = fs::read(path).expect("context pointer artifact should exist");
        let pointer: ContextPointerArtifact =
            serde_json::from_slice(&bytes).expect("context pointer artifact should parse");
        assert_eq!(pointer.schema, CONTEXT_POINTER_SCHEMA);
        assert_eq!(pointer.run_id, "run_1");
        assert_eq!(pointer.created_tick, 7);
    }

    #[test]
    fn write_context_pointer_failure_reports_context_pointer_write_failed() {
        let tmp = TempDir::new().unwrap();
        let runtime_root = tmp.path().join("runtime_root_as_file");
        fs::write(&runtime_root, b"not-a-directory").unwrap();
        let err = write_context_pointer_artifact(&runtime_root, "run_1", 7, "sha256:episode")
            .expect_err("context pointer write must fail");
        assert_eq!(err.reason(), CONTEXT_POINTER_WRITE_FAILED);
    }

    #[test]
    fn external_only_allows_hash_embedder_dim_zero() {
        let tmp = TempDir::new().unwrap();
        let runtime_root = tmp.path();
        let dir = runtime_root.join("artifacts").join("semantic_vectors");
        fs::create_dir_all(&dir).unwrap();

        let mut config = gsama_config(GSAMA_VECTOR_SOURCE_EXTERNAL_ONLY);
        config.gsama_hash_embedder_dim = 0;
        config.gsama_vector_dim = NON_SEMANTIC_DIM + 16;

        let vector = vec![0.5f32; 16];
        let artifact = SemanticVectorArtifact {
            schema: SEMANTIC_VECTOR_SCHEMA.to_string(),
            run_id: "run_1".to_string(),
            request_hash: "sha256:req".to_string(),
            vector,
            dim: 16,
            source: "external_embedder_service".to_string(),
        };
        let bytes = serde_json::to_vec(&artifact).unwrap();
        let artifact_ref = sha256_bytes(&bytes);
        let path = dir.join(artifact_filename(&artifact_ref));
        fs::write(path, bytes).unwrap();

        let query = RetrievalQueryArtifact {
            schema: RETRIEVAL_QUERY_SCHEMA.to_string(),
            run_id: "run_1".to_string(),
            request_hash: "sha256:req".to_string(),
            query_kind: "operator_search".to_string(),
            anchors: RetrievalAnchors {
                tick_index: 1,
                state_hash: "sha256:state".to_string(),
                task_id: None,
                skill_id: None,
            },
            selectors: RetrievalSelectors {
                namespaces: vec!["contexts".to_string()],
                tags_any: Vec::new(),
                recency_ticks: 1,
            },
            caps: RetrievalCaps {
                max_items: 1,
                max_bytes: 1024,
            },
            query_vector: None,
            query_vector_ref: Some(artifact_ref),
        };
        let combined = resolve_gsama_query_vector(runtime_root, &config, &query)
            .expect("external_only with dim=0 embedder should succeed");
        assert_eq!(combined.len(), config.gsama_vector_dim);
    }

    #[test]
    fn external_only_rejects_wrong_semantic_vector_len() {
        let tmp = TempDir::new().unwrap();
        let runtime_root = tmp.path();
        let mut config = gsama_config(GSAMA_VECTOR_SOURCE_EXTERNAL_ONLY);
        config.gsama_hash_embedder_dim = 0;
        config.gsama_vector_dim = NON_SEMANTIC_DIM + 16;
        let query = RetrievalQueryArtifact {
            schema: RETRIEVAL_QUERY_SCHEMA.to_string(),
            run_id: "run_1".to_string(),
            request_hash: "sha256:req".to_string(),
            query_kind: "operator_search".to_string(),
            anchors: RetrievalAnchors {
                tick_index: 1,
                state_hash: "sha256:state".to_string(),
                task_id: None,
                skill_id: None,
            },
            selectors: RetrievalSelectors {
                namespaces: vec!["contexts".to_string()],
                tags_any: Vec::new(),
                recency_ticks: 1,
            },
            caps: RetrievalCaps {
                max_items: 1,
                max_bytes: 1024,
            },
            query_vector: Some(vec![0.1; 15]),
            query_vector_ref: None,
        };
        let err = resolve_gsama_query_vector(runtime_root, &config, &query)
            .expect_err("wrong semantic vector length must fail");
        assert_eq!(err.reason(), "retrieval_query_invalid");
    }

    #[test]
    fn hash_fallback_requires_embedder_dim_matches_semantic_dim() {
        let mut config = gsama_config(GSAMA_VECTOR_SOURCE_HASH_FALLBACK_ONLY);
        config.gsama_vector_dim = NON_SEMANTIC_DIM + 16;
        config.gsama_hash_embedder_dim = 8;
        let err = normalize_retrieval_config(&mut config)
            .expect_err("hash fallback should require embedder dim == semantic dim");
        assert_eq!(err.reason(), "retrieval_config_invalid");
    }

    #[test]
    fn append_episode_rejects_invalid_write_refs_with_gsama_write_input_invalid() {
        let tmp = TempDir::new().unwrap();
        let runtime_root = tmp.path();
        let config = gsama_config(GSAMA_VECTOR_SOURCE_EXTERNAL_ONLY);
        let semantic_dim = config.gsama_vector_dim - NON_SEMANTIC_DIM;
        let input = GsamaEpisodeWriteInput {
            text: "sample",
            tick_index: 1,
            episode_ref: "episodes/sha256:episode",
            context_ref: "contexts/invalid/nested",
            intent_kind: "test",
            semantic_vector: Some(vec![0.0; semantic_dim]),
            entropy: 0.0,
            feature_profile: GsamaFeatureProfile {
                turn_index: 1.0,
                time_since_last: 0.0,
                write_frequency: 1.0,
                entropy: 0.0,
                self_state_shift_cosine: 0.0,
                importance: 1.0,
            },
            extra_tags: Vec::new(),
        };
        let err = append_episode_to_gsama_store(
            runtime_root,
            &config,
            &input,
            crate::command::ProviderMode::Live,
        )
            .expect_err("invalid write refs must fail before store write");
        assert_eq!(err.reason(), GSAMA_WRITE_INPUT_INVALID);
    }

    #[test]
    fn normalize_ref_allows_sha256_ids() {
        // Namespace must be a safe token; ID may include ':' such as sha256 refs.
        let normalized = normalize_ref("contexts", "sha256:deadbeef");
        assert_eq!(normalized.as_deref(), Some("contexts/sha256:deadbeef"));
    }

    #[test]
    fn split_ref_parts_rejects_nested_slashes() {
        // ID must be a single segment and therefore cannot include '/'.
        assert!(split_explicit_ref("contexts/a/b").is_none());
    }

    #[test]
    fn gsama_similarity_score_monotonic() {
        let low = gsama_similarity_to_score(-1.0);
        let mid = gsama_similarity_to_score(0.0);
        let high = gsama_similarity_to_score(1.0);
        assert_eq!(low, 0);
        assert_eq!(high, 1000);
        assert!(low < mid);
        assert!(mid < high);
    }

    #[test]
    fn gsama_retrieval_prefers_context_ref_and_keeps_higher_similarity_higher_score() {
        let tmp = TempDir::new().unwrap();
        let runtime_root = tmp.path();
        let config = gsama_config(GSAMA_VECTOR_SOURCE_EXTERNAL_ONLY);
        let mut store =
            gsama_core::Store::new(config.gsama_vector_dim, config.gsama_store_capacity);

        let mut high = vec![0.0f32; config.gsama_vector_dim];
        high[0] = 1.0;
        let mut lower = vec![0.0f32; config.gsama_vector_dim];
        lower[0] = 0.6;
        lower[1] = 0.8;

        store
            .write(
                high.clone(),
                vec![
                    (
                        "context_ref".to_string(),
                        "contexts/sha256:ctx_high".to_string(),
                    ),
                    (
                        "episode_ref".to_string(),
                        "episodes/sha256:ep_high".to_string(),
                    ),
                ],
                0.3,
                10,
            )
            .expect("write high similarity entry");
        store
            .write(
                lower,
                vec![
                    (
                        "context_ref".to_string(),
                        "contexts/sha256:ctx_low".to_string(),
                    ),
                    (
                        "episode_ref".to_string(),
                        "episodes/sha256:ep_low".to_string(),
                    ),
                ],
                0.3,
                11,
            )
            .expect("write lower similarity entry");
        save_gsama_store(runtime_root, &store).expect("save store");

        let query = RetrievalQueryArtifact {
            schema: RETRIEVAL_QUERY_SCHEMA.to_string(),
            run_id: "run_1".to_string(),
            request_hash: "sha256:req".to_string(),
            query_kind: "operator_search".to_string(),
            anchors: RetrievalAnchors {
                tick_index: 1,
                state_hash: "sha256:state".to_string(),
                task_id: None,
                skill_id: None,
            },
            selectors: RetrievalSelectors {
                namespaces: vec!["contexts".to_string()],
                tags_any: Vec::new(),
                recency_ticks: 8,
            },
            caps: RetrievalCaps {
                max_items: 2,
                max_bytes: 4096,
            },
            query_vector: Some(high),
            query_vector_ref: None,
        };

        let results =
            execute_retrieval(runtime_root, &config, &query, "sha256:query").expect("retrieval");
        assert_eq!(results.results.len(), 2);
        assert_eq!(results.results[0].ref_value, "contexts/sha256:ctx_high");
        assert!(
            results.results[0].score >= results.results[1].score,
            "higher similarity should keep a higher score"
        );
    }
}
