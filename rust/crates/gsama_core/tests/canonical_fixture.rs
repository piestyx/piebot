use gsama_core::Store;
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct WriteOp {
    vector: Vec<f32>,
    tags: Vec<(String, String)>,
    entropy: f32,
    time: u64,
}

#[derive(Debug, Clone)]
struct QueryOp {
    vector: Vec<f32>,
    k: usize,
    filter: Option<Vec<(String, String)>>,
}

fn fixture_writes() -> Vec<WriteOp> {
    vec![
        WriteOp {
            vector: vec![1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            tags: vec![("type".into(), "a".into())],
            entropy: 0.3,
            time: 100,
        },
        WriteOp {
            vector: vec![0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            tags: vec![("type".into(), "b".into())],
            entropy: 0.7,
            time: 200,
        },
        WriteOp {
            vector: vec![1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            tags: vec![("type".into(), "a".into())],
            entropy: 0.5,
            time: 300,
        },
        WriteOp {
            vector: vec![0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            tags: vec![("type".into(), "c".into())],
            entropy: 0.2,
            time: 400,
        },
        WriteOp {
            vector: vec![1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            tags: vec![("type".into(), "a".into())],
            entropy: 0.6,
            time: 500,
        },
        WriteOp {
            vector: vec![0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            tags: vec![("type".into(), "b".into())],
            entropy: 0.4,
            time: 600,
        },
        WriteOp {
            vector: vec![1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            tags: vec![("type".into(), "c".into())],
            entropy: 0.8,
            time: 700,
        },
    ]
}

fn fixture_queries() -> Vec<QueryOp> {
    vec![
        QueryOp {
            vector: vec![1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            k: 3,
            filter: None,
        },
        QueryOp {
            vector: vec![1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            k: 5,
            filter: None,
        },
        QueryOp {
            vector: vec![1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            k: 3,
            filter: Some(vec![("type".into(), "a".into())]),
        },
    ]
}

fn execute_writes() -> (Store, Vec<String>, Vec<usize>) {
    let writes = fixture_writes();
    let mut store = Store::new(8, 5);
    let mut write_ids: Vec<String> = Vec::new();
    let mut evicted_write_indices: Vec<usize> = Vec::new();

    for write in &writes {
        let result = store
            .write(
                write.vector.clone(),
                write.tags.clone(),
                write.entropy,
                write.time,
            )
            .expect("write should succeed");
        for evicted_id in &result.evicted_ids {
            if let Some(idx) = write_ids.iter().position(|id| id == evicted_id) {
                evicted_write_indices.push(idx);
            }
        }
        write_ids.push(result.id);
    }
    (store, write_ids, evicted_write_indices)
}

#[test]
fn canonical_eviction_order() {
    let (_store, _write_ids, evicted) = execute_writes();
    assert_eq!(evicted, vec![3, 0]);
}

#[test]
fn canonical_retrieval_order() {
    let (store, write_ids, _) = execute_writes();
    let mut id_to_write_idx: HashMap<String, usize> = HashMap::new();
    for (idx, id) in write_ids.iter().enumerate() {
        id_to_write_idx.insert(id.clone(), idx);
    }

    let queries = fixture_queries();
    let expected = vec![vec![4, 2, 6], vec![2, 6, 1, 5, 4], vec![4, 2]];

    for (q_idx, query) in queries.iter().enumerate() {
        let results = store
            .retrieve(query.vector.clone(), query.k, query.filter.as_deref())
            .expect("retrieve should succeed");
        let order: Vec<usize> = results
            .iter()
            .filter_map(|r| id_to_write_idx.get(&r.id).copied())
            .collect();
        assert_eq!(order, expected[q_idx], "query index {}", q_idx);
    }
}

#[test]
fn canonical_determinism_across_runs() {
    let (store1, ids1, evicted1) = execute_writes();
    let (store2, ids2, evicted2) = execute_writes();
    assert_eq!(ids1, ids2);
    assert_eq!(evicted1, evicted2);
    assert_eq!(store1.head_hash_hex(), store2.head_hash_hex());
}
