//! GSAMA Core — Deterministic vector store with cosine similarity retrieval.
//!
//! This crate implements the GSAMA core as specified:
//! - L2-normalized vectors
//! - Exact cosine similarity (dot product on normalized vectors)
//! - Deterministic write IDs (sha256 chain)
//! - Deterministic eviction by (entropy, time, id)
//! - Deterministic retrieval ordering

pub mod canonical;
pub mod math;
pub mod store;

pub use store::{
    Entry, RetrieveResult, SnapshotEntry, Store, StoreError, StoreSnapshot, WriteResult,
    STORE_SNAPSHOT_SCHEMA,
};
