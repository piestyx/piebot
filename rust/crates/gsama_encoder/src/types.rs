use serde::{Deserialize, Serialize};
use std::fmt;

pub const SEMANTIC_VECTOR_SCHEMA: &str = "gsama.semantic_vector.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SemanticVectorArtifact {
    pub schema: String,
    pub run_id: String,
    pub request_hash: String,
    pub vector: Vec<f32>,
    pub dim: usize,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DynamicalInput {
    pub turn_index: f32,
    pub time_since_last: f32,
    pub write_frequency: f32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SalienceInput {
    pub entropy: f32,
    pub self_state_shift_cosine: f32,
    pub importance: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Views {
    pub semantic_view: Vec<f32>,
    pub structural_view: Vec<f32>,
    pub dynamical_view: Vec<f32>,
    pub salience_view: Vec<f32>,
    pub combined: Vec<f32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncoderError {
    InvalidValue(&'static str),
    InvalidDimension {
        expected: usize,
        got: usize,
    },
    InvalidMatrixShape {
        rows: usize,
        cols: usize,
        data_len: usize,
    },
    MatrixInputMismatch {
        cols: usize,
        input_len: usize,
    },
    ZeroNorm,
}

impl fmt::Display for EncoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncoderError::InvalidValue(name) => write!(f, "invalid value: {}", name),
            EncoderError::InvalidDimension { expected, got } => {
                write!(f, "invalid dimension: expected {}, got {}", expected, got)
            }
            EncoderError::InvalidMatrixShape {
                rows,
                cols,
                data_len,
            } => write!(
                f,
                "invalid matrix shape: rows={} cols={} data_len={}",
                rows, cols, data_len
            ),
            EncoderError::MatrixInputMismatch { cols, input_len } => {
                write!(
                    f,
                    "matrix input mismatch: matrix cols={} input len={}",
                    cols, input_len
                )
            }
            EncoderError::ZeroNorm => write!(f, "zero norm"),
        }
    }
}

impl std::error::Error for EncoderError {}
