pub mod embedder;
pub mod multiview;
pub mod projection;
pub mod state_encoder;
pub mod types;
pub const STRUCTURAL_DIM: usize = 4;
pub const DYNAMICAL_DIM: usize = 3;
pub const SALIENCE_DIM: usize = 3;
pub const NON_SEMANTIC_DIM: usize = STRUCTURAL_DIM + DYNAMICAL_DIM + SALIENCE_DIM;

pub use embedder::{HashEmbedder, TextEmbedder};
pub use multiview::MultiViewEncoder;
pub use projection::ProjectionMatrix;
pub use state_encoder::StateEncoder;
pub use types::{
    DynamicalInput, EncoderError, SalienceInput, SemanticVectorArtifact, Views,
    SEMANTIC_VECTOR_SCHEMA,
};
