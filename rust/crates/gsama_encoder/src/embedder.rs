use crate::types::EncoderError;
use gsama_core::math::{l2_normalize, validate_vector};
use sha2::{Digest, Sha256};

pub trait TextEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, EncoderError>;
    fn dim(&self) -> usize;
}

#[derive(Debug, Clone)]
pub struct HashEmbedder {
    dim: usize,
}

impl HashEmbedder {
    pub fn new(dim: usize) -> Result<Self, EncoderError> {
        if dim == 0 {
            return Err(EncoderError::InvalidDimension {
                expected: 1,
                got: 0,
            });
        }
        Ok(Self { dim })
    }
}

impl TextEmbedder for HashEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, EncoderError> {
        let mut out = Vec::with_capacity(self.dim);
        let mut counter: u64 = 0;
        while out.len() < self.dim {
            let mut h = Sha256::new();
            h.update(text.as_bytes());
            h.update(counter.to_le_bytes());
            let digest = h.finalize();
            for chunk in digest.chunks_exact(4) {
                if out.len() == self.dim {
                    break;
                }
                let raw = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                let value = (raw as f64) / ((u32::MAX as f64) + 1.0);
                out.push(value as f32);
            }
            counter = counter.saturating_add(1);
        }
        validate_vector(&out).map_err(|_| EncoderError::InvalidValue("hash_embedder_output"))?;
        l2_normalize(&mut out).map_err(|_| EncoderError::ZeroNorm)?;
        Ok(out)
    }

    fn dim(&self) -> usize {
        self.dim
    }
}

#[cfg(test)]
mod tests {
    use super::{HashEmbedder, TextEmbedder};

    #[test]
    fn hash_embedder_is_deterministic() {
        let embedder = HashEmbedder::new(16).unwrap();
        let a = embedder.embed("hello world").unwrap();
        let b = embedder.embed("hello world").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hash_embedder_vector_is_normalized() {
        let embedder = HashEmbedder::new(16).unwrap();
        let v = embedder.embed("hello world").unwrap();
        let norm_sq: f32 = v.iter().map(|x| x * x).sum();
        assert!((norm_sq - 1.0).abs() < 1e-5);
    }
}
