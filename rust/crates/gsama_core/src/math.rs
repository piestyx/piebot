//! Math utilities for GSAMA core: L2 normalization, cosine similarity.

use std::fmt;

#[derive(Debug)]
pub enum MathError {
    ZeroVector,
    NanValue,
    InfValue,
    DimensionMismatch { expected: usize, got: usize },
}

impl fmt::Display for MathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MathError::ZeroVector => write!(f, "cannot normalize zero vector"),
            MathError::NanValue => write!(f, "vector contains NaN"),
            MathError::InfValue => write!(f, "vector contains Inf"),
            MathError::DimensionMismatch { expected, got } => {
                write!(f, "dimension mismatch: expected {}, got {}", expected, got)
            }
        }
    }
}

impl std::error::Error for MathError {}

/// Validate that a vector contains no NaN or Inf values.
pub fn validate_vector(v: &[f32]) -> Result<(), MathError> {
    for &x in v {
        if x.is_nan() {
            return Err(MathError::NanValue);
        }
        if x.is_infinite() {
            return Err(MathError::InfValue);
        }
    }
    Ok(())
}

/// Compute L2 norm of a vector.
pub fn l2_norm(v: &[f32]) -> f32 {
    let sum: f32 = v.iter().map(|x| x * x).sum();
    sum.sqrt()
}

/// L2-normalize a vector in place. Returns error if zero vector or contains NaN/Inf.
pub fn l2_normalize(v: &mut [f32]) -> Result<(), MathError> {
    validate_vector(v)?;
    let norm = l2_norm(v);
    if norm == 0.0 {
        return Err(MathError::ZeroVector);
    }
    for x in v.iter_mut() {
        *x /= norm;
    }
    Ok(())
}

/// L2-normalize a vector, returning a new vector. Returns error if zero or contains NaN/Inf.
pub fn l2_normalized(v: &[f32]) -> Result<Vec<f32>, MathError> {
    let mut out = v.to_vec();
    l2_normalize(&mut out)?;
    Ok(out)
}

/// Cosine similarity between two L2-normalized vectors (dot product).
/// Assumes both vectors are already normalized.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> Result<f32, MathError> {
    if a.len() != b.len() {
        return Err(MathError::DimensionMismatch {
            expected: a.len(),
            got: b.len(),
        });
    }
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    Ok(dot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l2_normalize() {
        let mut v = vec![3.0, 4.0];
        l2_normalize(&mut v).unwrap();
        assert!((v[0] - 0.6).abs() < 1e-6);
        assert!((v[1] - 0.8).abs() < 1e-6);
    }

    #[test]
    fn test_zero_vector_rejected() {
        let mut v = vec![0.0, 0.0, 0.0];
        assert!(matches!(l2_normalize(&mut v), Err(MathError::ZeroVector)));
    }

    #[test]
    fn test_nan_rejected() {
        let mut v = vec![1.0, f32::NAN, 2.0];
        assert!(matches!(l2_normalize(&mut v), Err(MathError::NanValue)));
    }

    #[test]
    fn test_inf_rejected() {
        let mut v = vec![1.0, f32::INFINITY, 2.0];
        assert!(matches!(l2_normalize(&mut v), Err(MathError::InfValue)));
    }

    #[test]
    fn test_cosine_similarity() {
        let a = vec![1.0, 0.0];
        let b = vec![1.0, 0.0];
        assert!((cosine_similarity(&a, &b).unwrap() - 1.0).abs() < 1e-6);

        let c = vec![0.0, 1.0];
        assert!(cosine_similarity(&a, &c).unwrap().abs() < 1e-6);
    }
}
