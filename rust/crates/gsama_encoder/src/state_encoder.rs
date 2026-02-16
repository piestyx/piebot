//! Reserved for future GSAMA state-space projection stages.
use crate::projection::ProjectionMatrix;
use crate::types::EncoderError;
use gsama_core::math::{l2_normalize, validate_vector};

#[derive(Debug, Clone)]
pub struct StateEncoder {
    projection: ProjectionMatrix,
}

impl StateEncoder {
    pub fn new(projection: ProjectionMatrix) -> Self {
        Self { projection }
    }

    pub fn encode(
        &self,
        perception: &[f32],
        internal: &[f32],
        goal: &[f32],
        context: &[f32],
    ) -> Result<Vec<f32>, EncoderError> {
        validate_vector(perception).map_err(|_| EncoderError::InvalidValue("perception"))?;
        validate_vector(internal).map_err(|_| EncoderError::InvalidValue("internal"))?;
        validate_vector(goal).map_err(|_| EncoderError::InvalidValue("goal"))?;
        validate_vector(context).map_err(|_| EncoderError::InvalidValue("context"))?;

        let mut x =
            Vec::with_capacity(perception.len() + internal.len() + goal.len() + context.len());
        x.extend_from_slice(perception);
        x.extend_from_slice(internal);
        x.extend_from_slice(goal);
        x.extend_from_slice(context);

        let mut z = self.projection.mul_deterministic(&x)?;
        validate_vector(&z).map_err(|_| EncoderError::InvalidValue("projection_output"))?;
        l2_normalize(&mut z).map_err(|_| EncoderError::ZeroNorm)?;
        Ok(z)
    }
}

#[cfg(test)]
mod tests {
    use super::StateEncoder;
    use crate::projection::ProjectionMatrix;

    #[test]
    fn state_encoder_projection_expected_result() {
        let projection =
            ProjectionMatrix::from_rows(vec![vec![1.0, 0.0, 0.0, 0.0], vec![0.0, 1.0, 1.0, 0.0]])
                .unwrap();
        let encoder = StateEncoder::new(projection);
        let z = encoder.encode(&[1.0], &[2.0], &[3.0], &[4.0]).unwrap();
        // pre-norm: [1, 5]
        let norm = (26.0f32).sqrt();
        assert!((z[0] - (1.0 / norm)).abs() < 1e-6);
        assert!((z[1] - (5.0 / norm)).abs() < 1e-6);
    }
}
