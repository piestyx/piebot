use crate::embedder::TextEmbedder;
use crate::types::{DynamicalInput, EncoderError, SalienceInput, Views};
use gsama_core::math::{l2_normalize, validate_vector};

#[derive(Debug, Clone)]
pub struct MultiViewEncoder<E: TextEmbedder> {
    embedder: E,
}

impl<E: TextEmbedder> MultiViewEncoder<E> {
    pub fn new(embedder: E) -> Self {
        Self { embedder }
    }

    pub fn encode(
        &self,
        text: &str,
        dynamical: DynamicalInput,
        salience: SalienceInput,
        injected_semantic: Option<Vec<f32>>,
    ) -> Result<Views, EncoderError> {
        let mut semantic_view = match injected_semantic {
            Some(v) => v,
            None => self.embedder.embed(text)?,
        };
        validate_vector(&semantic_view).map_err(|_| EncoderError::InvalidValue("semantic_view"))?;
        l2_normalize(&mut semantic_view).map_err(|_| EncoderError::ZeroNorm)?;

        let structural_view = structural_view(text);
        let dynamical_view = dynamical_view(dynamical);
        let salience_view = salience_view(salience);

        let mut combined = Vec::with_capacity(
            semantic_view.len()
                + structural_view.len()
                + dynamical_view.len()
                + salience_view.len(),
        );
        combined.extend_from_slice(&semantic_view);
        combined.extend_from_slice(&structural_view);
        combined.extend_from_slice(&dynamical_view);
        combined.extend_from_slice(&salience_view);

        Ok(Views {
            semantic_view,
            structural_view,
            dynamical_view,
            salience_view,
            combined,
        })
    }
}

pub fn structural_view(text: &str) -> Vec<f32> {
    let token_count = text.split_whitespace().count() as f32;
    let sentence_count_raw = text
        .chars()
        .filter(|c| matches!(*c, '.' | '!' | '?'))
        .count() as f32;
    let sentence_count = if sentence_count_raw == 0.0 {
        1.0
    } else {
        sentence_count_raw
    };
    let avg_sentence_len = token_count / sentence_count;

    let char_count = text.chars().count().max(1) as f32;
    let punctuation_count = text
        .chars()
        .filter(|c| matches!(*c, ',' | ';' | ':' | '!' | '?'))
        .count() as f32;
    let punctuation_density = punctuation_count / char_count;

    vec![
        token_count.ln_1p(),
        sentence_count.ln_1p(),
        avg_sentence_len.ln_1p(),
        punctuation_density.ln_1p(),
    ]
}

pub fn dynamical_view(input: DynamicalInput) -> Vec<f32> {
    vec![
        (input.turn_index / 100.0).tanh(),
        (input.time_since_last / 60.0).tanh(),
        (input.write_frequency / 10.0).tanh(),
    ]
}

pub fn salience_view(input: SalienceInput) -> Vec<f32> {
    vec![
        input.entropy.tanh(),
        input.self_state_shift_cosine.abs().tanh(),
        input.importance.tanh(),
    ]
}

#[cfg(test)]
mod tests {
    use super::{dynamical_view, salience_view, structural_view, MultiViewEncoder};
    use crate::embedder::HashEmbedder;
    use crate::types::{DynamicalInput, SalienceInput};

    #[test]
    fn structural_view_expected_values() {
        let v = structural_view("a b.");
        assert_eq!(v.len(), 4);
        assert!((v[0] - (2.0f32).ln_1p()).abs() < 1e-6); // token_count
        assert!((v[1] - (1.0f32).ln_1p()).abs() < 1e-6); // sentence_count
        assert!((v[2] - (2.0f32).ln_1p()).abs() < 1e-6); // avg sentence len
        assert!((v[3] - 0.0).abs() < 1e-6); // punctuation_density
    }

    #[test]
    fn dynamical_view_expected_values() {
        let v = dynamical_view(DynamicalInput {
            turn_index: 10.0,
            time_since_last: 30.0,
            write_frequency: 5.0,
        });
        assert_eq!(v.len(), 3);
        assert!((v[0] - (0.1f32).tanh()).abs() < 1e-6);
        assert!((v[1] - (0.5f32).tanh()).abs() < 1e-6);
        assert!((v[2] - (0.5f32).tanh()).abs() < 1e-6);
    }

    #[test]
    fn salience_view_expected_values() {
        let v = salience_view(SalienceInput {
            entropy: 0.7,
            self_state_shift_cosine: -0.3,
            importance: 2.0,
        });
        assert_eq!(v.len(), 3);
        assert!((v[0] - 0.7f32.tanh()).abs() < 1e-6);
        assert!((v[1] - 0.3f32.tanh()).abs() < 1e-6);
        assert!((v[2] - 2.0f32.tanh()).abs() < 1e-6);
    }

    #[test]
    fn multiview_combines_all_views() {
        let embedder = HashEmbedder::new(8).unwrap();
        let encoder = MultiViewEncoder::new(embedder);
        let views = encoder
            .encode(
                "hello world!",
                DynamicalInput {
                    turn_index: 1.0,
                    time_since_last: 0.0,
                    write_frequency: 1.0,
                },
                SalienceInput {
                    entropy: 0.5,
                    self_state_shift_cosine: 0.1,
                    importance: 1.0,
                },
                None,
            )
            .unwrap();
        assert_eq!(views.semantic_view.len(), 8);
        assert_eq!(views.structural_view.len(), 4);
        assert_eq!(views.dynamical_view.len(), 3);
        assert_eq!(views.salience_view.len(), 3);
        assert_eq!(views.combined.len(), 18);
    }
}
