use crate::types::EncoderError;

#[derive(Debug, Clone)]
pub struct ProjectionMatrix {
    rows: usize,
    cols: usize,
    data: Vec<f32>, // row-major
}

impl ProjectionMatrix {
    pub fn new(rows: usize, cols: usize, data: Vec<f32>) -> Result<Self, EncoderError> {
        if rows == 0 || cols == 0 {
            return Err(EncoderError::InvalidDimension {
                expected: 1,
                got: 0,
            });
        }
        if data.len() != rows * cols {
            return Err(EncoderError::InvalidMatrixShape {
                rows,
                cols,
                data_len: data.len(),
            });
        }
        for &v in &data {
            if v.is_nan() || v.is_infinite() {
                return Err(EncoderError::InvalidValue("projection_matrix"));
            }
        }
        Ok(Self { rows, cols, data })
    }

    pub fn from_rows(rows_data: Vec<Vec<f32>>) -> Result<Self, EncoderError> {
        let rows = rows_data.len();
        if rows == 0 {
            return Err(EncoderError::InvalidDimension {
                expected: 1,
                got: 0,
            });
        }
        let cols = rows_data[0].len();
        if cols == 0 {
            return Err(EncoderError::InvalidDimension {
                expected: 1,
                got: 0,
            });
        }
        if rows_data.iter().any(|r| r.len() != cols) {
            return Err(EncoderError::InvalidValue("projection_matrix_rows"));
        }
        let mut data = Vec::with_capacity(rows * cols);
        for row in rows_data {
            data.extend_from_slice(&row);
        }
        Self::new(rows, cols, data)
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    pub fn mul_deterministic(&self, input: &[f32]) -> Result<Vec<f32>, EncoderError> {
        if input.len() != self.cols {
            return Err(EncoderError::MatrixInputMismatch {
                cols: self.cols,
                input_len: input.len(),
            });
        }
        for &v in input {
            if v.is_nan() || v.is_infinite() {
                return Err(EncoderError::InvalidValue("projection_input"));
            }
        }

        let mut out = vec![0.0f32; self.rows];
        for (row, out_cell) in out.iter_mut().enumerate().take(self.rows) {
            let mut acc = 0.0f64;
            let row_start = row * self.cols;
            for (col, input_cell) in input.iter().enumerate().take(self.cols) {
                let a = self.data[row_start + col] as f64;
                let b = *input_cell as f64;
                acc += a * b;
            }
            *out_cell = acc as f32;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::ProjectionMatrix;

    #[test]
    fn deterministic_matmul_expected_result() {
        let m =
            ProjectionMatrix::from_rows(vec![vec![1.0, 0.0, 0.0, 0.0], vec![0.0, 1.0, 1.0, 0.0]])
                .unwrap();
        let out = m.mul_deterministic(&[1.0, 2.0, 3.0, 4.0]).unwrap();
        assert_eq!(out.len(), 2);
        assert!((out[0] - 1.0).abs() < 1e-6);
        assert!((out[1] - 5.0).abs() < 1e-6);
    }
}
