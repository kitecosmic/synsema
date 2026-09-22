//! `RTensor`: el tensor del backend propio. `f32`, contiguo, row-major.
//!
//! Deliberadamente chico. No tiene autograd, ni dtypes, ni dispositivos, ni broadcasting general —
//! nada de eso hace falta para correr un encoder. Lo que sí tiene es **validación de formas en
//! cada constructor**, porque en una red un error de forma no explota: produce números.
//!
//! Convive con el [`crate::tensor::Tensor`] de candle sin mezclarse: cada arquitectura usa uno u
//! otro, y el oráculo de I4 compara sus salidas. Cuando el propio pase los goldens, el otro se va.

/// Tensor `f32` contiguo. Casi siempre es de rango 2 (`[filas, columnas]`).
#[derive(Clone, Debug, PartialEq)]
pub struct RTensor {
    data: Vec<f32>,
    shape: Vec<usize>,
}

impl RTensor {
    /// Construye validando que los datos alcancen para la forma. Es el único camino de creación,
    /// así que un tensor mal formado no puede existir.
    pub fn new(data: Vec<f32>, shape: Vec<usize>) -> Result<Self, String> {
        let expected: usize = shape.iter().product();
        if data.len() != expected {
            return Err(format!(
                "tensor: {} valores para la forma {:?} (se esperaban {})",
                data.len(),
                shape,
                expected
            ));
        }
        Ok(RTensor { data, shape })
    }

    pub fn zeros(shape: Vec<usize>) -> Self {
        let n = shape.iter().product();
        RTensor { data: vec![0.0; n], shape }
    }

    pub fn data(&self) -> &[f32] {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut [f32] {
        &mut self.data
    }

    pub fn shape(&self) -> &[usize] {
        &self.shape
    }

    /// La forma como matriz. Falla si el tensor no es de rango 2: preferimos un error claro acá a
    /// un índice mal calculado tres capas más abajo.
    pub fn dims2(&self) -> Result<(usize, usize), String> {
        if self.shape.len() != 2 {
            return Err(format!("se esperaba un tensor de rango 2, es {:?}", self.shape));
        }
        Ok((self.shape[0], self.shape[1]))
    }

    /// Parte las columnas en `parts` bloques iguales. Lo usan el `qkv` fusionado (3 partes) y la
    /// compuerta del MLP de ModernBERT (2).
    pub fn split_columns(&self, parts: usize) -> Result<Vec<RTensor>, String> {
        let (n, d) = self.dims2()?;
        if parts == 0 || d % parts != 0 {
            return Err(format!("no se puede partir una dimensión de {} en {}", d, parts));
        }
        let width = d / parts;
        let mut out = Vec::with_capacity(parts);
        for p in 0..parts {
            let mut buf = Vec::with_capacity(n * width);
            for row in 0..n {
                let start = row * d + p * width;
                buf.extend_from_slice(&self.data[start..start + width]);
            }
            out.push(RTensor::new(buf, vec![n, width])?);
        }
        Ok(out)
    }

    /// Un bloque de columnas `[start, start+width)`. Lo usa la separación por cabeza de atención.
    pub fn columns(&self, start: usize, width: usize) -> Result<RTensor, String> {
        let (n, d) = self.dims2()?;
        if start + width > d {
            return Err(format!("columnas [{}, {}) fuera de {}", start, start + width, d));
        }
        let mut buf = Vec::with_capacity(n * width);
        for row in 0..n {
            let s = row * d + start;
            buf.extend_from_slice(&self.data[s..s + width]);
        }
        RTensor::new(buf, vec![n, width])
    }

    /// Escribe un bloque de columnas en el lugar. Es cómo cada cabeza devuelve su resultado al
    /// tensor completo sin reservar memoria por cabeza.
    pub fn set_columns(&mut self, start: usize, other: &RTensor) -> Result<(), String> {
        let (n, d) = self.dims2()?;
        let (n_o, w) = other.dims2()?;
        if n != n_o || start + w > d {
            return Err(format!(
                "set_columns: bloque [{}, {}] no entra en [{}, {}]",
                n_o, w, n, d
            ));
        }
        for row in 0..n {
            let dst = row * d + start;
            self.data[dst..dst + w].copy_from_slice(&other.data[row * w..(row + 1) * w]);
        }
        Ok(())
    }

    /// Transpuesta de una matriz. Sólo la necesita `k^T` en los scores de atención.
    pub fn transpose(&self) -> Result<RTensor, String> {
        let (n, d) = self.dims2()?;
        let mut out = vec![0f32; n * d];
        for i in 0..n {
            for j in 0..d {
                out[j * n + i] = self.data[i * d + j];
            }
        }
        RTensor::new(out, vec![d, n])
    }

    /// Una fila, como vector.
    pub fn row(&self, index: usize) -> Result<&[f32], String> {
        let (n, d) = self.dims2()?;
        if index >= n {
            return Err(format!("fila {} de {}", index, n));
        }
        Ok(&self.data[index * d..(index + 1) * d])
    }

    /// Verdadero si todos los valores son finitos. Se chequea en la frontera, no por operación:
    /// un `NaN` que nace en la capa 3 se detecta al final igual, y chequear cada op costaría más
    /// que el modelo.
    pub fn all_finite(&self) -> bool {
        self.data.iter().all(|v| v.is_finite())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mismatched_data_and_shape_is_rejected() {
        assert!(RTensor::new(vec![1.0, 2.0], vec![3, 1]).is_err());
        assert!(RTensor::new(vec![1.0, 2.0], vec![2, 1]).is_ok());
    }

    #[test]
    fn split_columns_keeps_rows_together() {
        // [[1,2,3,4],[5,6,7,8]] partido en 2 → [[1,2],[5,6]] y [[3,4],[7,8]]
        let x = RTensor::new(vec![1., 2., 3., 4., 5., 6., 7., 8.], vec![2, 4]).unwrap();
        let parts = x.split_columns(2).unwrap();
        assert_eq!(parts[0].data(), &[1., 2., 5., 6.]);
        assert_eq!(parts[1].data(), &[3., 4., 7., 8.]);
    }

    #[test]
    fn split_into_three_is_the_qkv_case() {
        let x = RTensor::new((1..=12).map(|v| v as f32).collect(), vec![2, 6]).unwrap();
        let parts = x.split_columns(3).unwrap();
        assert_eq!(parts[0].data(), &[1., 2., 7., 8.]);
        assert_eq!(parts[1].data(), &[3., 4., 9., 10.]);
        assert_eq!(parts[2].data(), &[5., 6., 11., 12.]);
    }

    #[test]
    fn columns_and_set_columns_round_trip() {
        let mut x = RTensor::new(vec![1., 2., 3., 4., 5., 6.], vec![2, 3]).unwrap();
        let block = x.columns(1, 2).unwrap();
        assert_eq!(block.data(), &[2., 3., 5., 6.]);
        let doubled =
            RTensor::new(block.data().iter().map(|v| v * 2.0).collect(), vec![2, 2]).unwrap();
        x.set_columns(1, &doubled).unwrap();
        assert_eq!(x.data(), &[1., 4., 6., 4., 10., 12.]);
    }

    #[test]
    fn transpose_swaps_dimensions() {
        let x = RTensor::new(vec![1., 2., 3., 4., 5., 6.], vec![2, 3]).unwrap();
        let t = x.transpose().unwrap();
        assert_eq!(t.shape(), &[3, 2]);
        assert_eq!(t.data(), &[1., 4., 2., 5., 3., 6.]);
    }

    #[test]
    fn rank_three_is_an_error_not_a_guess() {
        let x = RTensor::new(vec![1., 2.], vec![1, 1, 2]).unwrap();
        assert!(x.dims2().is_err());
    }

    #[test]
    fn all_finite_detects_nan_and_inf() {
        let ok = RTensor::new(vec![1.0, 2.0], vec![1, 2]).unwrap();
        assert!(ok.all_finite());
        let bad = RTensor::new(vec![1.0, f32::NAN], vec![1, 2]).unwrap();
        assert!(!bad.all_finite());
    }
}
