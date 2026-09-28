//! Un vector con los primeros `N` elementos en línea, para los frames (`Bindings`, F2a).
//!
//! Antes eran `SmallVec`. Pero la representación de `SmallVec` depende de sus features, y las
//! features se unifican en todo el binario: Cranelift (el nivel nativo, F4) le prende `union` y eso
//! costaba ~2,6 % de instrucciones en toda la VM (medido con valgrind: `specs/compute-bench/cg_ab.sh`).
//! Los frames son la estructura más caliente del intérprete; como los frames de V8, CPython o Lua,
//! su representación es nuestra y no cambia según qué otro crate entre al binario.
//!
//! Un acceso es una comparación (`k < N`): los primeros `N` en el arreglo, el resto en `heap`. Sin
//! `unsafe`: los lugares libres del arreglo tienen `T::default()` (un `None`).

pub(crate) struct InlineVec<T: Default, const N: usize> {
    len: usize,
    inline: [T; N],
    heap: Vec<T>,
}

impl<T: Default, const N: usize> Default for InlineVec<T, N> {
    fn default() -> Self {
        InlineVec { len: 0, inline: std::array::from_fn(|_| T::default()), heap: Vec::new() }
    }
}

impl<T: Default, const N: usize> InlineVec<T, N> {
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub(crate) fn push(&mut self, v: T) {
        if self.len < N {
            self.inline[self.len] = v;
        } else {
            self.heap.push(v);
        }
        self.len += 1;
    }

    #[inline]
    pub(crate) fn get(&self, k: usize) -> Option<&T> {
        if k < N {
            if k < self.len {
                Some(&self.inline[k])
            } else {
                None
            }
        } else {
            self.heap.get(k - N)
        }
    }

    #[inline]
    pub(crate) fn get_mut(&mut self, k: usize) -> Option<&mut T> {
        if k < N {
            if k < self.len {
                Some(&mut self.inline[k])
            } else {
                None
            }
        } else {
            self.heap.get_mut(k - N)
        }
    }

    /// Suelta todo (en orden) y queda vacío; el `Vec` conserva su capacidad.
    pub(crate) fn clear(&mut self) {
        for x in &mut self.inline[..self.len.min(N)] {
            *x = T::default();
        }
        self.heap.clear();
        self.len = 0;
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.inline[..self.len.min(N)].iter().chain(self.heap.iter())
    }
}

impl<T: Default, const N: usize> std::ops::Index<usize> for InlineVec<T, N> {
    type Output = T;
    #[inline]
    fn index(&self, k: usize) -> &T {
        self.get(k).expect("índice fuera del frame")
    }
}

impl<T: Default, const N: usize> std::ops::IndexMut<usize> for InlineVec<T, N> {
    #[inline]
    fn index_mut(&mut self, k: usize) -> &mut T {
        self.get_mut(k).expect("índice fuera del frame")
    }
}

#[cfg(test)]
mod tests {
    use super::InlineVec;

    #[test]
    fn inline_then_heap_in_order() {
        let mut v: InlineVec<Option<u32>, 3> = InlineVec::default();
        for i in 0..7 {
            v.push(Some(i));
        }
        assert_eq!(v.len(), 7);
        assert_eq!(v.iter().map(|x| x.unwrap()).collect::<Vec<_>>(), (0..7).collect::<Vec<_>>());
        assert_eq!(v[2], Some(2));
        assert_eq!(v[5], Some(5));
        assert!(v.get(7).is_none());
        v[4] = None;
        assert_eq!(v.get(4), Some(&None));
        v.clear();
        assert_eq!(v.len(), 0);
        assert!(v.get(0).is_none());
        v.push(Some(9));
        assert_eq!(v.iter().count(), 1);
    }
}
